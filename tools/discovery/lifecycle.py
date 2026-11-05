"""D1/D4: ownership and table-slot lifecycle over versioned memory states.

Two defects live here, and they share one engine because they are the same
question asked twice:

* **D1 (use after release)** -- a pointer is released and the *same object* is
  used again.  The hard part is object identity: a stack slot reused for another
  pointer is not the same object, and a register copy is.
* **D4 (table slot lifecycle)** -- an element of an indexed table is released
  and the same *slot* is used again, where the slot is identified by a canonical
  index expression, not by its address text.

The engine is a forward abstract interpretation over the function CFG:

* a register holds a **set of values** (``Ptr(obj)``, ``Addr``, ``Const``,
  ``Unknown``).  Member sets are may-facts, singleton sets are must-facts.
* memory is **versioned**: every store to a canonical address expression bumps
  its version, and a read returns what the cell holds *at that point*.  A cell
  whose content is unknown yields a *fresh object identity per (cell, version)*,
  which is what makes reuse safe and non-reuse detectable.
* a **read** of an unknown cell, a call result and any unnamed computation get a
  stable symbolic identity derived from their definition site, so two reads of
  the same unknown location are the same object and two different computations
  never are.  Equality is therefore always proven or absent -- never assumed.
* an **unknown call** may free any pointer argument.  That is recorded as an
  *uncertain* release, which cannot produce a confirmed defect: it produces an
  ``UNKNOWN_SIDE_EFFECT`` class finding instead.
* index equality is decided on canonical affine expressions (``rax*8`` ==
  ``rax<<3`` == ``lea rdx,[rax*8]``), and a symbolic index that differs yields
  ``MAY_ALIAS`` -- never "same slot" and never "confirmed use after release".

Everything the analysis cannot decide stays UNKNOWN and is reported as such.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

from .image import require_capstone
from .memory import (Addr, Affine, CELL_APPROX, CELL_EXACT, CELL_NEVER_WRITTEN, CELL_TOP,
                     Cell, Const, Memory, Obj, Ptr, RegState, Unknown, describe_values)
from .ownership import OwnershipCatalog, ROLE_ALLOC, ROLE_FREE, ROLE_REFCOUNT_RELEASE
from .patterns import ARGREGS, Finding, FunctionView

try:  # pragma: no cover - guarded
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
except Exception:  # pragma: no cover
    X86_OP_IMM = X86_OP_MEM = X86_OP_REG = X86_REG_RIP = -1

CALLER_SAVED = ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11")
FRAME = ("rbp", "rsp")

USE_KINDS = ("read", "write", "call_arg", "indirect_call")

# verdicts
CONFIRMED = "USE_AFTER_RELEASE"
PATH_DEPENDENT = "PATH_DEPENDENT_USE_AFTER_RELEASE"
MAY = "MAY_USE_AFTER_RELEASE"
UNKNOWN_EFFECT = "UNKNOWN_SIDE_EFFECT"
COVERAGE_CAUSES = ("step_budget", "block_budget", "iteration_budget", "cell_cap",
                   "access_cap", "release_cap", "recursion")

ALIAS_MAY = "MAY_ALIAS_REUSE"
ALIAS_UNKNOWN = "UNKNOWN_ALIAS_REUSE"

#: How many times one allocation site may produce a *distinguishable* object
#: before its identity is dropped.  Inside a loop the site allocates anew on every
#: iteration, so iteration 1 and 2 must not share an identity; past the cap the
#: site's objects are unprovable, which is what keeps a recycled slot from being
#: reported as a use-after-free.
MAX_OBJ_GEN = 3


@dataclass
class Defect:
    detector: str
    kind: str
    obj: Obj
    release_site: int
    release_kind: str
    use_site: int
    use_kind: str
    carrier: str
    identity_class: str
    confirmed: bool
    detail: Dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "detector": self.detector,
            "kind": self.kind,
            "object": self.obj.describe(),
            "release_site": hex(self.release_site),
            "release_kind": self.release_kind,
            "use_site": hex(self.use_site),
            "use_kind": self.use_kind,
            "carrier": self.carrier,
            "identity_class": self.identity_class,
            "confirmed": self.confirmed,
            "detail": self.detail,
        }


@dataclass
class Access:
    site: int
    kind: str            # read | write
    cell: str
    base: str
    scale: int
    index_sym: Optional[str]
    offset: Optional[int]
    indexed: bool
    carrier: str = ""

    def as_dict(self) -> dict:
        return {
            "site": hex(self.site),
            "kind": self.kind,
            "cell": self.cell,
            "base": self.base,
            "scale": self.scale,
            "index": self.index_sym,
            "offset": hex(self.offset) if self.offset is not None else None,
            "indexed": self.indexed,
        }


class Lifecycle:
    """Forward may/must interpretation with versioned memory."""

    def __init__(self, view: FunctionView, catalog: OwnershipCatalog,
                 max_blocks: int = 260, max_iterations: int = 6,
                 max_cells: int = 600, max_values: int = 8,
                 max_steps: int = 20000, max_iterations_total: int = 20000):
        require_capstone()
        self.view = view
        self.catalog = catalog
        self.max_blocks = max_blocks
        self.max_iterations = max_iterations
        self.max_cells = max_cells
        self.max_values = max_values
        self.max_steps = max_steps
        #: hard stop for the fixpoint itself.  Reaching it is a *truncation*, and
        #: a truncated function is reported as such -- never as "no defects".
        self.max_iterations_total = max_iterations_total
        self.steps = 0
        self.in_states: Dict[int, RegState] = {}
        self.out_states: Dict[int, RegState] = {}
        self.defects: List[Defect] = []
        self.accesses: List[Access] = []
        self.releases: List[dict] = []
        self.notes: List[str] = []
        self.truncated = False
        self.widened = False
        self.truncation_causes: Dict[str, int] = {}
        self.iterations = 0
        # raw append counters: the lists above are deduplicated, so "how many
        # events were emitted" and "how many distinct releases exist" stay apart
        self.release_events_raw = 0
        self.access_events_raw = 0
        self._release_keys: Set[tuple] = set()
        self._release_index: Dict[tuple, dict] = {}
        self._access_keys: Set[tuple] = set()
        self.dropped_identities = 0

    # ------------------------------------------------------------------ entry
    def seed(self) -> RegState:
        state = RegState()
        for n, reg in enumerate(ARGREGS):
            state.set(reg, frozenset({Ptr(Obj("arg", str(n)))}))
            state.origins[reg] = self.view.rva
        state.set("rsp", frozenset({Addr("frame:rsp", Affine.of(0))}))
        state.set("rbp", frozenset({Addr("frame:rbp", Affine.of(0))}))
        return state

    def run(self) -> None:
        blocks = [b for b in self.view.blocks if self.view.ins_by.get(b)]
        if not blocks:
            return
        if len(blocks) > self.max_blocks:
            self._trunc("block_budget")
            self.notes.append(f"block budget: {len(blocks)} > {self.max_blocks}")
            blocks = blocks[: self.max_blocks]
        entry = blocks[0]
        self.in_states[entry] = self.seed()
        work = [entry]
        counts: Dict[int, int] = {entry: 1}
        while work:
            block = work.pop(0)
            state_in = self.in_states.get(block)
            if state_in is None:
                continue
            self.iterations += 1
            if self.iterations > self.max_iterations_total:
                self._trunc("iteration_budget")
                self.notes.append(
                    f"fixpoint budget exhausted after {self.max_iterations_total} block visits"
                )
                break
            out = self._exec_block(state_in.copy(), block)
            if out is None:
                continue
            self.out_states[block] = out
            for succ in self.view.succ.get(block, ()):
                if succ not in self.view.ins_by or succ not in blocks:
                    continue
                prev = self.in_states.get(succ)
                merged = out if prev is None else prev.merge(out)
                if prev is not None and merged.fingerprint() == prev.fingerprint():
                    continue
                counts[succ] = counts.get(succ, 0) + 1
                if counts[succ] > self.max_iterations:
                    merged = self._widen(merged)
                    counts[succ] = 0
                self.in_states[succ] = merged
                work.append(succ)
        self.defects.extend(self.alias_defects())

    def _widen(self, state: RegState) -> RegState:
        """Cap runaway states: lose cells, never forge identities."""
        if len(state.mem.cells) > self.max_cells:
            keep = {}
            dropped: Set[str] = set()
            for addr, cell in list(sorted(state.mem.cells.items(),
                                          key=lambda kv: kv[0].key()))[: self.max_cells // 2]:
                keep[addr] = cell
            for addr in state.mem.cells:
                if addr not in keep:
                    dropped.add(addr.base)
            state.mem = Memory(keep, state.mem.lost | frozenset(dropped))
            self._trunc("cell_cap")
        for reg, vals in sorted(state.regs.items()):
            if len(vals) > self.max_values:
                state.regs[reg] = frozenset({Unknown(f"widened:{reg}")})
                self._trunc("value_cap")
                if not state.origins.get(reg):
                    state.origins[reg] = 0
        return state

    def _trunc(self, cause: str) -> None:
        """Record *why* precision was lost, per cause.

        Two very different things used to share one word.  Losing *coverage* (a
        budget stops the walk, so part of the function was never analysed) makes
        every claim unproven; losing *precision* (a register or a cell is widened)
        leaves the walk complete but the facts coarser.  ``truncated`` means the
        first, ``widened`` the second -- and only the first downgrades findings.
        """
        self.truncation_causes[cause] = self.truncation_causes.get(cause, 0) + 1
        if cause in COVERAGE_CAUSES:
            self.truncated = True
        else:
            self.widened = True

    # ------------------------------------------------------------ instruction
    def _exec_block(self, state: RegState, block: int) -> Optional[RegState]:
        for ins in self.view.ins_by[block]:
            self.steps += 1
            if self.steps > self.max_steps:
                if "step_budget" not in self.truncation_causes:
                    self.notes.append(
                        f"instruction budget exhausted at {ins.address:#x} "
                        f"({self.max_steps} steps); the tail of this function is not analysed"
                    )
                self._trunc("step_budget")
                return None
            try:
                self._step(state, ins, block)
            except RecursionError:  # pragma: no cover - defensive
                self.notes.append(f"recursion at {ins.address:#x}")
                self._trunc("recursion")
                return None
        return state

    def _step(self, state: RegState, ins, block: int) -> None:
        mnemonic = ins.mnemonic
        ops = ins.operands
        if not ops:
            return
        if mnemonic == "call":
            self._call(state, ins, block)
            return
        if mnemonic == "lea" and len(ops) == 2 and ops[0].type == X86_OP_REG:
            addr = self._mem_addr(state, ins, ops[1])
            dst = ins.reg_name(ops[0].reg)
            if addr is not None:
                self._set_reg(state, dst, frozenset({addr}), ins.address)
            else:
                self._set_reg(state, dst, frozenset({Unknown("lea:unknown-base")}), ins.address)
            return
        if mnemonic in ("mov", "movzx", "movsx", "movsxd") and len(ops) == 2:
            self._mov(state, ins, ops, block)
            return
        if mnemonic in ("add", "sub", "inc", "dec", "shl", "sal", "shr", "sar", "imul",
                        "and", "or", "xor", "neg", "not") and ops[0].type == X86_OP_REG:
            self._arith(state, ins, ops)
            return
        if mnemonic in ("xchg", "cmpxchg", "xadd"):
            for op in ops:
                if op.type == X86_OP_MEM:
                    addr = self._mem_addr(state, ins, op)
                    self._use_base(state, ins, op, "write")
                    if addr is not None:
                        state.mem.store(addr, frozenset({Unknown(f"atomic:{ins.address:#x}")}))
            state.clobber(CALLER_SAVED, f"atomic:{ins.address:#x}")
            return
        if mnemonic in ("push", "pop"):
            if mnemonic == "pop" and ops[0].type == X86_OP_REG:
                dst = ins.reg_name(ops[0].reg)
                self._set_reg(state, dst, frozenset({Unknown(f"pop:{ins.address:#x}")}), ins.address)
            return
        if mnemonic in ("jmp",) and self._release_via_jump(state, ins):
            return
        # everything else: memory operands are read-only uses of their base
        for op in ops:
            if op.type == X86_OP_MEM:
                self._use_base(state, ins, op, "read")
                addr = self._mem_addr(state, ins, op)
                if addr is not None:
                    self._record_access(ins.address, "read", addr, ins, op)

    # -- transfers ---------------------------------------------------------
    def _mov(self, state: RegState, ins, ops, block: int) -> None:
        dst, src = ops[0], ops[1]
        if dst.type == X86_OP_REG:
            values = self._eval(state, ins, src, use_kind=None)
            self._set_reg(state, ins.reg_name(dst.reg), values, ins.address)
            return
        if dst.type == X86_OP_MEM:
            addr = self._mem_addr(state, ins, dst)
            self._use_base(state, ins, dst, "write")
            values = self._eval(state, ins, src)
            if addr is not None:
                self._store(state, addr, values, ins, dst)

    def _store(self, state: RegState, addr: Addr, values: FrozenSet, ins, op) -> None:
        if len(state.mem.cells) > self.max_cells:
            self._widen(state)
        state.mem.store(addr, values)
        self._record_access(ins.address, "write", addr, ins, op)
        state.note(ins.address, "WRITE", f"{addr.key()} <- {describe_values(values)}")

    def _arith(self, state: RegState, ins, ops) -> None:
        dst = ins.reg_name(ops[0].reg)
        mnemonic = ins.mnemonic
        if len(ops) == 2 and mnemonic == "xor" and ops[1].type == X86_OP_REG:
            if ins.reg_name(ops[1].reg) == dst:
                self._set_reg(state, dst, frozenset({Const(0)}), ins.address)
                return
        if mnemonic in ("and", "or", "xor", "neg", "not"):
            self._set_reg(state, dst, frozenset({Unknown(f"{mnemonic}:{ins.address:#x}")}), ins.address)
            return
        left = self._affine_or_space(state, dst)
        right = None
        if len(ops) == 2:
            right = self._imm_or_affine(state, ins, ops[1])
        else:
            right = Affine.of(1 if mnemonic == "inc" else -1)
        # pointer arithmetic: an address expression plus a scalar stays an address
        if mnemonic in ("add", "sub"):
            folded = self._fold_address(state, ins, dst, ops, mnemonic)
            if folded is not None:
                self._set_reg(state, dst, folded, ins.address)
                return
        if left is None or right is None:
            self._set_reg(state, dst, frozenset({Unknown(f"{mnemonic}:{ins.address:#x}")}), ins.address)
            return
        if mnemonic in ("add", "inc"):
            result = left.add(right)
        elif mnemonic in ("sub", "dec"):
            result = left.sub(right)
        elif mnemonic in ("shl", "sal", "imul"):
            if not right.is_const():
                self._set_reg(state, dst, frozenset({Unknown(f"{mnemonic}:{ins.address:#x}")}), ins.address)
                return
            result = left.scale(1 << right.const if mnemonic != "imul" else right.const)
        elif mnemonic in ("shr", "sar"):
            if not right.is_const() or right.const > 32:
                self._set_reg(state, dst, frozenset({Unknown(f"{mnemonic}:{ins.address:#x}")}), ins.address)
                return
            if not left.is_const():
                self._set_reg(state, dst, frozenset({Unknown(f"{mnemonic}:{ins.address:#x}")}), ins.address)
                return
            result = Affine.of(left.const >> right.const)
        else:
            self._set_reg(state, dst, frozenset({Unknown(f"{mnemonic}:{ins.address:#x}")}), ins.address)
            return
        if result.is_const():
            self._set_reg(state, dst, frozenset({Const(result.const)}), ins.address)
        else:
            self._set_reg(state, dst, frozenset({Addr("value", result)}), ins.address)

    def _set_reg(self, state: RegState, reg: str, values: FrozenSet, site: int) -> None:
        if len(values) > self.max_values:
            values = frozenset({Unknown(f"wide:{site:#x}")})
        state.set(reg, values)
        state.origins[reg] = site

    # -- evaluation --------------------------------------------------------
    def _eval(self, state: RegState, ins, op, use_kind: Optional[str] = None) -> FrozenSet:
        if op.type == X86_OP_IMM:
            return frozenset({Const(int(op.imm))})
        if op.type == X86_OP_REG:
            return state.get(ins.reg_name(op.reg))
        if op.type == X86_OP_MEM:
            addr = self._mem_addr(state, ins, op)
            self._use_base(state, ins, op, "read")
            if addr is None:
                return frozenset({Unknown(f"load:no-base:{ins.address:#x}")})
            self._record_access(ins.address, "read", addr, ins, op)
            values = self._load_cell(state, addr)
            state.note(ins.address, "READ", f"{addr.key()} -> {describe_values(values)}")
            return values
        return frozenset({Unknown("operand")})

    def _load_cell(self, state: RegState, addr: Addr) -> FrozenSet:
        """The may-set a cell holds.

        * never written in this function -> one stable *slot* identity, which is
          what makes two reads of the same slot the same object (D4);
        * written and exact -> its value set (a singleton is a must fact);
        * merged/approximate -> the members it may hold, each with its own
          identity; a member whose value is unknown keeps a per-state symbol;
        * a lost (top) cell -> ``Unknown``: no identity at all, so nothing can be
          confirmed from it.  Never fall back to the never-written identity here:
          that collision is what turned "we know nothing" into "same object".
        """
        cell = state.mem.cells.get(addr)
        if cell is None:
            if state.mem.is_lost(addr):
                return frozenset({Unknown(f"lost:{addr.key()}")})
            return frozenset({self._cell_symbol(addr, CELL_NEVER_WRITTEN, -1, None)})
        if cell.state == CELL_TOP:
            return frozenset({Unknown(f"top:{addr.key()}")})
        members = []
        for value in cell.values:
            if isinstance(value, Unknown):
                members.append(self._cell_symbol(addr, cell.state, cell.version, value.reason))
            else:
                members.append(value)
        if not members or len(members) > self.max_values:
            return frozenset({self._cell_symbol(addr, cell.state, cell.version, None)})
        return frozenset(members)

    @staticmethod
    def _cell_symbol(addr: Addr, state_name: str, version: int,
                     reason: Optional[str]) -> Addr:
        """A stable identity for (cell, lattice state, version[, lost reason])."""
        # "##" separates the cell key from the lattice state: the cell key itself
        # contains "|" (it embeds nested symbols), so a single-char separator
        # would cut the key in half and silently merge two different slots.
        #
        # Only an EXACT cell carries its version into the identity.  That is what
        # makes a store a kill (a new version is a new object).  An APPROX cell
        # has no usable version: the arms disagree about it, so keying the
        # identity on it would both invent an order and keep the fixpoint moving.
        if state_name == CELL_EXACT:
            key = f"{addr.key()}##{state_name}:v{version}"
        else:
            key = f"{addr.key()}##{state_name}"
        if reason:
            key += f"|u:{reason}"
        return Addr("value", Affine.sym(f"s:{key}"))

    def _mem_addr(self, state: RegState, ins, op) -> Optional[Addr]:
        if op.type != X86_OP_MEM:
            return None
        mem = op.mem
        scale = mem.scale or 1
        disp = mem.disp
        base_name = ins.reg_name(mem.base) if mem.base else ""
        index_name = ins.reg_name(mem.index) if mem.index else ""
        if base_name == "rip":
            # a RIP-relative operand can carry an index too (global_table[i]); the
            # index belongs in the cell expression or two different slots merge
            base = Affine.of(ins.address + ins.size + disp)
            if index_name and index_name not in FRAME:
                index = self._affine_of(state, index_name)
                if index is not None:
                    return Addr("global", base.add(index.scale(scale)))
            return Addr("global", base)
        if base_name in FRAME:
            space, aff0 = f"frame:{base_name}", Affine.of(0)
        elif base_name:
            got = self._space_of(state, base_name)
            if got is None:
                return None
            space, aff0 = got
        else:
            space, aff0 = "abs", Affine.of(0)
        if index_name:
            index = self._affine_of(state, index_name)
            if index is None:
                return None
            aff = aff0.add(index.scale(scale)).add(Affine.of(disp))
        else:
            aff = aff0.add(Affine.of(disp))
        return Addr(space, aff)

    def _space_of(self, state: RegState, reg: str) -> Optional[Tuple[str, Affine]]:
        vals = state.get(reg)
        if len(vals) != 1:
            return None
        value = next(iter(vals))
        if isinstance(value, Ptr):
            return f"obj:{value.obj.describe()}", Affine.of(0)
        if isinstance(value, Addr):
            return value.base, value.aff
        if isinstance(value, Const):
            return f"abs:{value.value:#x}", Affine.of(0)
        return None

    def _affine_of(self, state: RegState, reg: str) -> Optional[Affine]:
        vals = state.get(reg)
        if len(vals) != 1:
            return None
        value = next(iter(vals))
        if isinstance(value, Const):
            return Affine.of(value.value)
        if isinstance(value, Addr) and value.base in ("value",):
            return value.aff
        return None

    def _affine_or_space(self, state: RegState, reg: str) -> Optional[Affine]:
        """Scalar view of a register: constants and value symbols only."""
        return self._affine_of(state, reg)

    def _fold_address(self, state: RegState, ins, dst: str, ops,
                      mnemonic: str) -> Optional[FrozenSet]:
        """``ptr + scalar`` and ``scalar + ptr`` keep one address expression."""
        if len(ops) != 2:
            return None
        dst_vals = state.get(dst)
        if len(dst_vals) != 1:
            return None
        dst_val = next(iter(dst_vals))

        def as_affine(value) -> Optional[Affine]:
            if isinstance(value, Const):
                return Affine.of(value.value)
            if isinstance(value, Addr) and value.base in ("value", "abs"):
                return value.aff
            return None

        def as_space(value) -> Optional[Tuple[str, Affine]]:
            if isinstance(value, Ptr):
                return f"obj:{value.obj.describe()}", Affine.of(0)
            if isinstance(value, Addr) and value.base not in ("value", "abs"):
                return value.base, value.aff
            return None

        sign = 1 if mnemonic == "add" else -1
        space = as_space(dst_val)
        if space is not None:
            right = self._operand_affine(state, ins, ops[1])
            if right is None:
                return None
            return frozenset({Addr(space[0], space[1].add(right.scale(sign)))})
        dst_aff = as_affine(dst_val)
        if dst_aff is None or mnemonic != "add":
            return None
        src_vals = self._operand_values(state, ins, ops[1])
        if src_vals is None or len(src_vals) != 1:
            return None
        src_space = as_space(next(iter(src_vals)))
        if src_space is None:
            return None
        return frozenset({Addr(src_space[0], src_space[1].add(dst_aff))})

    def _operand_values(self, state: RegState, ins, op) -> Optional[FrozenSet]:
        if op.type == X86_OP_REG:
            return state.get(ins.reg_name(op.reg))
        if op.type == X86_OP_IMM:
            return frozenset({Const(int(op.imm))})
        return None

    def _operand_affine(self, state: RegState, ins, op) -> Optional[Affine]:
        if op.type == X86_OP_IMM:
            return Affine.of(int(op.imm))
        if op.type == X86_OP_REG:
            return self._affine_of(state, ins.reg_name(op.reg))
        return None

    def _imm_or_affine(self, state: RegState, ins, op) -> Optional[Affine]:
        if op.type == X86_OP_IMM:
            return Affine.of(int(op.imm))
        if op.type == X86_OP_REG:
            return self._affine_of(state, ins.reg_name(op.reg))
        return None

    # -- uses --------------------------------------------------------------
    def _objects_in(self, values: Iterable) -> List[Obj]:
        """Objects behind a value set, in a stable order.

        ``values`` is a frozenset, whose iteration order depends on the hash seed.
        Sorting keeps the emitted records, and therefore the event counters,
        identical between two runs of the same firmware.
        """
        out = []
        for value in sorted(values, key=repr):
            if isinstance(value, Ptr):
                out.append(value.obj)
            elif isinstance(value, Addr):
                out.append(Obj("addr", value.key()))
        return out

    def _use_base(self, state: RegState, ins, op, kind: str) -> None:
        """A memory operand's base/target object is *used* here."""
        if op.type != X86_OP_MEM:
            return
        mem = op.mem
        base_name = ins.reg_name(mem.base) if mem.base else ""
        if not base_name or base_name in FRAME or base_name == "rip":
            carrier = ""
        else:
            carrier = base_name
            for obj in self._objects_in(state.get(base_name)):
                self._record_use(state, obj, ins.address, kind, carrier)
        index_name = ins.reg_name(mem.index) if mem.index else ""
        if index_name and index_name not in FRAME:
            for obj in self._objects_in(state.get(index_name)):
                self._record_use(state, obj, ins.address, kind, index_name)

    def _record_use(self, state: RegState, obj: Obj, site: int, kind: str, carrier: str) -> None:
        proven = self._proven_release_before(state, obj, site)
        release_sites = state.release_sites.get(obj, ())
        if proven is not None:
            verdict, confirmed = CONFIRMED, True
            release_site = proven
        elif obj in state.released_must or obj in state.released_may:
            # Pick a release that can actually precede this use -- including a
            # release later in the same block when that block is part of a cycle:
            # ``free(p)`` at the end of a loop body frees what the *next*
            # iteration reads at the top, which is the commonest real shape and
            # used to be dropped by a plain address comparison.
            candidates = [s for s in release_sites if self._may_precede(s, site)]
            release_site = candidates[0] if candidates else -1
            if release_site < 0:
                return
            # two different "not proven" shapes: a release on one branch (use not
            # reachable from the release and back), or a release inside a cycle
            # where this use also precedes it
            back = self._may_precede(site, release_site) or self._block_is_cyclic(
                self.view.block_of(release_site) or -1)
            verdict, confirmed = (MAY if back else PATH_DEPENDENT), False
        else:
            # Passing an object to a call whose effect is unknown is *not*
            # evidence of a use after release: most calls take pointers and
            # leave them alive.  The escape is recorded as evidence on the
            # finding it belongs to, never as a finding of its own.
            return
        # one finding per released object: a released object used in ten places is
        # one defect with ten witnesses, not ten defects
        for defect in self.defects:
            if defect.obj == obj and defect.release_site == release_site:
                return
        release_precondition = state.release_precondition(obj, release_site)
        self.defects.append(
            Defect(
                detector="D1_use_after_release",
                kind=verdict,
                obj=obj,
                release_site=release_site,
                release_kind=state.release_kind(obj, release_site),
                use_site=site,
                use_kind=kind,
                carrier=carrier,
                identity_class="DIRECT" if obj.kind in ("arg", "ret", "alloc") else "SAME_SLOT",
                confirmed=confirmed,
                detail={
                    "object_state": state.object_state(obj),
                    "release_sites": [hex(s) for s in release_sites],
                    "release_precondition": release_precondition,
                    "ordering": self._ordering_witness(release_site, site),
                    "identity_provable": self._provable(obj),
                    "carrier_origin": hex(state.origins.get(carrier, 0)) if carrier else None,
                    "unknown_effects": [hex(s) for s in state.unknown_effect[-4:]],
                    "escaped_to_unknown_call": obj in state.uncertain,
                    "lifecycle_timeline": self._timeline_for(state, obj),
                    "path_conditions": self._path_conditions(release_site, site),
                },
            )
        )

    def _ordering_witness(self, release_site: int, use_site: int) -> str:
        """How the release is known to precede the use (audit evidence)."""
        release_block = self.view.block_of(release_site)
        use_block = self.view.block_of(use_site)
        if release_block is None or use_block is None:
            return "unknown"
        if release_block == use_block:
            if use_site >= release_site:
                return "same_block_forward"
            return "loop_carried" if self._block_is_cyclic(release_block) else "none"
        if self._can_reach(release_site, use_site):
            return "cfg_path" if not self._dominates(release_site, use_site) else "dominates"
        return "loop_carried" if self._block_is_cyclic(release_block) else "none"

    def _may_precede(self, release_site: int, use_site: int) -> bool:
        """Can the release at ``release_site`` happen before the use at ``use_site``?

        Same block, release after use: only when the block is part of a cycle, in
        which case the release runs in iteration *n* and the use in *n+1*.  That is
        the loop-carried shape the previous guard threw away.
        """
        release_block = self.view.block_of(release_site)
        use_block = self.view.block_of(use_site)
        if release_block is None or use_block is None:
            return False
        if release_block == use_block:
            if use_site >= release_site:
                return True
            return self._block_is_cyclic(release_block)
        return self._can_reach(release_site, use_site)

    def _block_is_cyclic(self, block: int) -> bool:
        cache = getattr(self, "_cyc_cache", None)
        if cache is None:
            cache = {}
            self._cyc_cache = cache
        if block in cache:
            return cache[block]
        cyclic = False
        for succ in self.view.succ.get(block, ()):
            if block in set(self.view.reachable_blocks(succ)):
                cyclic = True
                break
        cache[block] = cyclic
        return cyclic

    def _proven_release_before(self, state: RegState, obj: Obj, site: int) -> Optional[int]:
        """A *definite* release of ``obj`` that every path to ``site`` must pass.

        The merged may/must state cannot express this: a loop body releases the
        object on every iteration, but the merge with the first iteration's state
        only says "may".  Dominance can express it, and dominance is what makes a
        claim falsifiable -- either every path reaches the use through the release
        or it does not.
        """
        for candidate in sorted(state.definite_sites.get(obj, ())):
            if candidate > site:
                continue
            if self.view.block_of(candidate) == self.view.block_of(site):
                return candidate
            if self._dominates(candidate, site):
                return candidate
        return None

    def _timeline_for(self, state: RegState, obj: Obj, limit: int = 14) -> List[str]:
        """The object's own lifecycle, in execution order, from the current state."""
        needle = obj.describe()
        rows = [f"{site:#x} {event} {detail}" for site, event, detail in state.timeline
                if needle in detail]
        return rows[-limit:]

    def _path_conditions(self, release_site: int, use_site: int, limit: int = 24) -> dict:
        """The witness path between the release and the use, with its branches."""
        start = self.view.block_of(release_site)
        target = self.view.block_of(use_site)
        if start is None or target is None:
            return {"blocks": [], "branches": [], "witness_found": False}
        if start == target:
            return {"blocks": [hex(start)], "branches": [], "witness_found": True}
        parent: Dict[int, int] = {start: start}
        order = [start]
        found = False
        while order and not found:
            nxt = []
            for block in order:
                for succ in self.view.succ.get(block, ()):
                    if succ in parent:
                        continue
                    parent[succ] = block
                    if succ == target:
                        found = True
                        break
                    nxt.append(succ)
                if found:
                    break
            order = nxt
        if not found:
            return {"blocks": [], "branches": [], "witness_found": False}
        path = [target]
        while path[-1] != start:
            path.append(parent[path[-1]])
        path.reverse()
        branches = []
        for block in path[:limit]:
            last = (self.view.ins_by.get(block) or [None])[-1]
            if last is not None and last.mnemonic.startswith("j"):
                branches.append(f"{last.address:#x} {last.mnemonic} {last.op_str}")
        return {
            "blocks": [hex(b) for b in path[:limit]],
            "branches": branches[:limit],
            "witness_found": True,
        }

    def _can_reach(self, first: int, second: int) -> bool:
        """Is there a CFG path from the block of ``first`` to the block of ``second``?"""
        start = self.view.block_of(first)
        target = self.view.block_of(second)
        if start is None or target is None:
            return False
        if start == target:
            return second >= first
        cache = getattr(self, "_reach_cache", None)
        if cache is None:
            cache = {}
            self._reach_cache = cache
        seen = cache.get(start)
        if seen is None:
            seen = set(self.view.reachable_blocks(start))
            cache[start] = seen
        return target in seen

    def _dominates(self, first: int, second: int) -> bool:
        start = self.view.block_of(first)
        target = self.view.block_of(second)
        if start is None or target is None:
            return False
        if start == target:
            return True
        cache = getattr(self, "_dom_cache", None)
        if cache is None:
            cache = self.view.dominators() if hasattr(self.view, "dominators") else {}
            self._dom_cache = cache
        doms = cache.get(target) or set()
        return start in doms

    # -- calls -------------------------------------------------------------
    def _call(self, state: RegState, ins, block: int) -> None:
        site = ins.address
        target = None
        for op in ins.operands:
            if op.type == X86_OP_IMM:
                target = int(op.imm)
        if target is None:
            # indirect call: the target value is used (and unknown)
            for op in ins.operands:
                if op.type == X86_OP_REG:
                    for obj in self._objects_in(state.get(ins.reg_name(op.reg))):
                        self._record_use(state, obj, site, "indirect_call", ins.reg_name(op.reg))
                elif op.type == X86_OP_MEM:
                    self._use_base(state, ins, op, "indirect_call")
                    addr = self._mem_addr(state, ins, op)
                    if addr is not None:
                        self._record_access(site, "read", addr, ins, op)
                        for obj in self._objects_in(self._load_cell(state, addr)):
                            self._record_use(state, obj, site, "indirect_call", "[mem]")
        args = [(reg, state.get(reg)) for reg in ARGREGS]
        role = self.catalog.role_at(target) if target is not None else None
        if role in (ROLE_FREE, ROLE_REFCOUNT_RELEASE):
            semantics = self.catalog.release_semantics(target)
            # dropping a *reference* does not invalidate the pointer: the object
            # stays alive while other references exist, so a later use is normal
            # and must never become a finding.  Only a real free does that.
            invalidates = role == ROLE_FREE
            kind = self._release_kind_name(semantics, invalidates)
            arg0_values = state.get("rdi")
            # A *definite* release needs exactly one object with a real identity:
            # a may-set of two candidates, or a symbol whose identity was lost,
            # can only ever be a may-release.  Marking every member of a may-set
            # as released is how "the pointer might be one of these" became "this
            # object is freed".
            proven = self._single_provable(arg0_values)
            definite = invalidates and semantics == "definite" and proven is not None
            precondition = "" if definite else self._precondition_for(
                target, semantics, invalidates, arg0_values)
            for value in sorted(arg0_values, key=repr):
                for obj in self._objects_in([value]):
                    if definite:
                        state.mark_released(obj, site, definite=True, semantics=kind,
                                            precondition="")
                    elif invalidates:
                        state.mark_may_released(obj, site, kind, precondition)
                    else:
                        # refcount: recorded, but the object stays LIVE
                        state.release_sites[obj] = tuple(
                            sorted(set(state.release_sites.get(obj, ())) | {site}))
                        state._note_fact(obj, site, kind, precondition)
                    self._add_release({
                        "site": site,
                        "object": obj.describe(),
                        "callee": target,
                        "semantics": semantics if invalidates else "refcount",
                        "release_kind": kind,
                        "invalidates": invalidates,
                        "treats_as_defect": definite,
                        "precondition": precondition,
                        "source_cell": self._cell_of_value(value),
                        "source_value": describe_values([value]),
                    })
                    state.note(site, "RELEASE",
                               f"{kind} {obj.describe()} @{site:#x}"
                               + (f" IF {precondition}" if precondition else ""))
        else:
            # an unknown call is *not* known to leave its arguments alone, so the
            # arguments are uses *before* the call and possibly-freed after it
            for reg, values in args:
                for obj in self._objects_in(values):
                    self._record_use(state, obj, site, "call_arg", reg)
            for reg, values in args:
                for obj in self._objects_in(values):
                    state.mark_uncertain(obj, site)
            state.unknown_effect = state.unknown_effect + (site,)
            state.note(site, "CALL_UNKNOWN", f"effect unknown @{site:#x}")
        # out parameters: an argument that is an *address* may be written through.
        # The write is a *may* write, so the previous content stays a candidate --
        # replacing it outright is what destroyed the identity of a pointer that
        # was still in the slot.
        for reg, values in args:
            for value in sorted(values, key=repr):
                if isinstance(value, Addr) and value.base.startswith(("frame:", "obj:", "value")):
                    cell_values = state.mem.load(value)
                    state.mem.store(value, frozenset(cell_values | {Unknown(f"outparam:{site:#x}")}))
                elif isinstance(value, Ptr):
                    self._invalidate_object_cells(state, value.obj, site)
        # results and clobbers
        if role == ROLE_ALLOC:
            result = Ptr(self._alloc_object(state, site))
        else:
            result = Ptr(self._ret_object(state, site))
        state.clobber([r for r in CALLER_SAVED if r != "rax"], f"call:{site:#x}")
        self._set_reg(state, "rax", frozenset({result}), site)
        state.note(site, "CALL",
                   f"target={target if target is None else hex(target)} "
                   f"role={role or 'unknown'} -> {result.obj.describe()}")

    # -- release helpers ---------------------------------------------------
    @staticmethod
    def _release_kind_name(semantics: str, invalidates: bool) -> str:
        if not invalidates:
            return "refcount"
        if semantics == "definite":
            return "free"
        if semantics == "conditional":
            return "conditional_free"
        return "may_free"

    def _precondition_for(self, target, semantics: str, invalidates: bool,
                          values: FrozenSet) -> str:
        """Say out loud *why* this release is not a proven one."""
        if not invalidates:
            return "reference drop does not free the object"
        if semantics != "definite":
            return f"callee {target if target is None else hex(target)} frees on some path only"
        if len(values) != 1:
            return f"argument may be one of {len(values)} objects"
        return "argument has no provable object identity"

    @staticmethod
    def _provable(obj: Obj) -> bool:
        """Does this object have an identity a release can be pinned to?"""
        text = obj.key
        for marker in ("#top", "##top:", "##lost:"):
            if marker in text:
                return False
        return True

    def _single_provable(self, values: FrozenSet) -> Optional[Obj]:
        """The one object a release can be pinned to, or ``None``.

        A cell's content is carried as an ``Addr`` symbol (that is what keeps slot
        arithmetic working), so the check must go through ``_objects_in`` rather
        than insisting on a ``Ptr``.
        """
        if len(values) != 1:
            return None
        objects = self._objects_in(values)
        if len(objects) != 1:
            return None
        return objects[0] if self._provable(objects[0]) else None

    @staticmethod
    def _next_gen(gens: Dict[int, int], site: int) -> int:
        """Generation counter for one allocation site; 0 means "too many".

        Inside a loop the same call site allocates a *new* object each iteration,
        so the identity has to differ.  Counting generations keeps iteration 1 and
        2 apart; beyond :data:`MAX_OBJ_GEN` the site degrades to an identity that
        cannot be confirmed, which is the conservative end.
        """
        current = gens.get(site)
        if current is None:
            gens[site] = 1
            return 1
        if current == 0:
            return 0
        gen = current + 1
        if gen > MAX_OBJ_GEN:
            gens[site] = 0
            return 0
        gens[site] = gen
        return gen

    def _alloc_object(self, state: RegState, site: int) -> Obj:
        gen = self._next_gen(state.alloc_gen, site)
        if gen == 0:
            self.dropped_identities += 1
            return Obj("alloc", f"{site:#x}#top")
        return Obj("alloc", f"{site:#x}#{gen}")

    def _ret_object(self, state: RegState, site: int) -> Obj:
        gen = self._next_gen(state.ret_gen, site)
        if gen == 0:
            self.dropped_identities += 1
            return Obj("ret", f"{site:#x}#top")
        return Obj("ret", f"{site:#x}#{gen}")

    def _add_release(self, record: dict) -> None:
        """Record a release once per (site, object): count every event.

        A loop re-emits the same release with a growing may-set, so the raw event
        count and the distinct-record count have to be kept apart.  A later
        *definite* record replaces an earlier may-record for the same site and
        object, because that is the stronger claim.
        """
        self.release_events_raw += 1
        key = (record["site"], record["object"])
        previous = self._release_index.get(key)
        if previous is not None:
            if record.get("treats_as_defect") and not previous.get("treats_as_defect"):
                self.releases[self.releases.index(previous)] = record
                self._release_index[key] = record
            return
        if len(self.releases) > 4000:
            self._trunc("release_cap")
            return
        self._release_keys.add(key)
        self._release_index[key] = record
        self.releases.append(record)

    def _invalidate_object_cells(self, state: RegState, obj: Obj, site: int) -> None:
        prefix = f"obj:{obj.describe()}"
        for addr in list(state.mem.cells):
            if addr.base == prefix:
                current = state.mem.load(addr)
                state.mem.store(addr, frozenset(current | {Unknown(f"called:{site:#x}")}))

    def _release_via_jump(self, state: RegState, ins) -> bool:
        target = None
        for op in ins.operands:
            if op.type == X86_OP_IMM:
                target = int(op.imm)
        if target is None:
            return False
        role = self.catalog.role_at(target)
        if role not in (ROLE_FREE, ROLE_REFCOUNT_RELEASE):
            return False
        # A tail jump to a wrapper is a call in everything but spelling: it must
        # go through the same semantics check as ``_call``.  Treating it as a
        # definite free is what let a conditional wrapper confirm a use-after-free.
        semantics = self.catalog.release_semantics(target)
        invalidates = role == ROLE_FREE
        kind = self._release_kind_name(semantics, invalidates)
        arg0_values = state.get("rdi")
        proven = self._single_provable(arg0_values)
        definite = invalidates and semantics == "definite" and proven is not None
        precondition = "" if definite else self._precondition_for(
            target, semantics, invalidates, arg0_values)
        for value in sorted(arg0_values, key=repr):
            for obj in self._objects_in([value]):
                if definite:
                    state.mark_released(obj, ins.address, definite=True, semantics=kind,
                                        precondition="")
                elif invalidates:
                    state.mark_may_released(obj, ins.address, kind, precondition)
                else:
                    state.release_sites[obj] = tuple(
                        sorted(set(state.release_sites.get(obj, ())) | {ins.address}))
                    state._note_fact(obj, ins.address, kind, precondition)
                self._add_release({
                    "site": ins.address,
                    "object": obj.describe(),
                    "callee": target,
                    "semantics": semantics if invalidates else "refcount",
                    "release_kind": kind,
                    "invalidates": invalidates,
                    "treats_as_defect": definite,
                    "precondition": precondition,
                    "source_cell": self._cell_of_value(value),
                    "source_value": describe_values([value]),
                    "via": "tail_jump",
                })
                state.note(ins.address, "RELEASE",
                           f"tail_jump {kind} {obj.describe()} @{ins.address:#x}"
                           + (f" IF {precondition}" if precondition else ""))
        return True

    # -- accesses ----------------------------------------------------------
    def _record_access(self, site: int, kind: str, addr: Addr, ins, op) -> None:
        self.access_events_raw += 1
        if len(self.accesses) > 20000:
            self._trunc("access_cap")
            return
        key = (site, kind, addr.key())
        if key in self._access_keys:
            return
        self._access_keys.add(key)
        indexed = addr.is_indexed()
        index_sym = None
        scale = 1
        if op.type == X86_OP_MEM and op.mem.index:
            scale = op.mem.scale or 1
        if indexed:
            # the canonical index symbol, not the register that carried it: two
            # different expressions for one index must compare equal here
            index_sym = ",".join(addr.aff.symbols())
        self.accesses.append(
            Access(site=site, kind=kind, cell=addr.key(), base=addr.base, scale=scale,
                   index_sym=index_sym, offset=addr.offset(), indexed=indexed,
                   carrier=ins.reg_name(op.mem.base) if op.type == X86_OP_MEM and op.mem.base else "")
        )

    @staticmethod
    def _cell_of_value(value) -> Optional[str]:
        """The cell key behind a value, when the value *is* a cell's content.

        Cell symbols carry the lattice state and version (``s:<cell>|<state>:v<n>``);
        the D4 relation is about the *slot*, so the state suffix is stripped here.
        """
        if not isinstance(value, Addr) or value.base != "value":
            return None
        if len(value.aff.terms) != 1 or value.aff.const:
            return None
        symbol = value.aff.terms[0][0]
        if not symbol.startswith("s:"):
            return None
        body = symbol[2:]
        if "##" in body:
            return body.rsplit("##", 1)[0]
        if "@v" in body:
            return body.rsplit("@v", 1)[0]
        return None

    # -- post pass ---------------------------------------------------------
    def alias_defects(self) -> List[Defect]:
        """Releases through a table slot whose *slot* identity is only a may-alias."""
        out: List[Defect] = []
        released_slots: Dict[Tuple[str, int, str], dict] = {}
        for release in self.releases:
            if not release.get("treats_as_defect"):
                continue
            cell = release.get("source_cell")
            if not cell:
                continue
            for acc in self.accesses:
                if acc.kind != "read" or acc.cell != cell:
                    continue
                released_slots[(acc.base, acc.scale, cell)] = release
                break
        for (base, scale, cell), release in sorted(released_slots.items()):
            if not base.startswith("obj:") and not base.startswith("frame:"):
                continue
            for acc in self.accesses:
                if acc.base != base or acc.cell == cell:
                    continue
                if not acc.indexed:
                    continue
                klass = ALIAS_MAY if acc.index_sym else ALIAS_UNKNOWN
                out.append(
                    Defect(
                        detector="D4_table_slot_lifecycle",
                        kind=klass,
                        obj=Obj("slot", cell),
                        release_site=release["site"],
                        release_kind=release["semantics"],
                        use_site=acc.site,
                        use_kind=acc.kind,
                        carrier=acc.carrier,
                        identity_class="MAY_ALIAS" if klass == ALIAS_MAY else "UNKNOWN",
                        confirmed=False,
                        detail={
                            "released_slot": cell,
                            "compared_slot": acc.cell,
                            "base": base,
                            "released_scale": scale,
                            "compared_scale": acc.scale,
                            "index": acc.index_sym,
                            "why": "same table base and scale, different index expression: "
                                   "the slots are not provably equal and not provably distinct",
                        },
                    )
                )
        return out

    # -- results -----------------------------------------------------------
    def defect_stats(self) -> dict:
        kinds: Dict[str, int] = {}
        for defect in self.defects:
            kinds[defect.kind] = kinds.get(defect.kind, 0) + 1
        indexed = [r for r in self.releases if r.get("source_cell")]
        slots = {r["source_cell"] for r in indexed if r.get("treats_as_defect")}
        reread = sum(1 for acc in self.accesses
                     if acc.kind == "read" and acc.cell in slots)
        return {
            "indexed_release_events": len(indexed),
            "slots_released": len(slots),
            "slot_reads_after_indexed_release": reread,
            "defects": len(self.defects),
            "by_kind": kinds,
            # ``releases``/``accesses`` are *distinct* records; the raw counters
            # count every emitted event, so a loop no longer looks like thousands
            # of releases of thousands of objects
            "releases": len(self.releases),
            "release_events": self.release_events_raw,
            "accesses": len(self.accesses),
            "access_events": self.access_events_raw,
            "indexed_accesses": sum(1 for a in self.accesses if a.indexed),
            "iterations": self.iterations,
            "truncated": self.truncated,
            "widened": self.widened,
            "truncation_causes": dict(sorted(self.truncation_causes.items())),
            "dropped_identities": self.dropped_identities,
            "notes": self.notes[:8],
        }

    def findings(self) -> List[Finding]:
        """Confirmed defects only.

        A defect that is not proven is not a finding: it is an *observation*.
        Reporting a may-release as a finding is how a detector becomes noise, and
        an UNKNOWN state must never be handed upward as if it were confirmed.

        A run that was truncated did not see the whole function, so nothing it
        claims is confirmed either: the claim is downgraded to an observation with
        the truncation reason attached.  TRUNCATED must never read as "proven".
        """
        out: List[Finding] = []
        for defect in sorted(self.defects, key=lambda d: (d.release_site, d.use_site)):
            if not defect.confirmed:
                continue
            if self.truncated:
                defect.confirmed = False
                defect.detail["downgraded"] = "run truncated: " + ", ".join(
                    sorted(self.truncation_causes) or ["unknown"])
                continue
            out.append(self._finding(defect))
        return out

    def observations(self) -> List[dict]:
        """Unproven defects, kept with full evidence and never ranked as findings."""
        out = []
        for defect in sorted(self.defects, key=lambda d: (d.release_site, d.use_site)):
            if not defect.confirmed:
                payload = defect.as_dict()
                payload["function"] = hex(self.view.rva)
                out.append(payload)
        return out

    def _finding(self, defect: Defect) -> Finding:
        detector = "D1_use_after_release" if defect.detector.startswith("D1") else "D4_table_slot_lifecycle"
        bug_class = "OWNERSHIP_UAF" if detector.startswith("D1") else "AIO_KQUEUE_SLOT_UAF"
        if defect.confirmed:
            rank = 1
        elif defect.kind in (PATH_DEPENDENT, MAY):
            rank = 2
        else:
            rank = 3
        window = list(self.view.window(defect.release_site, 2, 2))
        if defect.use_site > 0:
            window.extend(self.view.window(defect.use_site, 2, 2))
        claims = {
            "object": defect.obj.describe(),
            "identity_class": defect.identity_class,
            "release_semantics": defect.release_kind,
            "use_kind": defect.use_kind,
            "carrier": defect.carrier,
            "confirmed": defect.confirmed,
            "verdict": defect.kind,
        }
        claims.update({k: v for k, v in defect.detail.items() if k not in claims})
        counter = {
            "confirmed": defect.confirmed,
            "remaining_uncertainty": (
                "none recorded on the witness path"
                if defect.confirmed else
                "identity or effect is not proven; the access is recorded, not asserted"
            ),
        }
        return Finding(
            detector=detector,
            bug_class=bug_class,
            function_rva=self.view.rva,
            function_size=self.view.size,
            function_name=self.view.name,
            site_rvas=(defect.release_site, defect.use_site),
            slot=defect.detail.get("released_slot") or defect.obj.describe(),
            rank=rank,
            claims=claims,
            counter_evidence=counter,
            window=tuple(window),
            falsification=(
                "show a store to the carrier between release and use, or prove the two "
                "index expressions equal (then this is the same slot, not a may-alias)"
            ),
        )
