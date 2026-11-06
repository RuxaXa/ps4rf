"""Generic interprocedural ownership and lifetime summaries.

What this module answers, for one function and without knowing any exploit:

* for each of the six System V argument registers, what the function does with it — read, write,
  compare, take a reference, drop a reference, free it, pass it on, store it somewhere, return it;
* what it returns — a constant, an alias of one of its own arguments, a field loaded out of one of
  them, a freshly allocated object, or something it could not decide;
* whether any of that is a *must* (every exit path) or only a *may* (one path), and whether the
  body was decoded completely enough to claim a negative at all.

Design rules, all of them learned from the defects this replaces:

1. **Object-keyed, not register-keyed.** Every effect hangs off ``("arg", i)`` (or
   ``("ret", site)``), and a register holding that value is only ever an alias of it. A summary
   keyed by register name merges two generations of the same register into one object.
2. **Refusal instead of a clean bill.** A body that could not be decoded, exceeded a budget, or
   calls something indirectly gets ``status`` of ``partial``/``refused``, and every negative
   claim it would otherwise publish ("this argument is unused", "the object is still live")
   degrades to ``UNKNOWN``.
3. **Zero is a claim; unknown is a refusal.** ``reads == []`` is only published from a complete
   body, because "no read found" and "no read possible to find" are different statements.
4. **A hop is a placement plus a callee effect.** Both need a witness, and the status is the
   weakest of the two. ``possible`` is never emitted: that word belongs to entry attribution, and
   a synthetic ``possible`` hop silently substantiates a chain.
5. **An indirect call invalidates everything downstream of it.** Its target is unknown, so no
   argument can be claimed untouched and no return can be claimed to be anything.

The forward value interpretation here is deliberately small: six argument values, load results,
constants and a top value. That is enough to answer the questions above and small enough to stay
reviewable. Everything it cannot represent is top, and top never proves anything.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .ownership import canon_reg

try:  # pragma: no cover - guarded
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
except Exception:  # pragma: no cover
    X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP = 2, 3, 1, -1

SCHEMA = "ps4rf.discovery.fn-summary/1"

#: System V argument registers, in order.
ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
ARG_INDEX = {name: index for index, name in enumerate(ARG_REGS)}

PROVEN = "PROVEN"
CONDITIONAL = "CONDITIONAL"
UNKNOWN = "UNKNOWN"
REFUTED = "REFUTED"

COMPLETE = "complete"
PARTIAL = "partial"
REFUSED = "refused"

LIVE = "LIVE"
RELEASED = "RELEASED"
MAY_RELEASED = "MAY_RELEASED"

OWN_NONE = "NONE"
OWN_DROP_REF = "DROP_REF"
OWN_FREE = "FREE"
OWN_TRANSFER_OUT = "TRANSFER_OUT"
OWN_STORE_OUT = "STORE_OUT"

RET_NONE = "NONE"
RET_CONST = "CONST"
RET_ARG_ALIAS = "ARG_ALIAS"
RET_FIELD_LOAD = "FIELD_LOAD"
RET_NEW_OBJECT = "NEW_OBJECT"
RET_UNKNOWN = "UNKNOWN"

ESCAPE_NONE = "none"
ESCAPE_GLOBAL = "global"
ESCAPE_RETURNED = "returned"
ESCAPE_CALLEE_SLOT = "callee_slot"
ESCAPE_UNKNOWN = "unknown"

MAX_BLOCKS = 240
MAX_ITERATIONS = 6
MAX_STEPS = 20000
MAX_EFFECT_SITES = 24
DEFAULT_DEPTH_CAP = 2
DEFAULT_FUNCTION_CAP = 512

#: State slots beside the registers: the spilled frame slots and the rsp displacement.
STACK_KEY = "\x00stack"
STACK_POINTER_KEY = "\x00rsp"

#: A value the interpreter carries through registers.  Tuples, so equality is identity here.
Value = Optional[tuple]          # None is "top": nothing is known about this register


def v_arg(index: int) -> tuple:
    return ("obj", ("arg", index, ()))


def v_global(target: int) -> tuple:
    """A global object, by the address the instruction referenced.

    Kernel code keeps its interesting objects in globals, not in its arguments: a socket list
    head, a netevent queue, a table of pointers. Refusing those leaves the whole analysis with an
    attributable object in 2% of the release sites.
    """
    return ("obj", ("glob", target, ()))


def v_interior(key: tuple, offset: int) -> tuple:
    """An interior pointer: same object, known displacement."""
    return ("ptr", key, offset)


def v_slot(base_key: tuple, index: tuple, scale: int, disp: int, epoch: tuple) -> tuple:
    """A slot of a table: the object a `[base + index*scale + disp]` load reads.

    The slot's identity is the whole tuple — which table instance, which index provenance, which
    scale and displacement, and which *generation*. Any one of them differing means a different
    object; a bare "element of table X" is a class, not an identity.
    """
    return ("obj", ("tab", (base_key, index, scale, disp, epoch), ()))


def v_const(value: int) -> tuple:
    return ("const", value)


def v_ret(site: int) -> tuple:
    return ("ret", site)


MAX_PATH = 2


def object_key(value: Value) -> Optional[tuple]:
    """The object a register value denotes, or ``None``.

    A key is ``(kind, origin, path)``: ``kind`` is ``arg`` (origin = argument index) or ``glob``
    (origin = the address the code referenced), and ``path`` is the chain of displacements that
    leads to the pointer. Every key is a distinct object with its own life cycle, which is the
    whole point: a container and the pointer stored in it must never share a key.
    """
    if not value:
        return None
    if value[0] == "obj":
        return value[1]
    if value[0] == "ptr":
        return value[1]
    return None


def index_label(index: tuple) -> str:
    return term_label(index) if index else "?"


def object_label(key: tuple) -> str:
    if not key:
        return "?"
    if key[0] == "tab":
        base_key, index, scale, disp, epoch = key[1]
        label = (f"tab[{object_label(base_key)}][{index_label(index)}*{scale}"
                 f"{'+' + hex(disp) if disp else ''}]")
        if epoch and any(epoch):
            label += f"@g{epoch[0]}.{epoch[1]}"
        return label + "".join(f"+{hex(off)}" for off in key[2])
    origin = f"arg{key[1]}" if key[0] == "arg" else f"glob{hex(key[1])}"
    return origin + "".join(f"+{hex(off)}" for off in key[2])


MAX_TERM_DEPTH = 4


def v_term(term: tuple) -> tuple:
    return ("term", term)


def _term_depth(term) -> int:
    if not isinstance(term, tuple):
        return 0
    return 1 + max([_term_depth(part) for part in term[1:]] or [0])


def _term_of(value: Value) -> Optional[tuple]:
    """The stable integer term a value denotes, if any.

    Only terms built from arguments and constants are stable: the same expression over the same
    inputs always yields the same index. A term that contains a load or a call is not stable and is
    refused, because reading it twice can yield two different values.
    """
    if not value:
        return None
    if value[0] == "obj":
        key = value[1]
        if key and key[0] == "arg" and not key[2]:
            return ("arg", key[1])
        return None
    if value[0] == "const":
        return ("const", value[1])
    if value[0] == "term":
        return value[1]
    return None


def _combine_term(op: str, left: Optional[tuple], right: Optional[tuple]) -> Value:
    if left is None or right is None:
        return None
    term = (op, left, right)
    if _term_depth(term) > MAX_TERM_DEPTH:
        return None
    return v_term(term)


def term_label(term) -> str:
    if not isinstance(term, tuple) or not term:
        return "?"
    kind = term[0]
    if kind == "arg":
        return f"arg{term[1]}"
    if kind == "const":
        return f"#{term[1]}"
    if kind in ("add", "sub", "and", "or", "xor", "shl", "shr", "sar", "mul"):
        return f"({term_label(term[1])}{'*' if kind == 'mul' else {'add': '+', 'sub': '-', 'and': '&', 'or': '|', 'xor': '^', 'shl': '<<', 'shr': '>>', 'sar': '>>a'}[kind]}{term_label(term[2])})"
    return str(kind)


def index_provenance(value: Value) -> Optional[tuple]:
    """Where an index value comes from — the only thing that may establish slot identity.

    An argument or a constant is a provenance: the same expression selects the same slot. A value
    loaded from memory, transformed by arithmetic or produced by a call is not: reading it twice
    can yield two different indices, so no identity may be claimed from it.
    """
    term = _term_of(value)
    if term is None or term[0] not in ("arg", "const", "add", "sub", "and", "or", "xor", "shl",
                                       "shr", "sar", "mul"):
        return None
    return term


def _field_value(base_key: Optional[tuple], offset: int) -> Value:
    """The object a load produces: the pointer stored at ``base_key`` + ``offset``."""
    if not base_key:
        return None
    if offset == 0 and base_key[0] == "tab":
        # A zero displacement into a slot *is* the slot: the loaded pointer is the table element,
        # and it must not gain a second identity ("slot + 0") next to the slot itself.
        return ("obj", base_key)
    path = tuple(base_key[2]) + (offset,)
    if len(path) > MAX_PATH:
        return None
    return ("obj", (base_key[0], base_key[1], path))


def _interior_offset(value: Value, offset: int) -> int:
    if value and value[0] == "ptr":
        return offset + value[2]
    return offset


@dataclass(frozen=True)
class AccessFact:
    offset: int
    width: int
    site: int

    def as_dict(self) -> dict:
        return {"offset": hex(self.offset) if self.offset >= 0 else f"-{hex(-self.offset)}",
                "width": self.width, "site": hex(self.site)}


@dataclass(frozen=True)
class CompareFact:
    offset: int
    width: int
    immediate: Optional[int]
    site: int
    branch_site: int = 0

    def as_dict(self) -> dict:
        return {"offset": self.offset, "width": self.width,
                "immediate": self.immediate, "site": hex(self.site),
                "branch_site": hex(self.branch_site) if self.branch_site else None}


@dataclass(frozen=True)
class ParamEffect:
    """Everything one function does with one argument register."""

    index: int
    register: str
    role: str = "NONE"
    reads: Tuple[AccessFact, ...] = ()
    writes: Tuple[AccessFact, ...] = ()
    compares: Tuple[CompareFact, ...] = ()
    drops_must: int = 0
    drops_may: int = 0
    takes: int = 0
    refcount_field: Optional[int] = None
    guard: str = UNKNOWN
    guard_reason: str = ""
    release_conditional: bool = False
    release_sites: Tuple[int, ...] = ()
    ownership: str = OWN_NONE
    ownership_strength: str = UNKNOWN
    ownership_site: int = 0
    escape: str = ESCAPE_NONE
    escape_site: int = 0
    escape_detail: str = ""
    postcondition: str = UNKNOWN
    postcondition_reason: str = ""
    key: tuple = ()
    label: str = ""

    def as_dict(self) -> dict:
        return {
            "object": self.label or (f"arg{self.index}" if self.index >= 0 else ""),
            "index": self.index, "register": self.register, "role": self.role,
            "reads": [r.as_dict() for r in self.reads],
            "writes": [w.as_dict() for w in self.writes],
            "compares": [c.as_dict() for c in self.compares],
            "refcount": {"drops_must": self.drops_must, "drops_may": self.drops_may,
                         "takes": self.takes, "field": (hex(self.refcount_field)
                                                        if self.refcount_field is not None else None),
                         "guard": self.guard, "guard_reason": self.guard_reason,
                         "release_conditional": self.release_conditional,
                         "release_sites": [hex(s) for s in self.release_sites]},
            "ownership": {"kind": self.ownership, "strength": self.ownership_strength,
                          "site": hex(self.ownership_site) if self.ownership_site else None},
            "escape": {"kind": self.escape, "site": hex(self.escape_site) if self.escape_site else None,
                       "detail": self.escape_detail},
            "postcondition": self.postcondition,
            "postcondition_reason": self.postcondition_reason,
        }


@dataclass(frozen=True)
class ReturnEffect:
    kind: str = RET_UNKNOWN
    arg_index: Optional[int] = None
    field_offset: Optional[int] = None
    const: Optional[int] = None
    owned: Optional[bool] = None
    site: int = 0
    why: str = ""

    def as_dict(self) -> dict:
        return {"kind": self.kind, "arg_index": self.arg_index,
                "field_offset": (hex(self.field_offset)
                                 if self.field_offset is not None else None),
                "const": self.const, "owned": self.owned,
                "site": hex(self.site) if self.site else None, "why": self.why}


@dataclass(frozen=True)
class CalleeFact:
    site: int
    target: Optional[int]
    resolution: str          # direct | indirect | missing

    def as_dict(self) -> dict:
        return {"site": hex(self.site),
                "target": hex(self.target) if self.target is not None else None,
                "resolution": self.resolution}


@dataclass(frozen=True)
class FunctionSummary:
    rva: int
    size: int
    extent_source: str = "record"
    status: str = REFUSED
    refusal: Optional[dict] = None
    params: Tuple[ParamEffect, ...] = ()
    field_objects: Tuple[ParamEffect, ...] = ()
    returns: ReturnEffect = field(default_factory=ReturnEffect)
    callees: Tuple[CalleeFact, ...] = ()
    indirect_calls: int = 0
    analysis: Dict = field(default_factory=dict)

    def param(self, index: int) -> ParamEffect:
        for effect in self.params:
            if effect.index == index:
                return effect
        return ParamEffect(index=index, register=ARG_REGS[index] if index < 6 else "")

    def object(self, key) -> ParamEffect:
        """The effect record for an object key, argument or field object alike."""
        for effect in list(self.params) + list(self.field_objects):
            if effect.key == tuple(key):
                return effect
        return ParamEffect(index=-1, register="", key=tuple(key) if key else (),
                           label=object_label(tuple(key)) if key else "")

    def all_objects(self) -> Tuple[ParamEffect, ...]:
        return tuple(self.params) + tuple(self.field_objects)

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA, "rva": hex(self.rva), "size": hex(self.size),
            "extent_source": self.extent_source, "status": self.status,
            "refusal": self.refusal,
            "params": [p.as_dict() for p in self.params],
            "field_objects": [o.as_dict() for o in self.field_objects],
            "returns": self.returns.as_dict(),
            "callees": [c.as_dict() for c in self.callees],
            "indirect_calls": self.indirect_calls,
            "analysis": self.analysis,
        }


@dataclass(frozen=True)
class HopEffect:
    """One call edge, judged on a placement witness and a callee effect witness."""

    call_site: int
    callee: Optional[int]
    argument: Optional[str]
    placement: str
    effect: str
    status: str
    ownership: str = OWN_NONE
    witnesses: Tuple[dict, ...] = ()
    why: str = ""
    summary_digest: str = ""
    summary_status: str = ""
    object_label_: str = ""

    def as_dict(self) -> dict:
        return {"call_site": hex(self.call_site),
                "callee": hex(self.callee) if self.callee is not None else None,
                "argument": self.argument, "placement": self.placement,
                "effect": self.effect, "status": self.status,
                "ownership": self.ownership, "witnesses": list(self.witnesses),
                "why": self.why, "summary_digest": self.summary_digest,
                "summary_status": self.summary_status, "object": self.object_label_}


# ------------------------------------------------------------------ dominators


def _dominators(view) -> Dict[int, set]:
    """Block dominators by the usual iterative intersection. Small and deterministic."""
    blocks = [b for b in view.blocks if view.ins_by.get(b)]
    if not blocks:
        return {}
    entry = view.ins[0].address
    entry_block = view._addr2blk.get(entry, blocks[0])
    dom: Dict[int, set] = {b: set(blocks) for b in blocks}
    dom[entry_block] = {entry_block}
    predecessors: Dict[int, List[int]] = {b: [] for b in blocks}
    for block, successors in view.succ.items():
        for successor in successors:
            if successor in predecessors:
                predecessors[successor].append(block)
    changed = True
    rounds = 0
    while changed and rounds < 40:
        changed = False
        rounds += 1
        for block in blocks:
            if block == entry_block:
                continue
            preds = [p for p in predecessors.get(block, []) if p in dom]
            if not preds:
                continue
            intersection = set(dom[preds[0]])
            for pred in preds[1:]:
                intersection &= dom[pred]
            new = intersection | {block}
            if new != dom[block]:
                dom[block] = new
                changed = True
    return dom


def _reachable_blocks(view) -> set:
    blocks = [b for b in view.blocks if view.ins_by.get(b)]
    if not blocks:
        return set()
    start = view._addr2blk.get(view.ins[0].address, blocks[0])
    seen, work = {start}, [start]
    while work:
        block = work.pop()
        for successor in view.succ.get(block, ()):
            if successor in view.blocks and successor not in seen:
                seen.add(successor)
                work.append(successor)
    return seen


def _skipped_by_branch(view, site: int) -> Optional[int]:
    """Address of a branch that jumps over ``site`` from before it, if any.

    Returns the branch address. ``None`` means no reachable branch can bypass the instruction,
    which is what a *must* claim needs on top of block dominance.
    """
    end = view.rva + view.size
    for ins in view.ins:
        if ins.address >= site:
            break
        mnemonic = ins.mnemonic.split()[-1]
        if not mnemonic.startswith("j"):
            continue
        target = None
        for operand in getattr(ins, "operands", []) or []:
            if getattr(operand, "type", None) == X86_OP_IMM:
                target = int(getattr(operand, "imm", 0))
        if target is not None and site < target < end:
            return ins.address
    return None


# ----------------------------------------------------------------- the interpreter


class _Body:
    """Forward value interpretation of one function body.

    Values are the tuples above; ``None`` is top. The state is a register map plus the facts
    collected so far. Merging keeps a fact only when both sides agree exactly, which keeps every
    published fact a must-fact.
    """

    def __init__(self, view, is_release, resolve_summary=None, store=None):
        self.view = view
        self.is_release = is_release
        self.resolve_summary = resolve_summary
        self.store = store
        self.reads: Dict[int, List[AccessFact]] = {}
        self.writes: Dict[int, List[AccessFact]] = {}
        self.compares: Dict[int, List[CompareFact]] = {}
        self.callees: List[CalleeFact] = []
        self.indirect_calls = 0
        self.escapes: Dict[int, Tuple[str, int, str]] = {}
        self.returns: List[Tuple[int, Value]] = []
        self.dispatched: List[dict] = []
        self.truncated = False
        self.truncation_causes: Dict[str, int] = {}
        self.steps = 0
        self.iterations = 0
        self.blocked_reason = ""
        #: Frame slots, keyed ("rbp", disp) or ("rsp", disp) with the displacement expressed
        #: against the *entry* rsp.  Spill/reload is how a pointer normally survives a call, so
        #: without this map 90% of the release call sites have an unattributable register.
        self.stack: Dict[tuple, Value] = {}
        self.rsp_delta = 0
        self.stack_writes = 0
        self.stack_reads = 0
        #: Object generations. A store through a table bumps that table's counter, and any call we
        #: cannot resolve bumps the global counter: after either, a slot read is a different object.
        self.table_epoch: Dict[tuple, int] = {}
        self.call_epoch = 0
        #: may-sets of spilled registers, keyed like the frame slots
        self.may_stack: Dict[tuple, Tuple[Value, ...]] = {}
        #: Object accesses the walk had to refuse. A body with any of these cannot support a
        #: negative ownership claim: the consumption may be exactly what was not resolved.
        self.unresolved_accesses = 0
        self.unresolved_reasons: Dict[str, int] = {}

    # -- bookkeeping --------------------------------------------------------
    def _trunc(self, cause: str) -> None:
        self.truncation_causes[cause] = self.truncation_causes.get(cause, 0) + 1
        self.truncated = True

    def _unresolved(self, reason: str) -> None:
        self.unresolved_accesses += 1
        self.unresolved_reasons[reason] = self.unresolved_reasons.get(reason, 0) + 1

    def _epoch_for(self, base_key: tuple) -> tuple:
        return (self.table_epoch.get(base_key, 0), self.call_epoch)

    def _note_escape(self, key: tuple, kind: str, site: int, detail: str) -> None:
        current = self.escapes.get(key)
        if current is None:
            self.escapes[key] = (kind, site, detail)

    # -- driver -------------------------------------------------------------
    def run(self) -> None:
        blocks = [b for b in self.view.blocks if self.view.ins_by.get(b)]
        if not blocks:
            self.blocked_reason = "no decodable block"
            return
        if len(blocks) > MAX_BLOCKS:
            self._trunc("block_budget")
            self.blocked_reason = f"block budget: {len(blocks)} > {MAX_BLOCKS}"
            return
        reachable = _reachable_blocks(self.view)
        entry_block = self.view._addr2blk.get(self.view.ins[0].address, blocks[0])
        in_states: Dict[int, Dict[str, Value]] = {
            entry_block: {**{name: v_arg(i) for i, name in enumerate(ARG_REGS)},
                          STACK_KEY: {}, STACK_POINTER_KEY: 0,
                          MAY_KEY: {name: (v_arg(i),) for i, name in enumerate(ARG_REGS)}}}
        work = [entry_block]
        visits: Dict[int, int] = {entry_block: 1}
        while work:
            block = work.pop(0)
            state = in_states.get(block)
            if state is None:
                continue
            self.iterations += 1
            if self.iterations > MAX_BLOCKS * MAX_ITERATIONS:
                self._trunc("iteration_budget")
                self.blocked_reason = "fixpoint budget exhausted"
                return
            out = self._exec_block(_clone_state(state), block)
            if out is None:
                continue
            for successor in self.view.succ.get(block, ()):
                if successor not in reachable:
                    continue
                previous = in_states.get(successor)
                merged = out if previous is None else _merge(previous, out)
                if previous is not None and merged == previous:
                    continue
                visits[successor] = visits.get(successor, 0) + 1
                if visits[successor] > MAX_ITERATIONS:
                    merged = {k: None for k in ARG_REGS + ("rax",)}
                    merged[MAY_KEY] = {}
                in_states[successor] = merged
                work.append(successor)

    def _exec_block(self, state: Dict[str, Value], block: int) -> Optional[Dict[str, Value]]:
        for ins in self.view.ins_by.get(block, ()):
            self.steps += 1
            if self.steps > MAX_STEPS:
                self._trunc("step_budget")
                self.blocked_reason = "step budget exhausted"
                return None
            self._exec(ins, state)
        return state

    # -- frame slots --------------------------------------------------------
    def _slot_of(self, ins, mem, state) -> Optional[tuple]:
        """Frame slot a memory operand addresses, in entry-rsp coordinates."""
        if getattr(mem, "index", 0):
            return None
        base_name = _reg_name_mem(ins, mem.base)
        if not base_name:
            return None
        base_name = canon_reg(base_name)
        displacement = int(getattr(mem, "disp", 0))
        if base_name == "rbp":
            return ("rbp", displacement)
        if base_name == "rsp":
            delta = state.get(STACK_POINTER_KEY)
            if delta is None:
                return None
            return ("rsp", displacement + delta)
        return None

    # -- instruction semantics ---------------------------------------------
    def _exec(self, ins, state: Dict[str, Value]) -> None:
        mnemonic = ins.mnemonic.split()[-1]
        operands = list(getattr(ins, "operands", []) or [])
        target = self.view.calls.get(ins.address)

        if mnemonic == "call":
            self._exec_call(ins, target, state)
            return
        if mnemonic in ("ret", "hlt", "ud2"):
            self.returns.append((ins.address, state.get("rax")))
            return
        if mnemonic in ("cmp", "test"):
            self._exec_compare(ins, operands, state)
            return
        if mnemonic in ("lock", "xadd", "xchg", "inc", "dec", "add", "sub") or \
                ins.mnemonic.startswith("lock"):
            if self._exec_read_modify_write(ins, mnemonic, operands, state):
                return
        if not operands:
            return
        if mnemonic in ("push", "pop"):
            delta = state.get(STACK_POINTER_KEY)
            if delta is None:
                return
            slot = ("rsp", delta - 8 if mnemonic == "push" else delta)
            if mnemonic == "push":
                value = state.get(canon_reg(_reg(ins, operands[0]))) \
                    if getattr(operands[0], "type", None) == X86_OP_REG else None
                state.setdefault(STACK_KEY, {})[slot] = value
                self.may_stack[slot] = (_may_sets(state).get(
                    canon_reg(_reg(ins, operands[0]) or ""), ())
                    if getattr(operands[0], "type", None) == X86_OP_REG else ())
                state[STACK_POINTER_KEY] = delta - 8
                self.stack_writes += 1
            else:
                state[STACK_POINTER_KEY] = delta + 8
                if getattr(operands[0], "type", None) == X86_OP_REG:
                    name = _reg(ins, operands[0])
                    if name:
                        state[canon_reg(name)] = (state.get(STACK_KEY) or {}).get(slot)
                        _may_forget(state, [canon_reg(name)])
                        _may_add(state, canon_reg(name), (self.may_stack or {}).get(slot, ()))
                        self.stack_reads += 1
            self.stack = state.get(STACK_KEY) or {}
            return
        if mnemonic in ("add", "sub") and len(operands) >= 2 and \
                _reg(ins, operands[0]) and canon_reg(_reg(ins, operands[0]) or "") == "rsp" and \
                getattr(operands[1], "type", None) == X86_OP_IMM:
            delta = state.get(STACK_POINTER_KEY)
            if delta is not None:
                immediate = int(getattr(operands[1], "imm", 0))
                state[STACK_POINTER_KEY] = delta - immediate if mnemonic == "sub" else delta + immediate
            return
        destination = operands[0]
        if mnemonic == "mov" and len(operands) >= 2:
            self._exec_mov(ins, destination, operands[1], state)
            return
        if mnemonic == "lea" and len(operands) >= 2:
            self._exec_lea(ins, destination, operands[1], state)
            return
        if self._exec_term_arithmetic(ins, mnemonic, operands, state):
            return
        # any other write to a register makes it top
        if getattr(destination, "type", None) == X86_OP_REG:
            name = _reg(ins, destination)
            if name:
                state[canon_reg(name)] = None
                _may_forget(state, [canon_reg(name)])

    TERM_OPS = {"add": "add", "sub": "sub", "and": "and", "or": "or", "xor": "xor",
                "shl": "shl", "sal": "shl", "shr": "shr", "sar": "sar", "imul": "mul"}

    def _exec_term_arithmetic(self, ins, mnemonic, operands, state) -> bool:
        """Index provenance survives arithmetic. `i`, `i & 0xff` and `i << 4` are all expressions
        whose value is fixed by their inputs: two loads through the same expression are the same
        slot. Without this, the bucket-mask and array-of-struct addressing that dominate kernel
        table access carry no identity at all.
        """
        if not operands or getattr(operands[0], "type", None) != X86_OP_REG:
            return False
        name = _reg(ins, operands[0])
        if not name:
            return False
        name = canon_reg(name)
        if mnemonic in ("movsxd", "movsx", "movzx", "cdqe", "cwde", "movslq"):
            if mnemonic == "cdqe" or mnemonic == "cwde":
                state[name] = state.get("rax") if mnemonic == "cdqe" else state.get("rax")
                return True
            if len(operands) >= 2 and getattr(operands[1], "type", None) == X86_OP_REG:
                source_name = _reg(ins, operands[1])
                state[name] = state.get(canon_reg(source_name)) if source_name else None
                return True
            return False
        if mnemonic == "imul" and len(operands) >= 2:
            right = self._term_operand(ins, operands[-1], state)
            left = (self._term_operand(ins, operands[0], state) if len(operands) == 2
                    else self._term_operand(ins, operands[1], state))
            state[name] = _combine_term("mul", left, right)
            return True
        operation = self.TERM_OPS.get(mnemonic)
        if operation is None or len(operands) < 2:
            return False
        left = self._term_operand(ins, operands[0], state)
        right = self._term_operand(ins, operands[1], state)
        if left is None or right is None:
            state[name] = None
            return True
        state[name] = _combine_term(operation, left, right)
        return True

    def _term_operand(self, ins, operand, state) -> Optional[tuple]:
        if getattr(operand, "type", None) == X86_OP_REG:
            name = _reg(ins, operand)
            return _term_of(state.get(canon_reg(name))) if name else None
        if getattr(operand, "type", None) == X86_OP_IMM:
            return ("const", int(getattr(operand, "imm", 0)))
        return None

    def _exec_mov(self, ins, destination, source, state) -> None:
        if getattr(destination, "type", None) == X86_OP_REG:
            name = _reg(ins, destination)
            if not name:
                return
            name = canon_reg(name)
            value: Value = None
            incoming_may: Tuple[Value, ...] = ()
            if getattr(source, "type", None) == X86_OP_REG:
                source_name = _reg(ins, source)
                value = state.get(canon_reg(source_name)) if source_name else None
                incoming_may = _may_sets(state).get(canon_reg(source_name), ()) if source_name else ()
            elif getattr(source, "type", None) == X86_OP_IMM:
                value = v_const(int(getattr(source, "imm", 0)))
            elif getattr(source, "type", None) == X86_OP_MEM:
                slot = self._slot_of(ins, source.mem, state)
                if slot is not None:
                    spilled = (state.get(STACK_KEY) or {}).get(slot)
                    self.stack_reads += 1
                    state[name] = spilled
                    _may_forget(state, [name])
                    _may_add(state, name, (spilled, (self.may_stack or {}).get(slot)))
                    return
                if getattr(source.mem, "base", 0) == X86_REG_RIP or \
                        _reg_name_mem(ins, source.mem.base) == "rip":
                    # The pointer kept in a global is an object in its own right: kernel code
                    # releases exactly these (list heads, queues, cached sockets).
                    target = ins.address + ins.size + int(getattr(source.mem, "disp", 0))
                    state[name] = _field_value(("glob", target, ()), 0)
                    _may_forget(state, [name])
                    _may_add(state, name, (state[name],))
                    return
                key, offset = self._memory_base(ins, source, state)
                if key is not None:
                    self.reads.setdefault(key, []).append(
                        AccessFact(offset=offset, width=int(getattr(source, "size", 0) or 0),
                                   site=ins.address))
                    # A load produces a *candidate* object: its pointer nature is only established
                    # when something dereferences or releases it.
                    value = _field_value(key, offset)
                else:
                    value = None
            state[name] = value
            if getattr(source, "type", None) == X86_OP_REG:
                _may_forget(state, [name])
                _may_add(state, name, tuple(incoming_may) + (value,))
            else:
                _may_forget(state, [name])
                _may_add(state, name, (value,))
            return
        if getattr(destination, "type", None) == X86_OP_MEM:
            self._record_store(ins, destination, source, state)

    def _exec_lea(self, ins, destination, source, state) -> None:
        if getattr(destination, "type", None) != X86_OP_REG:
            return
        name = _reg(ins, destination)
        if not name:
            return
        name = canon_reg(name)
        state[name] = None
        _may_forget(state, [name])
        if getattr(source, "type", None) != X86_OP_MEM:
            return
        mem = source.mem
        if getattr(mem, "index", 0):
            return
        displacement = int(getattr(mem, "disp", 0))
        if getattr(mem, "base", 0) == X86_REG_RIP or _reg_name_mem(ins, mem.base) == "rip":
            # lea reg, [rip+X] is the address of a global object; that object is real even
            # though nothing in the argument list led to it.
            state[name] = v_global(ins.address + ins.size + displacement)
            _may_add(state, name, (state[name],))
            return
        base_name = _reg_name_mem(ins, mem.base)
        if not base_name:
            return
        base_value = state.get(canon_reg(base_name))
        key = object_key(base_value)
        if key is None:
            # Not an object address, but possibly still an index expression: `lea rax,[rax+rax*2]`
            # is how array-of-struct addressing scales an index.
            base_term = _term_of(base_value)
            index_name = _reg_name_mem(ins, mem.index) if getattr(mem, "index", 0) else None
            index_term = _term_of(state.get(canon_reg(index_name))) if index_name else None
            scale = int(getattr(mem, "scale", 1) or 1) if index_term else 1
            if base_term is not None:
                combined = base_term
                if index_term is not None and scale != 1:
                    combined = _combine_term("mul", index_term, ("const", scale))
                if index_term is not None and scale == 1:
                    combined = _combine_term("add", combined, index_term)
                elif index_term is not None:
                    combined = _combine_term("add", base_term, combined)
                if displacement:
                    combined = _combine_term("add", combined, ("const", displacement))
                if combined is not None:
                    state[name] = v_term(combined)
            return
        state[name] = v_interior(key, _interior_offset(base_value, displacement))
        _may_add(state, name, (state[name],))

    def _exec_compare(self, ins, operands, state) -> None:
        immediate = None
        field = None
        for operand in operands:
            if getattr(operand, "type", None) == X86_OP_IMM:
                immediate = int(getattr(operand, "imm", 0))
            elif getattr(operand, "type", None) == X86_OP_MEM:
                field = operand
        if field is None:
            return
        key, offset = self._memory_base(ins, field, state)
        if key is None:
            return
        width = int(getattr(field, "size", 0) or 0)
        self.reads.setdefault(key, []).append(
            AccessFact(offset=offset, width=width, site=ins.address))
        self.compares.setdefault(key, []).append(
            CompareFact(offset=offset, width=width, immediate=immediate, site=ins.address))

    def _exec_read_modify_write(self, ins, mnemonic, operands, state) -> bool:
        """Refcount arithmetic on an object field, and the loads it implies."""
        if not operands:
            return False
        destination = operands[0]
        if getattr(destination, "type", None) != X86_OP_MEM:
            return False
        key, offset = self._memory_base(ins, destination, state)
        if key is None:
            return False
        self.writes.setdefault(key, []).append(
            AccessFact(offset=offset, width=int(getattr(destination, "size", 0) or 0),
                       site=ins.address))
        return True

    def _record_store(self, ins, destination, source, state) -> None:
        mem = destination.mem
        slot = self._slot_of(ins, mem, state)
        if slot is not None:
            value = state.get(canon_reg(_reg(ins, source))) \
                if getattr(source, "type", None) == X86_OP_REG else None
            state.setdefault(STACK_KEY, {})[slot] = value
            self.stack_writes += 1
            self.stack = state[STACK_KEY]
            return
        base_name = _reg_name_mem(ins, mem.base)
        rip_relative = (getattr(mem, "base", 0) == X86_REG_RIP) or base_name == "rip"
        source_value = state.get(canon_reg(_reg(ins, source))) \
            if getattr(source, "type", None) == X86_OP_REG else None
        source_key = object_key(source_value)
        if rip_relative:
            if source_key is not None:
                self._note_escape(source_key, ESCAPE_GLOBAL, ins.address,
                                  f"{ins.mnemonic} {ins.op_str} stores the pointer in a global")
            return
        key, offset = self._memory_base(ins, destination, state)
        if key is not None:
            # any store through a table invalidates the identity of every slot read afterwards
            base_for_epoch = key[1][0] if key[0] == "tab" else key
            self.table_epoch[base_for_epoch] = self.table_epoch.get(base_for_epoch, 0) + 1
        if key is None:
            if source_key is not None and base_name and canon_reg(base_name) not in ARG_INDEX:
                self._note_escape(source_key, ESCAPE_UNKNOWN, ins.address,
                                  f"{ins.mnemonic} {ins.op_str} stores the pointer into an "
                                  f"object of unknown provenance")
            return
        self.writes.setdefault(key, []).append(
            AccessFact(offset=offset, width=int(getattr(destination, "size", 0) or 0),
                       site=ins.address))
        if source_key is not None and source_key != key:
            self._note_escape(source_key, ESCAPE_CALLEE_SLOT, ins.address,
                              f"{ins.mnemonic} {ins.op_str} stores the pointer into "
                              f"{object_label(key)}")

    def _clobber_caller_saved(self, state) -> None:
        """What a call does to the registers the ABI does not preserve.

        Keeping an argument register's value across a call is how a stale object gets released on
        paper: the callee is free to overwrite rdi, so afterwards the register holds *something*,
        and that something is not the object we were tracking.
        """
        clobbered = list(ARG_REGS) + ["rax", "r10", "r11"]
        for name in clobbered:
            state[name] = None
        _may_forget(state, clobbered)

    def _exec_call(self, ins, target: Optional[int], state) -> None:
        if target is None:
            self.indirect_calls += 1
            self.call_epoch += 1
            for name in ARG_REGS:
                key = object_key(state.get(name))
                if key is not None:
                    self._note_escape(key, ESCAPE_UNKNOWN, ins.address,
                                      f"indirect call at {hex(ins.address)}; the target and its "
                                      f"effect on {name} are unknown")
            self._clobber_caller_saved(state)
            self.callees.append(CalleeFact(site=ins.address, target=None, resolution="indirect"))
            return
        resolution = "direct"
        summary = None
        if self.resolve_summary is not None:
            summary = self.resolve_summary(target)
        if summary is None:
            resolution = "missing"
            self.call_epoch += 1
        self.callees.append(CalleeFact(site=ins.address, target=target, resolution=resolution))

        if self.is_release is not None and self.is_release(target):
            # A release consumes exactly one reference.  Which argument it consumes is a
            # property of the callee, so it is taken from the callee's own summary; a release
            # reached with no summary is assumed to consume the first argument, as every
            # catalogued anchor in this kernel does.  Attributing the call to *every* argument
            # register that still holds its incoming value is how one drop became six.
            consumed = 0
            if summary is not None:
                for index in range(len(ARG_REGS)):
                    effect = summary.param(index)
                    if effect.ownership in (OWN_DROP_REF, OWN_FREE):
                        consumed = index
                        break
            name = ARG_REGS[consumed]
            self._clobber_caller_saved(state)
            return

        for index, name in enumerate(ARG_REGS):
            key = object_key(state.get(name))
            if key is None:
                continue
            if summary is None:
                self._note_escape(key, ESCAPE_UNKNOWN, ins.address,
                                  f"{name} is passed to the unresolved callee at "
                                  f"{hex(target)}; its effect is unknown")
                continue
            effect = summary.object(key)
            # An escape travels: if the callee lets the object out of its own scope, the
            # caller's object has escaped too, whatever the callee does with references.
            if effect.escape and effect.escape != ESCAPE_NONE:
                self._note_escape(key, effect.escape, ins.address,
                                  f"{name} is passed to {hex(target)}, which lets it escape via "
                                  f"{effect.escape}")
            if effect.ownership in (OWN_DROP_REF, OWN_FREE, OWN_TRANSFER_OUT) \
                    and effect.ownership_strength in ("must", "may"):
                self.dispatched.append({"kind": "callee-" + effect.ownership.lower(),
                                        "site": ins.address, "object": key,
                                        "arg_register": name, "target": target,
                                        "strength": effect.ownership_strength,
                                        "summary_status": summary.status})
        returned = summary.returns if summary is not None else None
        if returned is None:
            state["rax"] = v_ret(ins.address)
        elif returned.kind == RET_ARG_ALIAS and returned.arg_index is not None:
            state["rax"] = state.get(ARG_REGS[returned.arg_index]) \
                if returned.arg_index < len(ARG_REGS) else None
        elif returned.kind == RET_NEW_OBJECT:
            state["rax"] = v_ret(ins.address)
        elif returned.kind == RET_FIELD_LOAD and returned.arg_index is not None:
            state["rax"] = ("obj", ("arg", returned.arg_index,
                                    (returned.field_offset or 0,)))
        elif returned.kind == RET_CONST:
            state["rax"] = v_const(returned.const or 0)
        else:
            # A callee result: an object of unknown provenance.  Recording it as such keeps the
            # return attributable ("something came back") without claiming an owned reference.
            state["rax"] = v_ret(ins.address)

    def _memory_base(self, ins, operand, state) -> Tuple[Optional[tuple], int]:
        """(object key, total offset) of a memory operand based on a tracked object."""
        mem = operand.mem
        base_name = _reg_name_mem(ins, mem.base)
        base_value = state.get(canon_reg(base_name)) if base_name else None
        base_key = object_key(base_value)
        if getattr(mem, "index", 0):
            # [base + index*scale + disp]: the slot, not the table, is the object.
            index_name = _reg_name_mem(ins, mem.index)
            index_value = state.get(canon_reg(index_name)) if index_name else None
            provenance = index_provenance(index_value)
            if base_key is None or base_name in ("rbp", "rsp") or base_name == "rip":
                self._unresolved("indexed_load_untracked_base")
                return None, 0
            if provenance is None:
                self._unresolved("index_without_provenance")
                return None, 0
            epoch = self._epoch_for(base_key)
            # The displacement is part of the identity: at a fixed scale, `[tab + idx*8 + 8]` is
            # the *next* slot, not a field of this one.
            slot = object_key(v_slot(base_key, provenance, int(getattr(mem, "scale", 1) or 1),
                                     int(getattr(mem, "disp", 0)), epoch))
            return slot, 0
        if base_key is None:
            if base_name and base_name not in ("rbp", "rsp", "rip"):
                self._unresolved("load_untracked_base")
            return None, 0
        return base_key, _interior_offset(base_value, int(getattr(mem, "disp", 0)))


#: A register may hold one of a few objects when control flow joins. The definite slot (`state[name]`)
#: drops to ``None`` the moment two predecessors disagree, which is right for a must-value and wrong
#: for object identity: on the path that reaches the release the object *is* the one we tracked.
#: The may-channel keeps those values, and every attribution made through it is ``may``-strength.
MAY_KEY = "__may__"
MAY_CAP = 3


def _clone_state(state: Dict[str, Value]) -> Dict[str, Value]:
    """Copy a state deeply enough that two paths sharing a parent do not share may-sets.

    A shallow `dict(state)` shares the nested may dict, so writing one path's value also rewrote
    its sibling's — which silently collapsed two candidate objects into one and turned a
    "may be either" into a definite identity.
    """
    clone = dict(state)
    if MAY_KEY in clone:
        clone[MAY_KEY] = {name: tuple(values)
                          for name, values in (clone[MAY_KEY] or {}).items()}
    return clone


def _may_sets(state) -> Dict[str, Tuple[Value, ...]]:
    return state.setdefault(MAY_KEY, {})


def _may_add(state, name: str, values) -> None:
    if not name:
        return
    may = _may_sets(state)
    current = list(may.get(name, ()))
    for value in values or ():
        if value is None or value in current:
            continue
        current.append(value)
    may[name] = tuple(current[:MAY_CAP]) if len(current) <= MAY_CAP else ()


def _may_forget(state, names) -> None:
    may = _may_sets(state)
    for name in names:
        may.pop(name, None)


def _may_object(state, name: str) -> Optional[tuple]:
    """The single object this register may hold, or ``None`` when it may hold several."""
    values = _may_sets(state).get(name) or ()
    keys = {object_key(value) for value in values}
    keys.discard(None)
    return keys.pop() if len(keys) == 1 else None


def _merge(left: Dict[str, Value], right: Dict[str, Value]) -> Dict[str, Value]:
    merged: Dict[str, Value] = {}
    for key in set(left) | set(right):
        if key == MAY_KEY:
            a, b = left.get(key) or {}, right.get(key) or {}
            union: Dict[str, Tuple[Value, ...]] = {}
            for name in set(a) | set(b):
                values: list = []
                for value in list(a.get(name, ())) + list(b.get(name, ())):
                    if value not in values:
                        values.append(value)
                union[name] = tuple(values[:MAY_CAP]) if len(values) <= MAY_CAP else ()
            merged[key] = union
            continue
        a, b = left.get(key), right.get(key)
        if key == STACK_KEY:
            slots = set(a or {}) | set(b or {})
            merged[key] = {slot: (a or {}).get(slot) for slot in slots
                           if (a or {}).get(slot) == (b or {}).get(slot)}
            continue
        merged[key] = a if a == b else None
    return merged


def _reg(ins, operand) -> Optional[str]:
    try:
        return ins.reg_name(operand.reg) or None
    except Exception:
        return None


def _reg_name_mem(ins, reg_id: int) -> Optional[str]:
    if not reg_id:
        return None
    try:
        return ins.reg_name(reg_id) or None
    except Exception:
        return None


# --------------------------------------------------------------------- summary


def summarize_function(view, is_release, resolve_summary=None,
                       extent_source: str = "record") -> FunctionSummary:
    """Summarise one function body. ``resolve_summary`` supplies callee summaries."""
    body = _Body(view, is_release, resolve_summary=resolve_summary)
    body.run()

    status = COMPLETE
    refusal = None
    if body.blocked_reason:
        status = REFUSED
        refusal = {"code": "analysis_stopped", "detail": body.blocked_reason}
    elif body.truncated:
        status = PARTIAL
        refusal = {"code": "truncated", "detail": ", ".join(sorted(body.truncation_causes))}
    elif body.indirect_calls:
        status = PARTIAL
        refusal = {"code": "indirect_only",
                   "detail": f"{body.indirect_calls} indirect call(s); their effects are unknown"}
    elif not body.returns:
        status = PARTIAL
        refusal = {"code": "no_return_seen", "detail": "no ret instruction reached"}

    dominators = _dominators(view)
    exit_blocks = {view._addr2blk.get(site) for site, _value in body.returns}
    exit_blocks.discard(None)

    def dominated_by(site: int) -> bool:
        """Does every path from the entry execute this instruction?

        Block dominance alone is not enough: a conditional branch can jump *past* the
        instruction into the middle of the same block, so the block is reached either way while
        the instruction itself is skipped. The skip check below is the part that makes the
        difference between "must" and "may" truthful.
        """
        block = view._addr2blk.get(site)
        if block is None or not exit_blocks:
            return False
        if not all(block in dominators.get(exit, set()) for exit in exit_blocks):
            return False
        return _skipped_by_branch(view, site) is None

    # ------------------------------------------------------------- refcount
    drop_facts: Dict[int, List[dict]] = {}
    take_facts: Dict[int, int] = {}
    try:
        from . import handles as handles_mod
        shape = handles_mod.release_shape(view, is_release) if is_release else None
    except Exception:
        shape = None
        status = PARTIAL if status == COMPLETE else status
        refusal = refusal or {"code": "refcount_unavailable",
                              "detail": "the release shape could not be computed"}
    if shape is not None:
        env_at = _register_values_by_site(view, body)
        for drop in getattr(shape, "drops", []):
            state_at_drop = env_at.get(drop.site) or {}
            key = _object_key_of_register(state_at_drop, drop.obj_reg)
            may_strength = "must"
            if key is None:
                key = _may_object(state_at_drop, canon_reg(drop.obj_reg or ""))
                may_strength = "may"
            if key is None:
                continue
            drop_facts.setdefault(key, []).append({
                "site": drop.site, "offset": drop.offset, "release_site": drop.release_site,
                "release_target": drop.release_target, "guard": drop.guard_state,
                "guard_reason": drop.guard_reason,
                "must": bool(dominated_by(drop.site) and may_strength == "must")})
        for take in getattr(shape, "takes", []):
            key = _object_key_of_register(env_at.get(take.site), take.obj_reg)
            if key is not None:
                take_facts[key] = take_facts.get(key, 0) + 1

    # Release sites are attributed from the *merged* per-site state: the may-sets of every
    # traversal are unioned, so a site only receives an object when all traversals agree on one.
    for site, target in view.calls.items():
        if is_release is None or not is_release(target):
            continue
        if any(record["site"] == site for record in body.dispatched):
            continue
        state_at_site = env_at.get(site) or {}
        consumed = "rdi"
        callee_summary = body.resolve_summary(target) if body.resolve_summary else None
        if callee_summary is not None:
            for index in range(len(ARG_REGS)):
                effect = callee_summary.param(index)
                if effect.ownership in (OWN_DROP_REF, OWN_FREE):
                    consumed = ARG_REGS[index]
                    break
        key = object_key(state_at_site.get(consumed))
        strength = "must"
        if key is None:
            key = _may_object(state_at_site, consumed)
            strength = "may"
        if key is not None:
            body.dispatched.append({"kind": "release-call", "site": site, "object": key,
                                    "arg_register": consumed, "target": target,
                                    "strength": strength})

    for record in body.dispatched:
        key = record["object"]
        strength = record.get("strength", "must")
        # The release shape already counts the drop that precedes this very call; counting the
        # call again doubles every wrapper's drop count.
        if any(fact["release_site"] == record["site"] for fact in drop_facts.get(key, [])):
            continue
        dominated = dominated_by(record["site"])
        drop_facts.setdefault(key, []).append({
            "site": record["site"], "offset": None, "release_site": record["site"],
            "release_target": record["target"], "guard": UNKNOWN,
            "guard_reason": f"the callee ({record['kind']}) consumes the reference",
            "must": bool(dominated and strength == "must"),
            "via": record["kind"]})

    # ------------------------------------------------------------------ objects
    complete = status == COMPLETE
    params: List[ParamEffect] = []
    field_objects: List[ParamEffect] = []
    arg_keys = [("arg", index, ()) for index in range(len(ARG_REGS))]
    seen_keys = set(arg_keys) | set(body.reads) | set(body.writes) | set(body.compares) \
        | set(drop_facts) | set(body.escapes) | set(take_facts)
    for key in sorted(seen_keys,
                      key=lambda item: (item[0] != "arg", item[0], str(item[1]), str(item[2]))):
        is_argument = key[0] == "arg"
        index = key[1] if is_argument else -1
        reads = tuple(sorted(set(body.reads.get(key, [])), key=lambda f: (f.site, f.offset)))
        writes = tuple(sorted(set(body.writes.get(key, [])), key=lambda f: (f.site, f.offset)))
        compares = tuple(sorted(set(body.compares.get(key, [])), key=lambda f: f.site))
        drops = drop_facts.get(key, [])
        must = [d for d in drops if d["must"]]
        may = [d for d in drops if not d["must"]]
        takes = take_facts.get(key, 0)
        escape = body.escapes.get(key)
        returned_alias = any(_returned_alias(body, key, value) for _site, value in body.returns)

        if must:
            postcondition, reason = RELEASED, (f"the decrement at {hex(must[0]['site'])} dominates "
                                               f"every exit")
        elif may:
            postcondition, reason = MAY_RELEASED, (f"the decrement at {hex(may[0]['site'])} runs on "
                                                   f"one path only")
        elif not complete:
            # A negative claim ("still live") needs a complete body.  An indirect call or a
            # truncated walk is not evidence that nothing happened.
            postcondition, reason = UNKNOWN, (f"the body is {status}"
                                              + (f" ({refusal['code']})" if refusal else "")
                                              + ": a negative claim is not available")
        elif escape and escape[0] in (ESCAPE_GLOBAL, ESCAPE_UNKNOWN, ESCAPE_CALLEE_SLOT):
            postcondition, reason = LIVE, (f"escaped via {escape[0]} at {hex(escape[1])}; the "
                                           f"callee keeps a reference")
        else:
            postcondition, reason = LIVE, "no reference-consuming call on any path"

        ownership, strength, ownership_site = OWN_NONE, UNKNOWN, 0
        if must:
            ownership_site = must[0]["site"]
            freed = is_release is not None and is_release(must[0]["release_target"])
            ownership = OWN_FREE if freed else OWN_DROP_REF
            strength = "must"
        elif may:
            ownership_site = may[0]["site"]
            ownership, strength = OWN_DROP_REF, "may"
        elif drop_facts.get(key):
            # A take alone is not a consumption; only a decrement or a release call is.
            ownership, strength = OWN_DROP_REF, "may"
            ownership_site = drop_facts[key][0]["release_site"]

        guard = UNKNOWN
        guard_reason = "no refcount update was found"
        release_conditional = False
        if drops:
            guard = must[0]["guard"] if must else drops[0]["guard"]
            guard_reason = must[0]["guard_reason"] if must else drops[0]["guard_reason"]
            release_conditional = any(not d["must"] for d in drops)

        role = "NONE"
        if compares:
            role = "COMPARE"
        if reads:
            role = "READ" if role in ("NONE", "COMPARE") else role
        if writes:
            role = "DEREF"
        if escape and escape[0] == ESCAPE_CALLEE_SLOT:
            role = "OUT_REF"
        if returned_alias and role == "NONE":
            role = "HANDOFF"

        effect = ParamEffect(
            index=(index if is_argument and isinstance(index, int) and 0 <= index < 6 else -1),
            register=(ARG_REGS[index] if is_argument and isinstance(index, int) and 0 <= index < 6
                      else ""),
            role=role, reads=reads, writes=writes,
            compares=compares, drops_must=len(must), drops_may=len(may), takes=takes,
            refcount_field=(must[0]["offset"] if must else (may[0]["offset"] if may else None)),
            guard=guard, guard_reason=guard_reason,
            release_conditional=release_conditional,
            release_sites=tuple(d["release_site"] for d in drops),
            ownership=ownership, ownership_strength=strength, ownership_site=ownership_site,
            escape=(escape[0] if escape else ESCAPE_NONE),
            escape_site=(escape[1] if escape else 0),
            escape_detail=(escape[2] if escape else ""),
            postcondition=postcondition, postcondition_reason=reason,
            key=key, label=object_label(key))
        if is_argument:
            params.append(effect)
        elif effect.ownership != OWN_NONE or effect.takes or effect.writes or effect.reads:
            field_objects.append(effect)

    return FunctionSummary(
        rva=view.rva, size=view.size, extent_source=extent_source, status=status,
        refusal=refusal, params=tuple(params), field_objects=tuple(field_objects),
        returns=_return_effect(view, body, is_release),
        callees=tuple(body.callees), indirect_calls=body.indirect_calls,
        analysis={"blocks": len(view.blocks), "iterations": body.iterations,
                  "steps": body.steps, "truncated": body.truncated,
                  "truncation_causes": body.truncation_causes,
                  "params_with_effects": sum(1 for p in params
                                       if p.role != "NONE" or p.ownership != OWN_NONE),
                  "field_objects": len(field_objects),
                  "unresolved_accesses": body.unresolved_accesses,
                  "unresolved_reasons": body.unresolved_reasons,
                  "indexed_slots": sum(1 for effect in field_objects
                                       if effect.key and effect.key[0] == "tab")})


def _returned_alias(body, key: tuple, value: Value) -> bool:
    return bool(value) and object_key(value) == tuple(key)


def _object_key_of_register(env: Optional[Dict[str, Value]], register: str) -> Optional[tuple]:
    if not env or not register:
        return None
    return object_key(env.get(canon_reg(register)))


def _register_values_by_site(view, body) -> Dict[int, Dict[str, Value]]:
    """Re-run the body quickly to record the register map at each instruction.

    The refcount facts come from ``handles``, which works on registers; mapping them back to an
    argument needs the values that were live at that instruction. A second pass is cheaper to
    review than threading a callback through every instruction handler.
    """
    snapshot: Dict[int, Dict[str, Value]] = {}
    replay = _Body(view, body.is_release, resolve_summary=body.resolve_summary)
    original_exec = replay._exec

    def wrapped(ins, state):
        # A site is visited once per traversal. Keeping the *last* traversal would let an early,
        # partial one decide the identity, so the snapshots are merged: the may-sets union and a
        # definite value survives only while every traversal agrees on it.
        previous = snapshot.get(ins.address)
        snapshot[ins.address] = (_clone_state(state) if previous is None
                                 else _merge(previous, state))
        original_exec(ins, state)

    replay._exec = wrapped          # type: ignore[assignment]
    replay.run()
    return snapshot


def _return_effect(view, body, is_release) -> ReturnEffect:
    if not body.returns:
        return ReturnEffect(kind=RET_UNKNOWN, why="no return instruction was reached")
    kinds = []
    for site, value in body.returns:
        if not value:
            kinds.append((RET_UNKNOWN, site, None, None))
        elif value[0] in ("obj", "ptr"):
            key = object_key(value)
            if key and key[0] == "arg" and not key[2]:
                kinds.append((RET_ARG_ALIAS, site, key[1], None))
            elif key and key[2]:
                kinds.append((RET_FIELD_LOAD, site, key[1] if key[0] == "arg" else None,
                              key[2][0]))
            else:
                kinds.append((RET_UNKNOWN, site, None, None))
        elif value[0] == "const":
            kinds.append((RET_CONST, site, None, value[1]))
        elif value[0] == "ret":
            kinds.append((RET_NEW_OBJECT, site, None, None))
        else:
            kinds.append((RET_UNKNOWN, site, None, None))
    distinct = {kind for kind, _s, _a, _o in kinds}
    if len(distinct) > 1:
        return ReturnEffect(kind=RET_UNKNOWN, why="the exits disagree about the return value")
    kind, site, arg_index, extra = kinds[0]
    if kind == RET_ARG_ALIAS:
        return ReturnEffect(kind=kind, arg_index=arg_index, owned=False, site=site,
                            why=f"returns argument {arg_index} itself; no new reference")
    if kind == RET_FIELD_LOAD:
        return ReturnEffect(kind=kind, arg_index=arg_index, field_offset=extra, owned=None,
                            site=site,
                            why="returns a value loaded out of the object; that is a different "
                                "object, not an alias")
    if kind == RET_CONST:
        return ReturnEffect(kind=kind, const=extra, owned=False, site=site,
                            why="returns a constant")
    if kind == RET_NEW_OBJECT:
        return ReturnEffect(kind=kind, owned=None, site=site,
                            why="the returned value comes from a callee; whether it carries an "
                                "owned reference is not established here")
    return ReturnEffect(kind=RET_UNKNOWN, site=site,
                        why="the return value is not attributable to an argument, a field, a "
                            "constant or a callee result")


# ------------------------------------------------------------------------ store


class SummaryStore:
    """Per-image summary cache. ``get`` never returns None: a refusal is a record, not a gap."""

    def __init__(self, image, index, is_release, depth_cap: int = DEFAULT_DEPTH_CAP,
                 function_cap: int = DEFAULT_FUNCTION_CAP, view_factory=None):
        self.image = image
        self.index = index
        self.is_release = is_release
        self.depth_cap = depth_cap
        self.function_cap = function_cap
        self._view_factory = view_factory or self._default_view
        self._cache: Dict[Tuple[int, int], FunctionSummary] = {}
        self.stats_counters = {"built": 0, "refused": 0, "partial": 0, "cache_hits": 0,
                               "recursive": 0, "capped": 0, "decode_failed": 0}
        self._active: set = set()

    # -- views --------------------------------------------------------------
    def _default_view(self, rva: int):
        from .patterns import FunctionView
        record = self.index.get(rva) or self.index.containing(rva)
        if record is None:
            return None, "missing"
        size = max(int(getattr(record, "size", 0) or 0), 1)
        start = record.rva
        try:
            return FunctionView(self.image, start, size), "record"
        except Exception:
            return None, "decode_failed"

    def get(self, rva: int, depth: int = 0) -> FunctionSummary:
        key = (int(rva), min(depth, self.depth_cap))
        cached = self._cache.get(key)
        if cached is not None:
            self.stats_counters["cache_hits"] += 1
            return cached
        if len(self._cache) >= self.function_cap:
            self.stats_counters["capped"] += 1
            return FunctionSummary(rva=int(rva), size=0, status=REFUSED,
                                   refusal={"code": "capped",
                                            "detail": f"{self.function_cap} summaries built"})
        if rva in self._active or depth > self.depth_cap:
            self.stats_counters["recursive"] += 1
            return FunctionSummary(rva=int(rva), size=0, status=REFUSED,
                                   refusal={"code": "recursive",
                                            "detail": "the call graph revisits this function "
                                                      "within the depth cap"})
        view, extent_source = self._view_factory(int(rva))
        if view is None:
            self.stats_counters["decode_failed"] += 1
            summary = FunctionSummary(rva=int(rva), size=0, status=REFUSED,
                                      refusal={"code": "no_extent" if extent_source == "missing"
                                               else "decode_failed",
                                               "detail": f"no decodable body ({extent_source})"})
            self._cache[key] = summary
            return summary
        self._active.add(rva)
        try:
            summary = summarize_function(
                view, self.is_release,
                resolve_summary=(lambda target: self.get(target, depth + 1)),
                extent_source=extent_source)
        finally:
            self._active.discard(rva)
        self.stats_counters["built"] += 1
        if summary.status == REFUSED:
            self.stats_counters["refused"] += 1
        elif summary.status == PARTIAL:
            self.stats_counters["partial"] += 1
        self._cache[key] = summary
        return summary

    def digest(self) -> str:
        import hashlib
        import json
        payload = json.dumps({f"{rva}:{depth}": summary.as_dict()
                              for (rva, depth), summary in sorted(self._cache.items())},
                             sort_keys=True, default=str)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def stats(self) -> dict:
        out = dict(self.stats_counters)
        out["cached"] = len(self._cache)
        out["depth_cap"] = self.depth_cap
        out["function_cap"] = self.function_cap
        return out


# ------------------------------------------------------------- defective life cycles


def reachable_from(view, start_site: int, goal_site: int) -> bool:
    """Is ``goal_site`` reachable from ``start_site`` inside this body?"""
    start_block = view._addr2blk.get(start_site)
    goal_block = view._addr2blk.get(goal_site)
    if start_block is None or goal_block is None:
        return False
    if start_block == goal_block:
        return goal_site >= start_site
    seen, work = {start_block}, [start_block]
    while work:
        block = work.pop()
        for successor in view.succ.get(block, ()):
            if successor not in seen:
                if successor == goal_block:
                    return True
                seen.add(successor)
                work.append(successor)
    return False


def sequential_double_releases(view, summary: FunctionSummary) -> List[dict]:
    """Release sites on one argument where a later one is reachable without an intervening take.

    This is the shape of a double release and nothing more: it says two reference-consuming
    operations can follow each other on the same object. Whether the first one really freed it is
    a separate claim that needs the release anchor's semantics (and, for the netcontrol family,
    the fd-reuse argument on top).
    """
    defects: List[dict] = []
    for effect in summary.all_objects():
        sites = sorted(set(effect.release_sites))
        if len(sites) < 2:
            continue
        for first, second in zip(sites, sites[1:]):
            if not reachable_from(view, first, second):
                continue
            defects.append({
                "param": effect.index, "register": effect.register,
                "first": hex(first), "second": hex(second),
                "takes": effect.takes, "guard": effect.guard,
                "ownership": effect.ownership, "strength": effect.ownership_strength,
                "summary_status": summary.status,
                "why": (f"two reference-consuming sites on object "
                        f"{effect.label or effect.register} where the second is reachable from "
                        f"the first without a take on any path")})
    return defects


# --------------------------------------------------------------------- hopping


def _nearest_write_to(view, call_site: int, register: str) -> Optional[Tuple[int, str]]:
    """The closest instruction before the call that writes ``register``."""
    position = next((i for i, ins in enumerate(view.ins) if ins.address == call_site), None)
    if position is None:
        return None
    target = canon_reg(register)
    for back in range(position - 1, max(-1, position - 120), -1):
        ins = view.ins[back]
        operands = list(getattr(ins, "operands", []) or [])
        if not operands or getattr(operands[0], "type", None) != X86_OP_REG:
            continue
        name = _reg(ins, operands[0])
        if name and canon_reg(name) == target:
            return ins.address, f"{ins.mnemonic} {ins.op_str}"
    return None


def caller_argument_objects(view, call_site: int) -> Dict[str, dict]:
    """Which object each argument register holds at a call site, from the forward values.

    A backwards window over argument registers misses the normal case: the object is loaded from
    a frame slot or a global, so the register chain never starts at another argument. The forward
    interpretation already tracks those, so the placement question is answered with it — and the
    witness is the instruction that last wrote the register.
    """
    body = _Body(view, lambda target: False)
    body.run()
    env_at = _register_values_by_site(view, body)
    state = env_at.get(call_site) or {}
    out: Dict[str, dict] = {}
    for name in ARG_REGS:
        key = object_key(state.get(name))
        if key is None:
            continue
        write = _nearest_write_to(view, call_site, name)
        out[name] = {"key": key, "object": object_label(key),
                     "write_site": write[0] if write else None,
                     "write_text": write[1] if write else "",
                     "via": ("argument" if key[0] == "arg" else "global")}
    return out


def _placement_for(view, call_site: int, object_register: str) -> dict:
    """Bounded, *exact-pointer* argument placement witness.

    A typed, full-width `mov rdi, rax` preserves a pointer identity.
    `mov rdi, [rax+offset]` loads another value, `lea rdi, [rax+offset]`
    creates a different (interior) pointer, and `mov edi, eax` truncates
    or zero-extends the value.  None proves the original 64-bit pointer
    reaches the callee.  A local backward scan is not CFG-complete; an
    unresolved branch in the window must refuse a PROVEN witness.
    """
    insns = view.ins
    position = next((i for i, ins in enumerate(insns) if ins.address == call_site), None)
    if position is None:
        return {"status": UNKNOWN, "argument": None,
                "why": "the call site is not in this body"}
    target = canon_reg(object_register)
    if target != object_register:
        return {"status": UNKNOWN, "argument": None,
                "why": "a partial-width source is not a full pointer identity"}
    alias = {target}
    # The backward-window algorithm cannot prove that a branch in the
    # inspected region always passes through the same argument definition.
    # Be conservative until CFG-based must-reaching-definitions is used.
    window_start = max(0, position - 24)
    if any((ins.mnemonic.split()[-1].lower() in ("jmp", "ret")
            or ins.mnemonic.split()[-1].lower().startswith(("j", "loop")))
           for ins in insns[window_start:position]):
        return {"status": UNKNOWN, "argument": None,
                "why": "control flow in the argument-placement window is unresolved"}

    for back in range(position - 1, window_start - 1, -1):
        ins = insns[back]
        operands = list(getattr(ins, "operands", []) or [])
        mnemonic = ins.mnemonic.split()[-1].lower()
        if mnemonic == "call":
            break  # calls may clobber argument and other caller-saved registers
        if not operands:
            continue
        destination = operands[0]
        if getattr(destination, "type", None) != X86_OP_REG:
            continue
        written = _reg(ins, destination)
        if not written:
            continue
        name = canon_reg(written)
        if name in alias:
            alias.discard(name)
            continue
        if name in ARG_INDEX and len(operands) >= 2:
            if written != name:
                return {"status": UNKNOWN, "argument": name,
                        "site": ins.address, "text": f"{ins.mnemonic} {ins.op_str}",
                        "why": "a partial-width argument write does not preserve a 64-bit pointer"}
            source = operands[1]
            if getattr(source, "type", None) == X86_OP_REG:
                raw_source = _reg(ins, source) or ""
                if (mnemonic in ("mov", "movabs") and raw_source == target
                        and raw_source in alias):
                    return {"status": PROVEN, "argument": name, "site": ins.address,
                            "text": f"{ins.mnemonic} {ins.op_str}",
                            "why": f"{name} receives the full-width object pointer from {target}"}
            elif getattr(source, "type", None) == X86_OP_MEM:
                base = _reg_name_mem(ins, source.mem.base)
                if base and canon_reg(base) in alias:
                    if (mnemonic == "lea" and not getattr(source.mem, "index", 0)
                            and getattr(source.mem, "disp", 0) == 0):
                        return {"status": PROVEN, "argument": name, "site": ins.address,
                                "text": f"{ins.mnemonic} {ins.op_str}",
                                "why": f"{name} is the identity address of {target}"}
                    return {"status": UNKNOWN, "argument": name, "site": ins.address,
                            "text": f"{ins.mnemonic} {ins.op_str}",
                            "why": ("a field load or interior/indexed address cannot establish "
                                    "the exact identity of the acquired object")}
            return {"status": REFUTED, "argument": name, "site": ins.address,
                    "text": f"{ins.mnemonic} {ins.op_str}",
                    "why": f"{name} is written by {ins.mnemonic} {ins.op_str}, which does not "
                           f"carry the object"}
        if mnemonic in ("add", "sub") and len(operands) >= 2 and \
                getattr(operands[1], "type", None) == X86_OP_IMM:
            continue
        alias.discard(name)
    return {"status": UNKNOWN, "argument": None,
            "why": "no full-width argument register is proved to carry this object"}


def hop_at(view, call_site: int, object_register: str, callee_summary: Optional[FunctionSummary],
           callee_rva: Optional[int] = None, summary_digest: str = "",
           placement: Optional[dict] = None) -> HopEffect:
    """Judge one call edge: does it pass the object, and does the callee consume it?

    ``placement`` overrides the backward register scan with a placement derived from the forward
    values (see ``caller_argument_objects``), which is what finds the object when it arrives from
    a frame slot or a global instead of from another argument.
    """
    if placement is None:
        placement = _placement_for(view, call_site, object_register)
    witnesses: List[dict] = []
    if placement["status"] == PROVEN:
        witnesses.append({"caller": {"site": (hex(placement["site"])
                                              if placement.get("site") is not None else None),
                                     "kind": placement.get("kind", "argument-placement"),
                                     "object": placement.get("object", ""),
                                     "text": placement.get("text", "")}})
    if callee_summary is None:
        return HopEffect(call_site=call_site, callee=callee_rva, argument=placement.get("argument"),
                         placement=placement["status"], effect="unresolved", status=UNKNOWN,
                         witnesses=tuple(witnesses),
                         why=(placement["why"] if placement["status"] != PROVEN else
                              "the callee has no summary, so nothing is known about what it does "
                              "with the argument"),
                         summary_digest=summary_digest)
    if placement["status"] == REFUTED:
        return HopEffect(call_site=call_site, callee=callee_rva, argument=placement.get("argument"),
                         placement=REFUTED, effect="none", status=REFUTED,
                         witnesses=tuple(witnesses), why=placement["why"],
                         summary_digest=summary_digest, summary_status=callee_summary.status)
    argument_index = ARG_INDEX.get(placement.get("argument") or "")
    if argument_index is None:
        return HopEffect(call_site=call_site, callee=callee_rva, argument=None,
                         placement=placement["status"], effect="unknown", status=UNKNOWN,
                         witnesses=tuple(witnesses), why=placement["why"],
                         summary_digest=summary_digest, summary_status=callee_summary.status)
    # The object that travels is the one placed in that register *and everything the callee does
    # with what that object holds*. On this kernel a reference is normally consumed on the pointer
    # stored inside the container, so looking only at the argument itself finds nothing.
    effects = [candidate for candidate in callee_summary.all_objects()
               if candidate.key and candidate.key[0] == "arg"
               and candidate.key[1] == argument_index
               and candidate.ownership != OWN_NONE]
    effects.sort(key=lambda candidate: (candidate.ownership_strength != "must",
                                        len(candidate.key[2])))
    effect = effects[0] if effects else callee_summary.param(argument_index)
    composed_label = effect.label
    caller_key = placement.get("key")
    if caller_key and effect.key and effect.key[0] == "arg" and effect.key[1] == argument_index:
        # The object that travels is the caller's object at the path the callee reaches into.
        composed_label = object_label((caller_key[0], caller_key[1],
                                       tuple(caller_key[2]) + tuple(effect.key[2])))
    if effect.ownership != OWN_NONE:
        site = (effect.release_sites[0] if effect.release_sites else effect.ownership_site) or 0
        witnesses.append({"callee": {"site": hex(site) if site else None,
                                     "kind": effect.ownership.lower(),
                                     "object": effect.label,
                                     "text": f"the callee {effect.ownership}s "
                                             f"{effect.label} ({effect.ownership_strength}) at "
                                             f"{hex(site) if site else 'an unknown site'}"}})
    complete = callee_summary.status == COMPLETE
    witnessed = bool(effect.release_sites or effect.ownership_site)
    if effect.ownership in (OWN_FREE, OWN_DROP_REF, OWN_TRANSFER_OUT) and \
            effect.ownership_strength == "must" and complete:
        status = PROVEN if placement["status"] == PROVEN else UNKNOWN
        why = "" if status == PROVEN else "the placement is not proved"
    elif effect.ownership in (OWN_FREE, OWN_DROP_REF, OWN_TRANSFER_OUT) and witnessed and \
            placement["status"] == PROVEN:
        # The reference is consumed, on a path, at a concrete instruction. Calling that UNKNOWN
        # would hide a witnessed transfer; calling it PROVEN would claim every path. On this
        # kernel *every* consuming callee is path-gated, so this is the honest middle rung and it
        # is the one the S1.6 minimal goal is stated in.
        status = CONDITIONAL
        why = (f"the callee consumes the reference at {hex(effect.release_sites[0] if effect.release_sites else effect.ownership_site)} "
               f"({effect.ownership}, {effect.ownership_strength}"
               + (f", guard {effect.guard}" if effect.guard else "")
               + f"), so the transfer holds on that path only"
               + ("" if complete else f"; the callee body is {callee_summary.status}"))
    elif effect.ownership == OWN_NONE and complete and placement["status"] == PROVEN:
        status = REFUTED
        why = (f"the callee is complete and does nothing with argument {argument_index}: this "
               f"edge is not a transfer")
    else:
        status = UNKNOWN
        why = (f"the callee is {callee_summary.status}"
               + (f" ({callee_summary.refusal.get('code')})" if callee_summary.refusal else "")
               + f" and its effect on argument {argument_index} is {effect.ownership}/"
                 f"{effect.ownership_strength}")
    return HopEffect(call_site=call_site, callee=callee_rva, argument=placement.get("argument"),
                     placement=placement["status"], effect=effect.ownership, status=status,
                     ownership=effect.ownership, witnesses=tuple(witnesses), why=why,
                     summary_digest=summary_digest, summary_status=callee_summary.status,
                     object_label_=composed_label)
