"""Handle/object identity and reference-accounting summaries for the discovery engine.

Motivation (S1.2c): the S1.2b engine models abstract object identity inside one
function, but it has no notion of a *handle* -- a small number that denotes an object
through a table (file descriptor, kqueue id, slot index).  A whole class of real
kernel defects needs exactly that distinction: a record stores both the handle and the
object it resolved to, and a later lookup decides *ownership* by comparing the stored
handle against a handle supplied by the caller.  Handle numbers are reused, so such a
lookup can select an object that never held the reference that is then dropped.

Nothing here is domain specific: no syscall numbers, no marker names, no offsets. The
only signals used are operand widths and data flow:

* a **handle field** is a 4-byte field compared against a register that was loaded
  through a pointer argument (a caller-supplied number),
* an **object field** is an 8-byte field compared against a register (a pointer),
* an **acquire** is a call that writes an out-parameter slot on the stack, after which
  the slot is loaded into a register whose refcount field is decremented towards a
  release call (a **drop**).

The catalog is lazy: summaries are decoded per function on first use and memoised, so a
scan pays for them only where a candidate appears.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_RBP,
    X86_REG_RSP,
)

STACK_BASES = {X86_REG_RBP, X86_REG_RSP}
COMPARE_MNEMONICS = {"cmp", "test"}
COUNT_WIDTHS = {4: "handle", 8: "object"}


@dataclass(frozen=True)
class FieldCompare:
    """One comparison between a record field and a caller-supplied value."""

    site: int          # instruction address (rva)
    offset: int        # field offset from the record base register
    width: int         # 4 = handle/number domain, 8 = address/object domain
    other_reg: str     # register on the other side
    from_pointer: bool  # True if that register was loaded through a memory operand
    text: str

    @property
    def domain(self) -> str:
        return COUNT_WIDTHS.get(self.width, f"{self.width}-byte")


@dataclass
class FunctionSummary:
    """Identity-domain fingerprint of one function."""

    rva: int
    size: int
    compares: List[FieldCompare] = field(default_factory=list)
    stores: Dict[int, set] = field(default_factory=dict)  # offset -> {widths}
    decode_ok: bool = True

    @property
    def handle_compares(self) -> List[FieldCompare]:
        return [c for c in self.compares if c.width == 4]

    @property
    def object_compares(self) -> List[FieldCompare]:
        return [c for c in self.compares if c.width == 8]

    def domain(self) -> str:
        has_h, has_o = bool(self.handle_compares), bool(self.object_compares)
        if has_h and has_o:
            return "mixed"
        if has_h:
            return "handle"
        if has_o:
            return "object"
        return "none"


def _mnem(ins) -> str:
    """Bare mnemonic: this capstone build prefixes ``lock xadd``/``rep movs``."""
    return ins.mnemonic.split()[-1]


def _mem_field(ins) -> Optional[Tuple[int, int, str]]:
    """(offset, width, base_reg_name) of the record-field operand, or None."""
    for op in ins.operands:
        if op.type != X86_OP_MEM:
            continue
        if op.mem.base in STACK_BASES or op.mem.base == 0:
            return None
        base = ins.reg_name(op.mem.base) if op.mem.base else ""
        if base in ("rip", "rsp", "rbp"):
            return None
        if op.mem.index:
            # an indexed access is an array element, not a fixed record field
            return None
        return (op.mem.disp, op.size, base)
    return None


def _reg_operand(ins) -> Optional[str]:
    for op in ins.operands:
        if op.type == X86_OP_REG:
            return ins.reg_name(op.reg)
    return None


def _dest_reg(ins) -> Optional[str]:
    """Register written by this instruction, or None for a store to memory."""
    if not ins.operands:
        return None
    op = ins.operands[0]
    return ins.reg_name(op.reg) if op.type == X86_OP_REG else None


def _dest_mem_field(ins) -> Optional[Tuple[int, int, str]]:
    """(offset, width, base) when the *destination* operand is a record field.

    A store is only a store in its destination.  Reading ``_mem_field`` here would
    also record the source of a load, so ``mov eax, [rdi+0x10]`` would be booked as
    a write to ``+0x10``.
    """
    if not ins.operands:
        return None
    op = ins.operands[0]
    if op.type != X86_OP_MEM:
        return None
    if op.mem.base in STACK_BASES or op.mem.base == 0:
        return None
    if op.mem.index:
        return None
    return (op.mem.disp, op.size, ins.reg_name(op.mem.base))


LOAD_MNEMONICS = ("mov", "movzx", "movsxd", "movsx")
STORE_MNEMONICS = ("mov", "movups", "movdqu", "movq", "movd")


def summarize(image, rva: int, size: int) -> FunctionSummary:
    """Decode one function into an identity-domain summary."""
    out = FunctionSummary(rva=rva, size=size)
    try:
        insns, _md = image.disasm(rva, max(size, 1))
    except Exception:
        out.decode_ok = False
        return out
    loaded: Dict[str, bool] = {}  # register -> came from a memory operand
    for ins in insns:
        mnemonic = _mnem(ins)
        text = f"{ins.mnemonic} {ins.op_str}".strip()
        if mnemonic in LOAD_MNEMONICS:
            # register provenance and memory writes are two different facts about
            # the same instruction: a load must not swallow the store branch, and a
            # store must not pollute the provenance of its source register.
            dst = _dest_reg(ins)
            if dst:
                from_mem = any(op.type == X86_OP_MEM for op in ins.operands)
                loaded[dst] = bool(from_mem)
            if mnemonic in STORE_MNEMONICS:
                stored = _dest_mem_field(ins)
                if stored is not None:
                    offset, width, _base = stored
                    out.stores.setdefault(offset, set()).add(width)
            continue
        if mnemonic in COMPARE_MNEMONICS:
            field_info = _mem_field(ins)
            other = _reg_operand(ins)
            if field_info and other and mnemonic == "cmp":
                offset, width, _base = field_info
                out.compares.append(
                    FieldCompare(
                        site=ins.address,
                        offset=offset,
                        width=width,
                        other_reg=other,
                        from_pointer=loaded.get(other, False),
                        text=text,
                    )
                )
                continue
        if mnemonic in STORE_MNEMONICS:
            stored = _dest_mem_field(ins)
            if stored is not None:
                offset, width, _base = stored
                out.stores.setdefault(offset, set()).add(width)
    return out


class HandleCatalog:
    """Lazy, memoised per-function identity summaries for one image."""

    def __init__(self, image, index):
        self.image = image
        self.index = index
        self._cache: Dict[int, FunctionSummary] = {}

    def summary(self, rva: int) -> Optional[FunctionSummary]:
        cached = self._cache.get(rva)
        if cached is not None:
            return cached
        rec = self.index.get(rva)
        if rec is None:
            return None
        summary = summarize(self.image, rec.rva, rec.size)
        self._cache[rva] = summary
        return summary

    def domain(self, rva: int) -> str:
        summary = self.summary(rva)
        return summary.domain() if summary else "none"


# --------------------------------------------------------------------- release shape


@dataclass(frozen=True)
class Acquire:
    site: int          # call instruction address (rva)
    target: int        # callee rva
    slot: int          # stack slot displacement that receives the object
    obj_reg: str       # register that later holds the object
    obj_load: int      # address of the load of the slot


@dataclass(frozen=True)
class Drop:
    site: int          # address of the refcount decrement
    offset: int        # field offset holding the reference count
    obj_reg: str
    release_site: int  # address of the release call
    release_target: int
    guarded: bool      # True only when a refcount test provably gates the release
    guard_state: str = "unknown"   # "proven" | "unknown" -- never "unprotected"
    guard_reason: str = ""         # why the guard was accepted or refused
    guard_site: int = 0            # address of the proving conditional branch


@dataclass(frozen=True)
class Take:
    site: int
    offset: int
    obj_reg: str


@dataclass
class ReleaseShape:
    acquires: List[Acquire] = field(default_factory=list)
    drops: List[Drop] = field(default_factory=list)
    takes: List[Take] = field(default_factory=list)
    premise_calls: List[Tuple[int, int]] = field(default_factory=list)

    def drops_on(self, obj_reg: str) -> List[Drop]:
        return [d for d in self.drops if d.obj_reg == obj_reg]


def _stack_slot(ins) -> Optional[int]:
    """Displacement of a `lea REG, [rbp/rsp +/- X]` destination."""
    if _mnem(ins) != "lea" or len(ins.operands) < 2:
        return None
    dst, src = ins.operands[0], ins.operands[1]
    if dst.type != X86_OP_REG or src.type != X86_OP_MEM:
        return None
    if src.mem.base not in STACK_BASES:
        return None
    return src.mem.disp


def _slot_load(ins, slot: int) -> Optional[str]:
    """Register loaded from the given stack slot, if this instruction does that."""
    if _mnem(ins) != "mov" or len(ins.operands) < 2:
        return None
    dst, src = ins.operands[0], ins.operands[1]
    if dst.type != X86_OP_REG or src.type != X86_OP_MEM:
        return None
    if src.mem.base not in STACK_BASES or src.mem.disp != slot:
        return None
    return ins.reg_name(dst.reg)


def _refcount_delta(insns, idx: int) -> Optional[Tuple[int, str, int]]:
    """(field offset, object register, delta) of a refcount update, sign included.

    A reference *drop* and a reference *take* are the same instruction with a different
    constant in the source register (``lock xadd [obj+K], eax`` with ``eax = -1`` versus
    ``eax = 1``).  Counting both as "drop" would turn a legitimate borrow into an
    imbalance, so the constant is resolved when it was loaded shortly before.
    """
    ins = insns[idx]
    mnemonic = _mnem(ins)
    if mnemonic == "dec":
        field_info = _mem_field(ins)
        if field_info and field_info[1] in (4, 8):
            return (field_info[0], field_info[2], -1)
        return None
    if mnemonic != "xadd":
        return None
    field_info = _mem_field(ins)
    if not field_info or field_info[1] not in (4, 8):
        return None
    reg = _reg_operand(ins)
    delta = None
    if reg:
        for back in range(idx - 1, max(-1, idx - 4), -1):
            prev = insns[back]
            if _mnem(prev) != "mov" or reg not in prev.op_str:
                continue
            try:
                value = int(prev.op_str.split(",")[-1].strip(), 16)
            except Exception:
                continue
            if value >= (1 << 31):
                value -= 1 << 32
            delta = 1 if value > 0 else (-1 if value < 0 else 0)
            break
    return (field_info[0], field_info[2], delta if delta is not None else 0)


def _is_cond_branch(ins) -> bool:
    mnemonic = _mnem(ins)
    return mnemonic.startswith("j") and mnemonic != "jmp"


def _imm_operand(ins) -> Optional[int]:
    for op in ins.operands:
        if op.type == X86_OP_IMM:
            return int(op.imm)
    return None


def _field_match(ins, offset: int, obj_reg: str) -> Optional[str]:
    """'field' when a memory operand of ``ins`` is exactly ``[obj_reg+offset]``."""
    for op in ins.operands:
        if op.type != X86_OP_MEM:
            continue
        if op.mem.index:
            continue
        if op.mem.base == 0:
            continue
        if op.mem.disp == offset and ins.reg_name(op.mem.base) == obj_reg:
            return "field"
    return None


def _reg_names(ins) -> List[str]:
    out = []
    for op in ins.operands:
        if op.type == X86_OP_REG:
            out.append(ins.reg_name(op.reg))
    return out


def guard_proof(insns, idx: int, release_idx: int, release_site: int, offset: int,
                obj_reg: str) -> Tuple[str, str, int]:
    """Does a refcount test provably gate the release call?

    Returns ``(state, reason, branch_site)`` with ``state`` in ``{"proven",
    "unknown"}``.  "unknown" is the truthful answer for every shape that cannot be
    proved, including the tempting one where *some* ``cmp`` sits nearby: a
    comparison of an unrelated value against an unrelated immediate is not a
    reference-count guard, and reporting it as protected invents a defence the
    binary does not have.
    """
    span = range(idx + 1, max(idx + 1, release_idx))
    value_regs = {obj_reg}
    if _mnem(insns[idx]) == "xadd" and _field_match(insns[idx], offset, obj_reg) is not None:
        xadd_reg = _reg_operand(insns[idx])
        if xadd_reg:
            value_regs.add(xadd_reg)
    saw_compare = ""
    for fwd in span:
        ins = insns[fwd]
        mnemonic = _mnem(ins)
        if mnemonic == "xadd":
            # `lock xadd [obj+off], eax` leaves the *previous* count in eax, so the register is
            # the count's value. Without this, `cmp eax, 1` right after the decrement reads as
            # "compares an unrelated value" and a guarded release is reported unprotected.
            if _field_match(ins, offset, obj_reg) is not None:
                reg = _reg_operand(ins)
                if reg:
                    value_regs.add(reg)
            continue
        if mnemonic == "mov":
            dst = _dest_reg(ins)
            if dst:
                # a register loaded from the very field carries the count's value
                if _field_match(ins, offset, obj_reg):
                    value_regs.add(dst)
                elif dst in value_regs:
                    value_regs.discard(dst)      # overwritten: no longer the count
            continue
        if mnemonic not in COMPARE_MNEMONICS:
            continue
        same_field = _field_match(ins, offset, obj_reg) is not None
        operands = set(_reg_names(ins))
        touches_value = bool(operands & value_regs) or same_field
        immediate = _imm_operand(ins)
        text = f"{ins.mnemonic} {ins.op_str}".strip()
        if mnemonic == "test":
            # `test reg, reg` is a NULL check, not a count comparison against 1
            saw_compare = saw_compare or f"{text} (register test, not a count comparison)"
            continue
        if not touches_value:
            saw_compare = saw_compare or f"{text} (compares an unrelated value)"
            continue
        if immediate not in (0, 1):
            saw_compare = saw_compare or f"{text} (compares against {immediate}, not 0/1)"
            continue
        branch = None
        for step in range(fwd + 1, min(len(insns), fwd + 4)):
            if _is_cond_branch(insns[step]):
                branch = insns[step]
                break
            if _mnem(insns[step]) in ("call", "ret"):
                break
        if branch is None:
            saw_compare = saw_compare or f"{text} (no conditional branch consumes the flags)"
            continue
        return ("proven",
                f"{text} predicates {_mnem(branch)} {branch.op_str}".strip()
                + f" before the release at {hex(release_site)}",
                branch.address)
    if saw_compare:
        return ("unknown", saw_compare, 0)
    return ("unknown", "no comparison between the decrement and the release", 0)


def release_shape(view, is_release) -> ReleaseShape:
    """Data-flow-lite view of acquires, premise calls and drops in one function."""
    shape = ReleaseShape()
    ins = view.ins
    for idx, i in enumerate(ins):
        # acquire: an out-parameter slot set up shortly before a call
        target = view.calls.get(i.address)
        if target is not None:
            slot = None
            for back in range(idx - 1, max(-1, idx - 4), -1):
                slot = _stack_slot(ins[back])
                if slot is not None:
                    break
            if slot is not None:
                for fwd in range(idx + 1, min(len(ins), idx + 24)):
                    reg = _slot_load(ins[fwd], slot)
                    if reg:
                        shape.acquires.append(
                            Acquire(site=i.address, target=target, slot=slot,
                                    obj_reg=reg, obj_load=ins[fwd].address)
                        )
                        break
        # drop: decrement of a refcount field followed by a release call
        dec = _refcount_delta(ins, idx)
        if dec is not None:
            offset, obj_reg, sign = dec
            if sign > 0:                    # a reference *take*, not a drop
                shape.takes.append(Take(site=i.address, offset=offset, obj_reg=obj_reg))
                continue
            if sign == 0:                   # amount unknown: never counted as a drop
                continue
            release_idx = None
            release_site = None
            release_target = None
            # the release call sits behind the guard: cmp/jne, then argument setup
            for fwd in range(idx + 1, min(len(ins), idx + 9)):
                t = view.calls.get(ins[fwd].address)
                if t is not None and is_release(t):
                    release_idx = fwd
                    release_site = ins[fwd].address
                    release_target = t
                    break
            if release_site is not None and release_target is not None and release_idx is not None:
                state, reason, guard_site = guard_proof(
                    ins, idx, release_idx, release_site, offset, obj_reg)
                shape.drops.append(
                    Drop(site=i.address, offset=offset, obj_reg=obj_reg,
                         release_site=release_site, release_target=release_target,
                         guarded=(state == "proven"), guard_state=state,
                         guard_reason=reason, guard_site=guard_site)
                )
    # calls that sit between an acquire and the first drop are the ownership decision
    if shape.acquires and shape.drops:
        lo = min(a.site for a in shape.acquires)
        hi = min(d.site for d in shape.drops)
        for site, target in sorted(view.calls.items()):
            if lo < site < hi:
                shape.premise_calls.append((site, target))
    return shape
