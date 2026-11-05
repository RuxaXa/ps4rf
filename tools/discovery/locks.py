"""Semantic lock analysis: primitives, modes, pairing, scope.

Why this module exists: the Sprint-1 measurement showed that a pure "two release
sites on one slot" rule cannot separate the vulnerable ``aio_multi_delete`` (9.00)
from its fix (13.52).  The published root cause is a *locking* defect, so the
discriminator has to be the lock state at the mutating site, not the shape of the
mutation.

Design:

* **Primitives are discovered, not hardcoded.**  A sync primitive is a function
  that performs an atomic read-modify-write on a lock word.  ``xchg`` with a
  memory operand is atomic by definition; everything else needs the ``lock``
  prefix byte (0xF0), which capstone exposes in ``ins.prefix`` as a *byte list* --
  ``str(ins.prefix)`` never contains the word "lock", so an earlier version of
  this module silently missed every ``lock cmpxchg``.
* **Mode comes from the operands, not from the name.**  ``cmpxchg mem, src``
  installs ``src`` if ``mem == rax``.  Installing a register loaded from
  ``gs:[0]`` (the current thread) is an exclusive acquire; installing zero, or
  swapping the current thread out for an unowned token, is a release.
* **Claims.**  Orbis serialises entry ownership through a helper that takes an
  exclusive lock, writes the current thread into a field of the shared object and
  releases the lock again.  Such a helper leaves no lock held, so acquire/release
  counting alone sees "nothing"; :meth:`SyncCatalog.claim_of` recognises the
  three-step pattern and exposes it as a CLAIM on the object.
* **Scope is a dataflow.**  Held locks and claims propagate over the CFG as a
  *must* set (intersection over paths) and a *may* set (union).  A mutation whose
  must set is empty while its may set is not is the "protected on one arm,
  unprotected on the other" shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .image import FunctionIndex, KernelImage, require_capstone

try:  # pragma: no cover
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
except Exception:  # pragma: no cover
    X86_OP_IMM = X86_OP_MEM = X86_OP_REG = -1

ACQUIRE_EXCL = "ACQUIRE_EXCL"
ACQUIRE_SHARED = "ACQUIRE_SHARED"
RELEASE = "RELEASE"
TRY = "TRY"
UNKNOWN = "UNKNOWN"
CLAIM = "CLAIM"

HELD = "HELD"
NOT_HELD = "NOT_HELD"
PATH_DEPENDENT = "PATH_DEPENDENT"
UNKNOWN_STATE = "UNKNOWN"

ARGREGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
SCRATCH = ("rsp", "rbp")
LOCK_PREFIX_BYTE = 0xF0


# ------------------------------------------------------------------ utilities


def is_atomic(ins) -> bool:
    """True for an atomic memory read-modify-write."""
    try:
        if ins.prefix and LOCK_PREFIX_BYTE in list(ins.prefix):
            return True
    except Exception:
        pass
    if ins.mnemonic == "xchg" and ins.operands and ins.operands[0].type == X86_OP_MEM:
        return True
    return ins.mnemonic in ("cmpxchg", "xadd", "cmpxchg8b", "cmpxchg16b")


def mem_key(ins) -> Optional[str]:
    for op in ins.operands:
        if op.type == X86_OP_MEM:
            return _mem_expr(ins, op)
    return None


def _mem_expr(ins, op) -> str:
    base = ins.reg_name(op.mem.base) if op.mem.base else ""
    index = ins.reg_name(op.mem.index) if op.mem.index else ""
    disp = op.mem.disp
    if base == "rip":
        return "rip%+#x" % disp
    if index:
        return "%s+%s*%d%+#x" % (base or "0", index, op.mem.scale, disp)
    if base:
        return base + ("%+#x" % disp if disp else "")
    return "abs%+#x" % disp


def operand_size(ins) -> Optional[int]:
    if not ins.operands:
        return None
    return ins.operands[0].size


def _dst_reg(ins) -> Optional[str]:
    if ins.operands and ins.operands[0].type == X86_OP_REG:
        return ins.reg_name(ins.operands[0].reg)
    return None


def _is_zero_write(ins) -> Optional[str]:
    reg = _dst_reg(ins)
    if reg is None:
        return None
    if ins.mnemonic == "xor" and len(ins.operands) == 2:
        parts = [p.strip() for p in ins.op_str.split(",")]
        if len(parts) == 2 and parts[0] == parts[1]:
            return reg
    if ins.mnemonic == "mov" and len(ins.operands) == 2 and ins.operands[1].type == X86_OP_IMM:
        if ins.operands[1].imm == 0:
            return reg
    return None


def _is_thread_load(ins) -> Optional[str]:
    reg = _dst_reg(ins)
    if reg is None or ins.mnemonic != "mov":
        return None
    if "gs:[" in ins.op_str:
        return reg
    return None


def canonical_reg(reg: str) -> str:
    """Collapse register aliases onto the 64-bit name."""
    aliases = {
        "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
        "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
        "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
        "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
        "esi": "rsi", "si": "rsi", "sil": "rsi",
        "edi": "rdi", "di": "rdi", "dil": "rdi",
        "esp": "rsp", "sp": "rsp", "spl": "rsp",
        "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
    }
    if reg in aliases:
        return aliases[reg]
    for n in range(8, 16):
        if reg in ("r%d" % n, "r%dd" % n, "r%dw" % n, "r%db" % n):
            return "r%d" % n
    return reg


def trim_function(ins: list) -> list:
    """Cut a disassembly window at the function's real end.

    The end is the first ``ret`` whose successor starts alignment padding
    (``nop`` / ``int3`` / the ``xchg ax, ax`` two-byte nop).  A window that runs
    into the next function would otherwise attribute foreign call sites to this
    one and invent lock events.
    """
    for k, i in enumerate(ins):
        if i.mnemonic != "ret":
            continue
        if k + 1 >= len(ins):
            return ins[: k + 1]
        nxt = ins[k + 1]
        if nxt.mnemonic in ("nop", "int3", "hlt"):
            return ins[: k + 1]
        if nxt.mnemonic == "xchg" and "ax, ax" in nxt.op_str:
            return ins[: k + 1]
    return ins


def _last_write_of(ins_list: Sequence, upto: int, reg: str, budget: int = 24):
    for k in range(upto - 1, max(-1, upto - budget) - 1, -1):
        ins = ins_list[k]
        if len(ins.operands) < 2 or ins.operands[0].type != X86_OP_REG:
            continue
        if canonical_reg(ins.reg_name(ins.operands[0].reg)) == reg:
            return ins
    return None


def _reader_count_mode(ins_list: Sequence, pos: int, new_reg: Optional[str]):
    """Reader-count RMW: the lock word's own value is stored back +/- delta.

    Reader/writer locks encode the reader count inside the lock word, so their
    acquire/release is a compare-exchange whose new value is
    ``current_lockword + delta`` rather than a thread token.  Without this rule
    such a primitive stays UNKNOWN and a reader-held object could be mistaken
    for a write-held one.
    """
    ins = ins_list[pos]
    if not ins.operands or ins.operands[0].type != X86_OP_MEM or not new_reg:
        return None
    word = mem_key(ins)
    if not word or word.startswith("rip"):
        return None
    expected_ins = _last_write_of(ins_list, pos, "rax")
    if expected_ins is None or expected_ins.mnemonic != "mov":
        return None
    if len(expected_ins.operands) < 2 or expected_ins.operands[1].type != X86_OP_MEM:
        return None
    if mem_key(expected_ins) != word:
        return None
    new_ins = _last_write_of(ins_list, pos, new_reg)
    if new_ins is None or new_ins.mnemonic != "lea":
        return None
    if len(new_ins.operands) < 2 or new_ins.operands[1].type != X86_OP_MEM:
        return None
    src = new_ins.operands[1]
    base = canonical_reg(new_ins.reg_name(src.mem.base)) if src.mem.base else ""
    if base != "rax" or src.mem.index:
        return None
    delta = src.mem.disp
    if delta > 0:
        return ACQUIRE_SHARED, "sx", "compare-exchange increments the encoded reader count"
    if delta < 0:
        return RELEASE, "sx", "compare-exchange decrements the encoded reader count"
    return None


# ------------------------------------------------------------------ provenance


@dataclass
class Prov:
    expr: str
    confidence: str  # B traced through definitions, A assumed argument, U unknown

    def __str__(self) -> str:
        return self.expr

    def as_dict(self) -> dict:
        return {"expr": self.expr, "confidence": self.confidence}


def _prov_step(ins_list: Sequence, upto: int, reg: str, budget: int):
    """One backwards step for ``reg``. Returns (kind, payload, confidence)."""
    for k in range(upto - 1, max(-1, upto - budget) - 1, -1):
        ins = ins_list[k]
        if _is_thread_load(ins) == reg:
            return "expr", "curthread", "B"
        if _is_zero_write(ins) == reg:
            return "expr", "zero", "B"
        if len(ins.operands) < 2 or ins.operands[0].type != X86_OP_REG:
            continue
        if canonical_reg(ins.reg_name(ins.operands[0].reg)) != reg:
            continue
        src = ins.operands[1]
        if src.type == X86_OP_MEM:
            base = canonical_reg(ins.reg_name(src.mem.base)) if src.mem.base else ""
            disp = src.mem.disp
            if base == "rbp":
                slot = "rbp%+#x" % disp
                if ins.mnemonic == "lea":
                    return "expr", "stackaddr(%s)" % slot, "B"
                return "expr", "obj(%s)" % slot, "B"
            if base in ARGREGS:
                return "expr", "%s%+#x" % (base, disp), "B"
            if base in SCRATCH or base == "":
                return "expr", "mem(%s)" % _mem_expr(ins, src), "U"
            return "derived", (base, disp), "B"
        if src.type == X86_OP_REG:
            nxt = canonical_reg(ins.reg_name(src.reg))
            if ins.mnemonic == "lea":
                return "derived", (nxt, 0), "B"
            return "rename", nxt, "B"
        if src.type == X86_OP_IMM:
            return "expr", "imm(%#x)" % (src.imm & (2 ** 64 - 1)), "B"
        return "expr", "?", "U"
    return "missing", None, "U"


def provenance(ins_list: Sequence, upto: int, reg: str, depth: int = 3,
               budget: int = 40) -> Prov:
    """Backward slice for ``reg`` at ``ins_list[upto]``.

    Notation: ``argN`` for incoming argument registers, ``obj(rbp-X)`` for a
    pointer loaded from a stack home slot, ``stackaddr(rbp-X)`` for its address,
    ``argN+D`` after an lea/add, ``curthread`` for a ``gs:[0]`` load, ``zero``
    for a zeroed register.  The walk is iterative with a visited set: a register
    cycle (``mov rax, rbx`` / ``mov rbx, rax``) used to recurse until the
    interpreter gave up.
    """
    reg = canonical_reg(reg)
    suffix = ""
    confidence = "B"
    visited: Set[str] = set()
    for _step in range(depth + 1):
        if reg in visited:
            return Prov(reg + suffix, "U")
        visited.add(reg)
        kind, payload, conf = _prov_step(ins_list, upto, reg, budget)
        if conf != "B":
            confidence = conf if confidence == "B" else confidence
        if kind == "expr":
            return Prov(payload + suffix, confidence if conf == "B" else conf)
        if kind == "rename":
            reg = payload
            continue
        if kind == "derived":
            base, disp = payload
            if disp:
                suffix = "%+#x" % disp + suffix
            reg = base
            continue
        break
    if reg in ARGREGS:
        return Prov("arg%d" % ARGREGS.index(reg) + suffix, "A")
    return Prov(reg + suffix, "U")


# --------------------------------------------------------------- primitives


@dataclass
class SyncPrimitive:
    rva: int
    mode: str
    kind: str
    lock_word_offset: Optional[int]
    atomic_site: int
    atomic_text: str
    evidence: str = ""

    def as_dict(self) -> dict:
        return {
            "rva": hex(self.rva),
            "mode": self.mode,
            "kind": self.kind,
            "lock_word_offset": None if self.lock_word_offset is None else hex(self.lock_word_offset),
            "atomic_site": hex(self.atomic_site),
            "atomic": self.atomic_text,
            "evidence": self.evidence,
        }


@dataclass
class Wrapper:
    rva: int
    primitive_rva: int
    lock_delta: int
    evidence: str = ""

    def as_dict(self) -> dict:
        return {"rva": hex(self.rva), "primitive": hex(self.primitive_rva),
                "lock_delta": hex(self.lock_delta), "evidence": self.evidence}


@dataclass
class ClaimPrimitive:
    """Helper that takes ownership of an object on behalf of the caller."""
    rva: int
    primitive_rva: int
    acquire_site: int
    stamp_site: int
    stamp_field: Optional[int]
    release_site: Optional[int]
    lock_delta: int = 0
    evidence: str = ""
    # Lock mode still held when the helper returns.  A helper that claims the
    # object exclusively and then re-enters in reader mode hands back a
    # read-held object, which cannot cover a later write.
    mode: str = ACQUIRE_EXCL

    def as_dict(self) -> dict:
        return {"rva": hex(self.rva), "primitive": hex(self.primitive_rva),
                "acquire_site": hex(self.acquire_site),
                "stamp_site": hex(self.stamp_site),
                "stamp_field": None if self.stamp_field is None else hex(self.stamp_field),
                "release_site": None if self.release_site is None else hex(self.release_site),
                "lock_delta": hex(self.lock_delta), "mode": self.mode,
                "evidence": self.evidence}


def held_mode_at_return(acquires, releases, default: str = ACQUIRE_EXCL) -> str:
    """Mode of the lock still held at ``ret``.

    ``acquires``/``releases`` are ``(position, primitive)`` pairs in address
    order.  An acquire whose matching release never follows is still
    outstanding when the helper returns; its mode is what the caller inherits.
    """
    outstanding = []
    for position, primitive in acquires:
        later = [rel for rel in releases
                 if rel[0] > position and rel[1].rva == primitive.rva]
        if not later:
            outstanding.append((position, primitive))
    if not outstanding:
        return default
    return outstanding[-1][1].mode


# ------------------------------------------------------------------- catalog


class SyncCatalog:
    """Sync primitives, their wrappers and claim helpers for one image."""

    def __init__(self, image: KernelImage, index: FunctionIndex, window: int = 0x180,
                 max_window: int = 0x1000):
        require_capstone()
        self.image = image
        self.index = index
        self.primitives: Dict[int, SyncPrimitive] = {}
        self.wrappers: Dict[int, Wrapper] = {}
        self.claims: Dict[int, ClaimPrimitive] = {}
        self._function_cache: Dict[int, list] = {}
        self._coverage_seen: Set[int] = set()
        self._call_targets: Dict[int, Set[int]] = {}
        self._cache_peak_functions = 0
        self._coverage = {
            "requested_functions": len(list(index)),
            "decoded_functions": 0,
            "decoded_bytes": 0,
            "decoded_instructions": 0,
            "truncated_functions": [],
            "decode_errors": [],
        }
        self._atomic_candidates = 0
        self._unknown_atomic_candidates = 0
        self._discover(window, max_window)
        self._discover_wrappers()
        self._discover_claims()
        self._function_cache.clear()

    # -- instruction cache --------------------------------------------------

    def ins(self, rva: int, size: int) -> list:
        try:
            got, _md = self.image.disasm(rva, size, instructions=True)
        except Exception:
            got = []
        return got

    def function_ins(self, rva: int, minimum: int = 0x300, maximum: int = 0x1000) -> list:
        """Disassembly window, trimmed at the real function end.

        Flat-RVA inventory sizes are unreliable for leaf helpers (they can be
        32-byte sweep stubs, or too small for a function whose last block sits
        beyond the record), so a minimum window is used and the result is cut at
        the first ``ret`` that is followed by alignment padding.  Without the cut
        a short function would inherit its neighbour's call sites.
        """
        if rva in self._function_cache:
            return self._function_cache[rva]
        rec = self.index.get(rva)
        record_size = rec.size if rec else minimum
        # One fixed bounded window per function.  The old three-pass code used
        # a different minimum for primitive/wrapper/claim discovery and decoded
        # the same body up to three times.
        floor = 0x300
        cap = 0x1000
        span = min(max(record_size, floor), cap)
        available = max(0, int(getattr(self.image, "size", rva + span)) - rva)
        span = min(span, available)
        if record_size > cap and rva not in self._coverage_seen:
            self._coverage["truncated_functions"].append({
                "rva": hex(rva), "recorded_size": hex(record_size), "cap": hex(cap)})
        try:
            got = trim_function(self.ins(rva, span)) if span else []
        except Exception as exc:  # defensive; ins() normally records as []
            got = []
            self._coverage["decode_errors"].append({"rva": hex(rva), "error": str(exc)})
        first_decode = rva not in self._coverage_seen
        self._coverage_seen.add(rva)
        if got and first_decode:
            decoded_bytes = got[-1].address + got[-1].size - rva
            self._coverage["decoded_functions"] += 1
            self._coverage["decoded_bytes"] += max(0, decoded_bytes)
            self._coverage["decoded_instructions"] += len(got)
        elif span and first_decode:
            self._coverage["decode_errors"].append({
                "rva": hex(rva), "error": "capstone decoded no instruction"})
        self._function_cache[rva] = got
        self._cache_peak_functions = max(self._cache_peak_functions,
                                         len(self._function_cache))
        return got

    # -- discovery ----------------------------------------------------------

    def _discover(self, window: int, max_window: int) -> None:
        for rec in self.index:
            if rec.size <= 0:
                self._coverage["decode_errors"].append({
                    "rva": hex(rec.rva), "error": "non-positive function size"})
                continue
            ins = self.function_ins(rec.rva, minimum=window, maximum=max_window)
            if not ins:
                self._function_cache.pop(rec.rva, None)
                continue
            targets = set()
            for item in ins:
                if item.mnemonic not in ("call", "jmp"):
                    continue
                try:
                    targets.add(int(item.op_str, 16))
                except ValueError:
                    pass
            self._call_targets[rec.rva] = targets
            thread_regs: Set[str] = set()
            zero_regs: Set[str] = set()
            for i in ins:
                t = _is_thread_load(i)
                if t:
                    thread_regs.add(canonical_reg(t))
                z = _is_zero_write(i)
                if z:
                    zero_regs.add(canonical_reg(z))
            for pos, i in enumerate(ins):
                if not is_atomic(i):
                    continue
                self._atomic_candidates += 1
                key = mem_key(i)
                if not key or key.startswith("rip"):
                    continue
                base = canonical_reg(key.split("+")[0])
                if base in SCRATCH or base == "":
                    continue
                try:
                    disp = i.operands[0].mem.disp
                except Exception:
                    disp = None
                mode, kind, why = self._mode_of(ins, pos, thread_regs, zero_regs)
                if mode == UNKNOWN:
                    self._unknown_atomic_candidates += 1
                    continue
                self.primitives.setdefault(rec.rva, SyncPrimitive(
                    rva=rec.rva, mode=mode, kind=kind, lock_word_offset=disp,
                    atomic_site=i.address, atomic_text=f"{i.mnemonic} {i.op_str}",
                    evidence=why))
                break
            # Retain compact call summaries, not every Capstone object.
            self._function_cache.pop(rec.rva, None)

    def _mode_of(self, ins_list, pos, thread_regs, zero_regs) -> Tuple[str, str, str]:
        ins = ins_list[pos]
        # Capstone renders a prefixed instruction as mnemonic ``lock cmpxchg``
        # (the prefix also remains in ``ins.prefix``).  Classification uses the
        # semantic opcode, not the pretty-printer's combined mnemonic.
        mn = ins.mnemonic.removeprefix("lock ")
        size = operand_size(ins)
        new_reg = None
        new_imm = None
        if len(ins.operands) > 1:
            if ins.operands[1].type == X86_OP_REG:
                new_reg = canonical_reg(ins.reg_name(ins.operands[1].reg))
            elif ins.operands[1].type == X86_OP_IMM:
                new_imm = ins.operands[1].imm & (2 ** 64 - 1)

        def is_thread(reg) -> bool:
            if reg is None:
                return False
            if reg in thread_regs:
                return True
            return provenance(ins_list, pos, reg, depth=2, budget=24).expr.startswith("curthread")

        def is_zero(reg) -> bool:
            if reg is None:
                return False
            if reg in zero_regs:
                return True
            return provenance(ins_list, pos, reg, depth=2, budget=24).expr == "zero"

        if mn in ("cmpxchg", "cmpxchg8b", "cmpxchg16b"):
            if size not in (8, 16):
                return UNKNOWN, "unknown", "compare-exchange of an unexpected width"
            expected = provenance(ins_list, pos, "rax", depth=2, budget=24)
            if is_thread(new_reg):
                return ACQUIRE_EXCL, "sx", "compare-exchange installs the current thread"
            if new_imm == 0 or is_zero(new_reg):
                return RELEASE, "sx", "compare-exchange installs zero (release)"
            if expected.expr.startswith("curthread"):
                return RELEASE, "sx", "compare-exchange swaps the owner out for an unowned token"
            reader = _reader_count_mode(ins_list, pos, new_reg)
            if reader is not None:
                return reader
            return UNKNOWN, "unknown", "compare-exchange with an unresolved source"
        if mn == "xchg":
            if size != 8:
                return UNKNOWN, "unknown", "exchange of a non-pointer width (byte-swap idiom)"
            if is_thread(new_reg):
                return ACQUIRE_EXCL, "mtx", "exchange installs the current thread"
            if new_imm == 0 or is_zero(new_reg):
                return RELEASE, "mtx", "exchange installs zero (release)"
            if new_imm in (1, 4):
                return ACQUIRE_EXCL, "mtx", "exchange installs a non-zero owner token"
            return UNKNOWN, "unknown", "exchange with an unresolved source"
        if mn == "xadd":
            if size not in (4, 8):
                return UNKNOWN, "unknown", "atomic add of an unexpected width"
            if new_imm is not None:
                signed = new_imm - (1 << (size * 8)) if new_imm >= (1 << (size * 8 - 1)) else new_imm
                if signed < 0:
                    return RELEASE, "refcount", "atomic add of a negative value drops a reference"
                return ACQUIRE_SHARED, "refcount", "atomic add of a positive value takes a reference"
            return UNKNOWN, "refcount", "atomic add with an unresolved value"
        if mn in ("inc", "dec"):
            if size not in (4, 8):
                return UNKNOWN, "unknown", "atomic inc/dec of an unexpected width"
            return (ACQUIRE_SHARED if mn == "inc" else RELEASE), "refcount", "atomic " + mn
        return UNKNOWN, "unknown", mn

    def _sync_at(self, ins_list, pos) -> Optional[SyncPrimitive]:
        ins = ins_list[pos]
        if ins.mnemonic not in ("call", "jmp"):
            return None
        try:
            tgt = int(ins.op_str, 16)
        except ValueError:
            return None
        if tgt in self.primitives:
            return self.primitives[tgt]
        wrap = self.wrappers.get(tgt)
        if wrap is not None:
            return self.primitives.get(wrap.primitive_rva)
        return None

    def _discover_wrappers(self) -> None:
        primitive_targets = set(self.primitives)
        for rec in self.index:
            if rec.size <= 0 or rec.rva in self.primitives:
                continue
            if not (self._call_targets.get(rec.rva, set()) & primitive_targets):
                continue
            ins = self.function_ins(rec.rva, minimum=0x80, maximum=0x800)
            if ins and not any(is_atomic(i) for i in ins):
                hits = []
                for pos, item in enumerate(ins):
                    if item.mnemonic not in ("call", "jmp"):
                        continue
                    try:
                        target = int(item.op_str, 16)
                    except ValueError:
                        continue
                    if target in self.primitives:
                        hits.append((pos, item, target))
                if len(hits) == 1:
                    pos, _item, target = hits[0]
                    prov = provenance(ins, pos, "rdi")
                    delta = 0
                    if prov.expr.startswith("arg0+"):
                        try:
                            delta = int(prov.expr.split("+", 1)[1], 16)
                        except ValueError:
                            delta = 0
                    self.wrappers[rec.rva] = Wrapper(
                        rec.rva, target, delta, f"rdi at the call is {prov.expr}")
            self._function_cache.pop(rec.rva, None)

    def _discover_claims(self) -> None:
        """A claim = exclusive acquire, then a store of curthread into the object,
        then a release: ownership of the object is handed to the caller."""
        acquire_targets = {
            target for target in set(self.primitives) | set(self.wrappers)
            if (self.classify(target) or {}).get("effect") in (ACQUIRE_EXCL, ACQUIRE_SHARED)
        }
        release_targets = {
            target for target in set(self.primitives) | set(self.wrappers)
            if (self.classify(target) or {}).get("effect") == RELEASE
        }
        for rec in self.index:
            if rec.size <= 0 or rec.rva in self.primitives:
                continue
            calls = self._call_targets.get(rec.rva, set())
            if not (calls & acquire_targets) or not (calls & release_targets):
                continue
            ins = self.function_ins(rec.rva, minimum=0x100, maximum=0x1000)
            if ins:
                thread_regs: Set[str] = set()
                acquires, releases, stamps = [], [], []
                for pos, item in enumerate(ins):
                    thread = _is_thread_load(item)
                    if thread:
                        thread_regs.add(canonical_reg(thread))
                    if item.mnemonic == "call":
                        prim = self._sync_at(ins, pos)
                        if prim is None:
                            continue
                        if prim.mode in (ACQUIRE_EXCL, ACQUIRE_SHARED):
                            acquires.append((pos, item, prim))
                        elif prim.mode == RELEASE:
                            releases.append((pos, item, prim))
                if acquires and releases:
                    for pos, item in enumerate(ins):
                        if item.mnemonic != "mov" or len(item.operands) < 2:
                            continue
                        if (item.operands[0].type != X86_OP_MEM or
                                item.operands[1].type != X86_OP_REG):
                            continue
                        stamp_mem = item.operands[0].mem
                        stamp_base = (canonical_reg(item.reg_name(stamp_mem.base))
                                      if stamp_mem.base else "")
                        if stamp_base in ("rbp", "rsp", ""):
                            continue
                        reg = canonical_reg(item.reg_name(item.operands[1].reg))
                        if (reg in thread_regs or
                                provenance(ins, pos, reg, depth=2,
                                           budget=16).expr.startswith("curthread")):
                            stamps.append((pos, item, item.operands[0].mem.disp))
                    for acquire_pos, acquire_site, acquire_prim in acquires:
                        for stamp_pos, stamp_site, stamp_field in stamps:
                            if stamp_pos <= acquire_pos:
                                continue
                            later = [release for release in releases
                                     if release[0] > stamp_pos]
                            if not later:
                                continue
                            _release_pos, release_site, _release_prim = later[0]
                            self.claims.setdefault(rec.rva, ClaimPrimitive(
                                rva=rec.rva, primitive_rva=acquire_prim.rva,
                                acquire_site=acquire_site.address,
                                stamp_site=stamp_site.address,
                                stamp_field=stamp_field,
                                release_site=release_site.address,
                                mode=held_mode_at_return(
                                    [(pos, prim) for pos, _ins, prim in acquires],
                                    [(pos, prim) for pos, _ins, prim in releases]),
                                evidence=("acquires %s at %#x, stamps curthread into "
                                          "[obj%+#x] at %#x, releases at %#x" %
                                          (acquire_prim.kind, acquire_site.address,
                                           stamp_field or 0, stamp_site.address,
                                           release_site.address))))
                            break
                        if rec.rva in self.claims:
                            break
            self._function_cache.pop(rec.rva, None)

    # -- lookup -------------------------------------------------------------

    def classify(self, callee_rva: int) -> Optional[dict]:
        prim = self.primitives.get(callee_rva)
        if prim is not None:
            return {"effect": prim.mode, "mode": prim.mode, "kind": prim.kind,
                    "primitive": prim.rva, "lock_delta": 0, "evidence": prim.evidence,
                    "atomic": prim.atomic_text, "atomic_site": prim.atomic_site,
                    "lock_word_offset": prim.lock_word_offset, "wrapper": None,
                    "claim": None, "stamp_field": None}
        claim = self.claims.get(callee_rva)
        if claim is not None:
            inner = self.primitives.get(claim.primitive_rva)
            return {"effect": CLAIM,
                    "mode": claim.mode,
                    "kind": inner.kind if inner else "sx",
                    "primitive": claim.primitive_rva, "lock_delta": claim.lock_delta,
                    "evidence": claim.evidence,
                    "atomic": inner.atomic_text if inner else "",
                    "atomic_site": inner.atomic_site if inner else 0,
                    "lock_word_offset": inner.lock_word_offset if inner else None,
                    "wrapper": None, "claim": claim.rva,
                    "stamp_field": claim.stamp_field}
        wrap = self.wrappers.get(callee_rva)
        if wrap is not None:
            inner = self.primitives[wrap.primitive_rva]
            return {"effect": inner.mode, "mode": inner.mode, "kind": inner.kind,
                    "primitive": inner.rva, "lock_delta": wrap.lock_delta,
                    "evidence": wrap.evidence, "atomic": inner.atomic_text,
                    "atomic_site": inner.atomic_site,
                    "lock_word_offset": inner.lock_word_offset, "wrapper": wrap.rva,
                    "claim": None, "stamp_field": None}
        return None

    def stats(self) -> dict:
        by_mode: Dict[str, int] = {}
        for p in self.primitives.values():
            by_mode[p.mode] = by_mode.get(p.mode, 0) + 1
        return {
            "primitives": len(self.primitives),
            "wrappers": len(self.wrappers),
            "claims": len(self.claims),
            "by_mode": by_mode,
            "by_kind": {k: sum(1 for p in self.primitives.values() if p.kind == k)
                        for k in sorted({p.kind for p in self.primitives.values()})},
            "atomic_candidates": self._atomic_candidates,
            "unknown_atomic_candidates": self._unknown_atomic_candidates,
            "unknown_rate": (round(self._unknown_atomic_candidates / self._atomic_candidates, 6)
                             if self._atomic_candidates else 0.0),
            "cache_peak_functions": self._cache_peak_functions,
            "coverage": self._coverage,
        }
