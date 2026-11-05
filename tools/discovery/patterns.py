"""Semantic pattern scanner.

Seven lifecycle/ownership detectors over disassembled kernel functions.  Each
detector is *structural*: it reasons about slots (``[rbp-0x50]``, ``[rax+0x8]``,
array elements), release/lock call sites and control-flow reachability -- never
about addresses of known exploits.

Two rules carried from the R12-R15 engine work, both proven necessary:

* **Execution order, not address order.**  Kills are found by a path-sensitive
  walk over the real CFG, so a kill on a loop back-edge (address *below* the
  release) still counts.
* **An out-parameter call redefines a slot.**  ``lea rsi, [rbp-0x50]; call X``
  makes a later load of the slot a fresh definition, not a use.

Every finding records the instruction window it fired on plus the counter
evidence that was checked; a detector that cannot check something says so
instead of raising its rank.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import handles as handles_mod
from .image import KernelImage, require_capstone
from .locks import canonical_reg
from .lock_paths import stores_before_any_lock

try:  # pragma: no cover - guarded
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
except Exception:  # pragma: no cover
    X86_OP_IMM = X86_OP_MEM = X86_OP_REG = X86_REG_RIP = -1

ARGREGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
SCRATCH = ("rsp", "rbp")

RELEASE_NAME_HINTS = ("free", "fdrop", "_release", "destroy_", "_unref", "_put(")
LOCK_NAME_HINTS = ("_lock", "xlock", "wlock", "slock")
UNLOCK_NAME_HINTS = ("unlock", "xunlock", "wunlock", "sunlock")


# --------------------------------------------------------------------- records


@dataclass
class Finding:
    detector: str
    bug_class: str
    function_rva: int
    function_size: int
    function_name: str
    site_rvas: Tuple[int, ...]
    slot: Optional[str]
    rank: int
    subsystem: str = ""
    claims: Dict = field(default_factory=dict)
    counter_evidence: Dict = field(default_factory=dict)
    window: Tuple[str, ...] = ()
    falsification: str = ""

    def as_dict(self) -> dict:
        return {
            "detector": self.detector,
            "bug_class": self.bug_class,
            "function": {"rva": hex(self.function_rva), "size": self.function_size,
                         "name": self.function_name},
            "sites": [hex(s) for s in self.site_rvas],
            "slot": self.slot,
            "rank": self.rank,
            "subsystem": self.subsystem,
            "claims": self.claims,
            "counter_evidence": self.counter_evidence,
            "window": list(self.window),
            "falsification": self.falsification,
        }


# ------------------------------------------------------------- instruction view


def _mem_str(ins) -> Optional[str]:
    """Canonical key for the first memory operand, or None."""
    if not ins.operands:
        return None
    for op in ins.operands:
        if op.type != X86_OP_MEM:
            continue
        base = ins.reg_name(op.mem.base) if op.mem.base else ""
        index = ins.reg_name(op.mem.index) if op.mem.index else ""
        disp = op.mem.disp
        if base == "rip":
            return f"rip{disp:+#x}"
        if index:
            return f"{base}+{index}*{op.mem.scale}{disp:+#x}"
        if base:
            return f"{base}{disp:+#x}"
        return f"abs{disp:+#x}"
    return None


def _store_key(ins) -> Optional[str]:
    if not ins.operands:
        return None
    if ins.operands[0].type == X86_OP_MEM:
        return _mem_str(ins)
    return None


def _load_key(ins) -> Optional[str]:
    if len(ins.operands) < 2:
        return None
    for op in ins.operands[1:]:
        if op.type == X86_OP_MEM:
            return _mem_str(ins)
    return None


def _imm(ins) -> Optional[int]:
    for op in ins.operands:
        if op.type == X86_OP_IMM:
            return op.imm
    return None


def _direct_target(ins) -> Optional[int]:
    if ins.mnemonic not in ("call", "jmp"):
        return None
    for op in ins.operands:
        if op.type == X86_OP_IMM:
            return op.imm
    return None


def _branch_target(ins) -> Optional[int]:
    """Direct target of a jump, conditional branches included.

    Both CFG modes use this for ``j*``: a conditional branch has two
    successors, and a CFG that carries only the fall-through edge is not the
    program's control flow.
    """
    if not ins.mnemonic.startswith("j"):
        return None
    for op in ins.operands:
        if op.type == X86_OP_IMM:
            return op.imm
    return None


def _arg_source(ins) -> Optional[str]:
    """For ``mov rdi, [slot]`` style argument setup, return the source key."""
    if ins.mnemonic != "mov" or len(ins.operands) != 2:
        return None
    if ins.operands[0].type != X86_OP_REG:
        return None
    reg = ins.reg_name(ins.operands[0].reg)
    if reg not in ("rdi", "rsi"):
        return None
    if ins.operands[1].type == X86_OP_MEM:
        return _mem_str(ins)
    if ins.operands[1].type == X86_OP_REG:
        return ins.reg_name(ins.operands[1].reg)
    return None


def _arg_source_with_register(ins) -> Optional[Tuple[str, str]]:
    """(argument register, source key) for a ``mov argreg, ...`` setup."""
    if ins.mnemonic != "mov" or len(ins.operands) != 2:
        return None
    if ins.operands[0].type != X86_OP_REG:
        return None
    reg = ins.reg_name(ins.operands[0].reg)
    if reg not in ("rdi", "rsi", "rdx"):
        return None
    if ins.operands[1].type == X86_OP_MEM:
        return reg, _mem_str(ins)
    if ins.operands[1].type == X86_OP_REG:
        return reg, ins.reg_name(ins.operands[1].reg)
    return None


def _is_lea_of(ins, slot: str) -> Optional[str]:
    """``lea rsi, &slot`` -> the destination argument register."""
    if ins.mnemonic != "lea" or len(ins.operands) != 2:
        return None
    if ins.operands[0].type != X86_OP_REG or ins.operands[1].type != X86_OP_MEM:
        return None
    reg = ins.reg_name(ins.operands[0].reg)
    if _mem_str(ins) == slot:
        return reg
    return None


# ------------------------------------------------------------------ CFG / view


class FunctionView:
    """One function: instructions, blocks, CFG, call sites."""

    def __init__(self, image: KernelImage, rva: int, size: int, name: str = "",
                 strict_cfg: bool = False):
        require_capstone()
        self.image = image
        self.rva = rva
        self.size = size
        self.name = name
        self.strict_cfg = strict_cfg
        self.ins, _md = image.disasm(rva, size)
        self.blocks, self.succ, self.ins_by, self._addr2blk = self._build_cfg()
        self.calls = {}  # addr -> target rva
        self.jumps = {}  # addr -> target rva (tail jumps into another function)
        for i in self.ins:
            t = _direct_target(i)
            if t is None:
                continue
            if i.mnemonic == "call":
                self.calls[i.address] = t
            elif i.mnemonic == "jmp" and (t < self.rva or t >= self.rva + self.size):
                # only an out-of-function jump is a tail call; an in-function jmp is
                # just an edge of this CFG
                self.jumps[i.address] = t
        self._dom = None

    # -- construction -------------------------------------------------------

    def _build_cfg(self):
        ins = self.ins
        if not ins:
            return {}, {}, {}, {}
        leaders = {ins[0].address}
        targets = {}
        for idx, i in enumerate(ins):
            if i.mnemonic[0] == "j":
                # A conditional branch has two successors.  The default mode used to take only
                # the `call`/`jmp` target here, which dropped the taken edge of every `je`/`jne`:
                # alternative paths never joined, values stayed "definite" across a branch, and
                # must-strength claims rested on a CFG that did not contain the branch.
                # S1.9 restores the edge in *both* modes.  The S1.8 reason for withholding it --
                # D2_double_release claiming a kill-free path on the *fixed* aio_multi_delete body
                # once the loop back edge existed -- is fixed in the same step by the identity
                # check in `_path_without_kill`: a register slot (or a slot addressed through a
                # rebound base register) is not the same object on the far side of a loop.
                t = _branch_target(i)
                if t is not None:
                    targets[i.address] = t
                    leaders.add(t)
                if idx + 1 < len(ins):
                    leaders.add(ins[idx + 1].address)
            elif i.mnemonic in (("ret", "hlt", "ud2") if self.strict_cfg else ("ret", "hlt")):
                if idx + 1 < len(ins):
                    leaders.add(ins[idx + 1].address)
        lo = ins[0].address
        hi = ins[-1].address + ins[-1].size
        leaders = sorted(l for l in leaders if lo <= l < hi)
        blocks = {}
        for bi, s in enumerate(leaders):
            blocks[s] = leaders[bi + 1] if bi + 1 < len(leaders) else hi
        ins_by = {s: [] for s in blocks}
        addr2blk = {}
        for i in ins:
            for s in reversed(leaders):
                if s <= i.address:
                    ins_by[s].append(i)
                    addr2blk[i.address] = s
                    break
        succ = {s: [] for s in blocks}
        for s, il in ins_by.items():
            if not il:
                continue
            last = il[-1]
            if last.mnemonic in (("ret", "hlt", "ud2") if self.strict_cfg else ("ret", "hlt")):
                continue
            fall = blocks[s]
            if last.mnemonic == "jmp":
                t = targets.get(last.address)
                if t is not None and t in addr2blk:
                    succ[s].append(addr2blk[t])
            elif last.mnemonic[0] == "j":
                t = targets.get(last.address)
                taken = addr2blk.get(t) if t is not None else None
                if taken is not None:
                    succ[s].append(taken)
                # A branch whose target *is* the next instruction has one successor, not two
                # copies of one edge.
                if fall in addr2blk and fall != taken:
                    succ[s].append(addr2blk[fall])
            else:
                if fall in addr2blk:
                    succ[s].append(addr2blk[fall])
        return blocks, succ, ins_by, addr2blk

    # -- helpers ------------------------------------------------------------

    def block_of(self, addr: int) -> Optional[int]:
        return self._addr2blk.get(addr)

    def reachable_blocks(self, start_block: int) -> List[int]:
        seen, stack = [], [start_block]
        visited = set()
        while stack:
            b = stack.pop()
            if b in visited:
                continue
            visited.add(b)
            seen.append(b)
            stack.extend(self.succ.get(b, ()))
        return seen

    def dominators(self) -> Dict[int, set]:
        """Block dominator sets (iterative, standard)."""
        if self._dom is not None:
            return self._dom
        blocks = list(self.blocks)
        if not blocks:
            self._dom = {}
            return self._dom
        entry = blocks[0]
        dom = {b: set(blocks) for b in blocks}
        dom[entry] = {entry}
        changed = True
        while changed:
            changed = False
            for b in blocks:
                if b == entry:
                    continue
                preds = [p for p in blocks if b in self.succ.get(p, ())]
                if not preds:
                    continue
                new = set(blocks)
                for p in preds:
                    new &= dom[p]
                new |= {b}
                if new != dom[b]:
                    dom[b] = new
                    changed = True
        self._dom = dom
        return dom

    def window(self, addr: int, before: int = 2, after: int = 2) -> Tuple[str, ...]:
        idx = [k for k, i in enumerate(self.ins) if i.address == addr]
        if not idx:
            return ()
        k = idx[0]
        out = []
        for i in self.ins[max(0, k - before) : k + after + 1]:
            marker = ">>" if i.address == addr else "  "
            out.append(f"{marker} {i.address:#x}  {i.mnemonic} {i.op_str}".rstrip())
        return tuple(out)


# ------------------------------------------------------------------ detector ctx


@dataclass
class ScanContext:
    release_calls: frozenset = frozenset()
    lock_calls: frozenset = frozenset()
    unlock_calls: frozenset = frozenset()
    subsystem: str = ""
    ownership: object = None  # OwnershipCatalog; None keeps the legacy name-based rules
    observations: list = field(default_factory=list)  # unproven defects, evidence only
    handles: object = None  # HandleCatalog; identity-domain summaries per callee
    analytics: dict = field(default_factory=dict)  # per-run analysis coverage counters

    @classmethod
    def from_names(cls, named: Dict[int, str]) -> "ScanContext":
        rel, lock, unlock = set(), set(), set()
        for rva, name in named.items():
            low = name.lower()
            if any(h in low for h in RELEASE_NAME_HINTS):
                rel.add(rva)
            if any(h in low for h in LOCK_NAME_HINTS) and not any(
                h in low for h in UNLOCK_NAME_HINTS
            ):
                lock.add(rva)
            if any(h in low for h in UNLOCK_NAME_HINTS):
                unlock.add(rva)
        return cls(frozenset(rel), frozenset(lock), frozenset(unlock))

    def with_ownership(self, catalog) -> "ScanContext":
        return ScanContext(self.release_calls, self.lock_calls, self.unlock_calls,
                           self.subsystem, catalog)


# -------------------------------------------------------------------- detectors


def _release_sites(view: FunctionView, ctx: ScanContext) -> List[Tuple[int, Optional[str], int]]:
    """(ins_addr, source_slot, callee) for every release call in the function."""
    out = []
    for addr, tgt in view.calls.items():
        if tgt not in ctx.release_calls:
            continue
        blk = view.block_of(addr)
        if blk is None:
            continue
        pre = [i for i in view.ins_by[blk] if i.address < addr][-10:]
        # A release consumes a specific argument — its first one. Taking the *last* `mov` into any
        # argument register labelled the release with rsi's slot (a lock name, a context pointer),
        # so the slot that is actually freed was invisible and its NULL reset never counted as a
        # kill. Prefer rdi, fall back to the others only when no rdi setup exists.
        candidates = [item for item in (_arg_source_with_register(i) for i in reversed(pre)) if item]
        src = None
        for wanted in ("rdi", "rsi", "rdx"):
            for register, key in candidates:
                if register == wanted and key:
                    src = key
                    break
            if src:
                break
        out.append((addr, src, tgt))
    return out


def _kill_between(view: FunctionView, blk: int, start: int, slot: str) -> Tuple[bool, dict]:
    """Is the slot redefined (kill) later in this block?

    Three kill forms are recognised: a store to the slot, a register
    zero-extension into the slot, or an out-parameter call (``lea argreg,
    &slot`` before a call, with no later redefinition of that argument).
    """
    info = {"store": None, "outparam": None}
    il = [i for i in view.ins_by[blk] if i.address > start]
    for i in il:
        if _store_key(i) == slot:
            info["store"] = i.address
            return True, info
        reg = _is_lea_of(i, slot)
        if reg in ARGREGS:
            later = [j for j in il if j.address > i.address]
            writeback = [
                j
                for j in later
                if j.mnemonic in ("mov", "lea", "pop", "xor")
                and j.op_str.startswith(reg + ",")
            ]
            call = [j for j in later if j.mnemonic == "call"]
            if call and not writeback:
                info["outparam"] = call[0].address
                return True, info
    return False, info


def _uses_after_release(view: FunctionView, addr: int, slot: str, limit: int = 400):
    """Path-sensitive walk from a release: which instructions read the slot."""
    blk = view.block_of(addr)
    if blk is None:
        return [], {"killed": True, "kills": {}}
    uses, kills = [], {}
    visited = set()
    stack = [(blk, addr)]
    budget = limit
    while stack and budget > 0:
        b, start = stack.pop()
        if (b, start) in visited:
            continue
        visited.add((b, start))
        killed, info = _kill_between(view, b, start, slot)
        for i in view.ins_by[b]:
            if i.address <= start:
                continue
            if killed and i.address > min(
                [x for x in info.values() if x is not None] or [10**18]
            ):
                break
            lk = _load_key(i)
            if lk == slot and i.mnemonic not in ("mov",) or (lk == slot):
                uses.append(i.address)
            elif i.mnemonic in ("call", "jmp") and i.op_str.strip() == slot:
                uses.append(i.address)
            budget -= 1
            if budget <= 0:
                break
        if killed:
            kills[b] = info
            continue
        for s in view.succ.get(b, ()):
            stack.append((s, view.blocks[s]))
    return sorted(set(uses)), {"killed": bool(kills), "kills": kills}


#: D1/D4 confirmations are **not** trustworthy until the S1.2b repair is accepted.
#: While this is ``False`` every D1/D4 finding is stamped in its counter-evidence
#: and demoted below the queue admission rank, so it cannot reach a report as a
#: confirmed defect.  Flip it only with a positive reference in hand.
D1_D4_TRUSTED = False
UNTRUSTED_MARK = "untrusted_pending_S1.2b_acceptance"


def _stamp_trust(findings: List[Finding]) -> List[Finding]:
    if D1_D4_TRUSTED:
        return findings
    for finding in findings:
        finding.counter_evidence["trust"] = UNTRUSTED_MARK
        finding.counter_evidence["trust_reason"] = (
            "D1/D4 confirmations are disabled until the S1.2b soundness repair is "
            "accepted against a positive reference"
        )
        finding.rank = max(finding.rank, 3)
    return findings


def _lifecycle_view(view: FunctionView) -> FunctionView:
    """Strict-CFG view, extended past a fragment-sized index record."""
    cached = getattr(view, "_lifecycle_view", None)
    if cached is not None:
        return cached
    from .s11 import discover_extent

    size = view.size
    if size > 0x4000:
        # a sweep record can span megabytes when the next start is far away; the
        # analysis is bounded and the bound is reported, never silent
        size = 0x4000
    if size < 0x80:
        # A sweep-derived index reports the distance to the next start, which can
        # be a fragment of the real function.  Recover the reachable extent so a
        # truncated body never becomes a silent false negative.
        extent = discover_extent(view.image, view.rva, cap=0x1400)
        if extent.size > size:
            size = min(extent.size, 0x1400)
    strict = view
    if not view.strict_cfg or size != view.size:
        strict = FunctionView(view.image, view.rva, size, view.name, strict_cfg=True)
    view._lifecycle_view = strict
    return strict


def _lifecycle_run(view: FunctionView, ctx: ScanContext):
    """One versioned-memory pass per function, shared by D1 and D4."""
    cached = getattr(view, "_lifecycle_run", None)
    if cached is not None:
        return cached
    from .lifecycle import Lifecycle

    run = Lifecycle(_lifecycle_view(view), ctx.ownership)
    run.run()
    view._lifecycle_run = run
    return run


def _emit_observations(run, ctx: ScanContext) -> None:
    """Unproven defects are collected once per analysis, not once per detector."""
    if getattr(run, "_observations_emitted", False):
        return
    run._observations_emitted = True
    ctx.observations.extend(run.observations())
    stats = run.defect_stats()
    for key in ("releases", "indexed_release_events", "slots_released", "accesses",
                "indexed_accesses", "defects", "release_events", "access_events",
                "dropped_identities"):
        ctx.analytics[key] = ctx.analytics.get(key, 0) + int(stats.get(key, 0) or 0)
    ctx.analytics["functions_analysed"] = ctx.analytics.get("functions_analysed", 0) + 1
    causes = ctx.analytics.setdefault("truncation_causes", {})
    for cause, count in (stats.get("truncation_causes") or {}).items():
        causes[cause] = causes.get(cause, 0) + int(count)
    if stats.get("truncated"):
        ctx.analytics["truncated_functions"] = ctx.analytics.get("truncated_functions", 0) + 1
    if stats.get("widened"):
        ctx.analytics["widened_functions"] = ctx.analytics.get("widened_functions", 0) + 1


def _has_release_call(view: FunctionView, ctx: ScanContext) -> bool:
    """Is any release reachable from this function at all?

    A tail jump into a release wrapper is a call in all but spelling, so the gate
    has to look at jumps too -- otherwise the whole function is skipped and the
    release never even becomes an observation.
    """
    if ctx.ownership is None:
        return False
    lifecycle_view = _lifecycle_view(view)
    if any(ctx.ownership.is_release(t) for t in lifecycle_view.calls.values()):
        return True
    return any(ctx.ownership.is_release(t) for t in lifecycle_view.jumps.values())


def detect_use_after_release(view: FunctionView, ctx: ScanContext) -> List[Finding]:
    """D1 over versioned memory; the name-based rule stays as the measurement baseline."""
    if ctx.ownership is None:
        return detect_use_after_release_legacy(view, ctx)
    if not _has_release_call(view, ctx):
        return []
    run = _lifecycle_run(view, ctx)
    out = []
    for finding in run.findings():
        if finding.detector == "D1_use_after_release":
            finding.subsystem = ctx.subsystem
            out.append(finding)
    _emit_observations(run, ctx)
    return _stamp_trust(out)


def detect_use_after_release_legacy(view: FunctionView, ctx: ScanContext) -> List[Finding]:
    out = []
    for addr, slot, callee in _release_sites(view, ctx):
        if not slot:
            continue
        uses, killinfo = _uses_after_release(view, addr, slot)
        if not uses:
            continue
        window = list(view.window(addr, 1, 1))
        for u in uses[:2]:
            window.extend(view.window(u, 1, 1))
        out.append(
            Finding(
                detector="D1_use_after_release",
                bug_class="OWNERSHIP_UAF",
                function_rva=view.rva,
                function_size=view.size,
                function_name=view.name,
                site_rvas=tuple([addr] + uses[:4]),
                slot=slot,
                rank=1,
                subsystem=ctx.subsystem,
                claims={"release_site": hex(addr), "post_release_uses": [hex(u) for u in uses]},
                counter_evidence={"kill_forms_checked": ["store", "outparam"],
                                  "kill_hit": False},
                window=tuple(window),
                falsification=(
                    "show that every path from the release to the use redefines the slot "
                    "(store, zero-extension or out-parameter call), or that the release "
                    "callee does not free the object"
                ),
            )
        )
    return out


#: Registers whose value does not survive a call (System V AMD64 caller-saved).
CALLER_SAVED = ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11")

#: How a release site is reached.  Only a plain site is a candidate for a static double
#: release; a refcount-guarded site frees on the last reference, and two of those cannot
#: both hold on one path without a racing observation.
RELEASE_PLAIN = "PLAIN"
RELEASE_CONDITIONAL = "CONDITIONAL"
RELEASE_REFCOUNT_GUARDED = "REFCOUNT_GUARDED"

#: 64-bit register names, i.e. what a slot label can be read back as.
REGISTER_NAMES = frozenset(["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip"]
                           + ["r%d" % n for n in range(8, 16)])

_SLOT_TOKEN = re.compile(r"[a-z][a-z0-9]*")


def _slot_identity(slot: str) -> Tuple[bool, Tuple[str, ...]]:
    """``(register_slot, base registers)`` of a release-site slot label.

    A label is either a bare register (``rbx`` -- the release consumed the
    value the register holds) or a memory expression (``rbp-0x58``,
    ``rbx+0x40``, ``rcx+r14*8+0x0``).  A memory expression names one object
    only as long as the registers it is computed from keep their values;
    a ``rip``-relative label is a global and carries no such register.
    """
    canon = canonical_reg(slot)
    if canon in REGISTER_NAMES:
        return True, (canon,)
    bases: List[str] = []
    for token in _SLOT_TOKEN.findall(slot):
        name = canonical_reg(token)
        if name in REGISTER_NAMES and name != "rip" and name not in bases:
            bases.append(name)
    return False, tuple(bases)


def _writes_register(ins, registers: Tuple[str, ...]) -> bool:
    """Does ``ins`` destroy the value of one of ``registers``?"""
    if not registers:
        return False
    if ins.mnemonic in ("call", "jmp"):
        # A call preserves the callee-saved registers and clobbers the rest.
        return any(name in CALLER_SAVED for name in registers)
    try:
        _read, written = ins.regs_access()
    except Exception:  # pragma: no cover - a decoder without detail support
        # Fail closed: an instruction whose writes cannot be read cannot be
        # evidence that a register kept its value.
        return True
    for reg_id in written:
        name = ins.reg_name(reg_id) if reg_id else None
        if name and canonical_reg(name) in registers:
            return True
    return False


def _path_without_kill(view: FunctionView, first: int, second: int, slot: str) -> bool:
    """Is there a real CFG path from ``first`` to ``second`` that keeps the same object?

    Two claims have to hold along that path, because a double release is only a
    double release if the second site consumes *the same object*:

    * **the slot is not redefined** -- no store to it and no out-parameter call
      rewriting it (the NULL reset that makes the second release harmless);
    * **the identity survives** -- no base register of the slot expression is
      rebound on the way, and a caller-saved base is not clobbered by an
      intervening call.

    The identity condition is what S1.8 lacked, and it is the difference between
    a rule and a guess: on the *fixed* 13.52 ``aio_multi_delete`` body both
    release sites carry the label ``rbx``, but ``rbx`` is reloaded from the
    entry table inside the loop between them, so the two releases consume
    different entries.  Grouping by the label alone claimed a kill-free double
    free at rank 1 on the labelled negative as soon as the loop back edge
    existed in the CFG.

    An earlier version asked whether *any* reachable block contained an address
    in the range, which over-approximates and turned almost every function with
    two release calls into a rank-1 finding (79 of them on 13.52).  The walk
    carries a killed/identity-broken state per path, so one killing prefix
    disqualifies that path and not its sibling.
    """
    start_block = view.block_of(first)
    target_block = view.block_of(second)
    if start_block is None or target_block is None:
        return False
    _register_slot, bases = _slot_identity(slot)

    def ends_the_object(b: int, lo: int, hi: int) -> bool:
        for i in view.ins_by[b]:
            if not (lo <= i.address < hi):
                continue
            if _store_key(i) == slot or _writes_register(i, bases):
                return True
        return False

    visited = set()
    stack = [start_block]
    while stack:
        b = stack.pop()
        if b in visited:
            continue
        visited.add(b)
        if b == target_block:
            # between the two release sites nothing may end the object; the first
            # release call itself counts, because it returns through a clobbered
            # caller-saved register file
            if not ends_the_object(b, first, second):
                return True
            continue
        if ends_the_object(b, first if b == start_block else -1, 1 << 62):
            continue
        for succ in view.succ.get(b, ()):
            stack.append(succ)
    return False


def _unique_predecessor(view: FunctionView, block: int) -> Optional[int]:
    preds = [b for b, succ in view.succ.items() if block in succ and b != block]
    return preds[0] if len(preds) == 1 else None


def _guarded_release(view: FunctionView, addr: int) -> Optional[dict]:
    """A refcount guard in front of a release, or None.

    ``lock xadd [obj+0x28], ecx`` (delta -1), ``cmp ecx, 1``, ``jne <past the call>``,
    then the call: the release runs only when this thread observed the last reference.
    Such a site cannot free the same object twice on one path -- a second pass would have
    to observe the count as 1 again, which is a concurrency defect, not a static double
    release -- so it must not be ranked as one.

    The guard usually *ends* the predecessor block, not the release's own block, so the
    search walks the single-predecessor chain backwards (at most three blocks) and stops
    at a join, where there is no linear context to read a guard from.
    """
    block = view.block_of(addr)
    if block is None:
        return None
    chain = [block]
    while len(chain) < 4:
        earlier = _unique_predecessor(view, chain[-1])
        if earlier is None or earlier in chain:
            break
        chain.append(earlier)
    seq = []
    for b in reversed(chain[1:]):
        seq.extend(view.ins_by[b])
    seq.extend(view.ins_by[block])
    positions = {i.address: k for k, i in enumerate(seq)}
    call_pos = positions.get(addr)
    if call_pos is None:
        return None
    guard = None
    for k in range(call_pos - 1, -1, -1):
        ins = seq[k]
        if ins.mnemonic == "jmp":
            continue
        target = _branch_target(ins)
        if target is not None and target > addr:
            guard = ins
            break
    if guard is None:
        return None
    for k in range(call_pos - 1, -1, -1):
        delta = handles_mod._refcount_delta(seq, k)
        if delta and delta[2] is not None and delta[2] < 0:
            return {"kind": RELEASE_REFCOUNT_GUARDED,
                    "drop_site": hex(seq[k].address),
                    "drop_text": f"{seq[k].mnemonic} {seq[k].op_str}",
                    "guard_site": hex(guard.address),
                    "guard_text": f"{guard.mnemonic} {guard.op_str}",
                    "field": None if delta[0] is None else hex(delta[0]),
                    "object_register": delta[1]}
    return None


def _release_reaches_a_return_without(view: FunctionView, block: int) -> bool:
    """Is a return reachable from the entry without entering ``block``?"""
    if not view.ins:
        return True
    start = view.block_of(view.ins[0].address)
    if start is None or block == start:
        return False
    seen, stack = {start}, [start]
    while stack:
        b = stack.pop()
        if b == block:
            continue
        ins_list = view.ins_by.get(b) or []
        if ins_list and ins_list[-1].mnemonic in ("ret", "hlt", "ud2"):
            return True
        for succ in view.succ.get(b, ()):
            if succ not in seen:
                seen.add(succ)
                stack.append(succ)
    return False


def _release_kind(view: FunctionView, addr: int) -> dict:
    """What makes this release conditional, and is it refcount-killed?

    ``REFCOUNT_GUARDED`` -- the call is skipped unless the reference count hit zero.
    ``CONDITIONAL`` -- the site sits on an arm: a return is reachable around it.
    ``PLAIN`` -- neither, i.e. the site runs on every path to every return.
    """
    guard = _guarded_release(view, addr)
    if guard is not None:
        return guard
    block = view.block_of(addr)
    conditional = block is None or _release_reaches_a_return_without(view, block)
    return {"kind": RELEASE_CONDITIONAL if conditional else RELEASE_PLAIN,
            "block": None if block is None else hex(block)}


def detect_double_release(view: FunctionView, ctx: ScanContext) -> List[Finding]:
    """Two release sites on one slot, with no path that ends the object in between."""
    sites = _release_sites(view, ctx)
    by_slot: Dict[str, List[int]] = {}
    for addr, slot, _callee in sites:
        if slot:
            by_slot.setdefault(slot, []).append(addr)
    out = []
    for slot, addrs in by_slot.items():
        if len(addrs) < 2:
            continue
        addrs = sorted(addrs)
        first, second = addrs[0], addrs[-1]
        register_slot, bases = _slot_identity(slot)
        first_kind = _release_kind(view, first)
        second_kind = _release_kind(view, second)
        guarded = [kind for kind in (first_kind, second_kind)
                   if kind["kind"] == RELEASE_REFCOUNT_GUARDED]
        path_free = _path_without_kill(view, first, second, slot)
        reachable = path_free and not guarded
        out.append(
            Finding(
                detector="D2_double_release",
                bug_class="OWNERSHIP_DOUBLE_FREE",
                function_rva=view.rva,
                function_size=view.size,
                function_name=view.name,
                site_rvas=tuple(addrs),
                slot=slot,
                rank=1 if reachable else 3,
                subsystem=ctx.subsystem,
                claims={"release_sites": [hex(a) for a in addrs],
                        "path_between_without_kill": path_free,
                        # A double release needs the same *object* twice.  A bare register
                        # label or a memory label computed from a rebound base register is
                        # only an equal string, never evidence of one object.
                        "same_object": {"slot": slot,
                                        "register_slot": register_slot,
                                        "identity_registers": list(bases)},
                        # What makes each site conditional: a refcount kill cannot fire
                        # twice on one path, so it is not a static double release.
                        "release_kinds": [{"site": hex(first), **first_kind},
                                          {"site": hex(second), **second_kind}]},
                counter_evidence={"null_reset_after_first": not path_free,
                                  "refcount_guarded": bool(guarded),
                                  "guarded_sites": [kind.get("guard_site") for kind in guarded],
                                  "identity_forms_checked": [
                                      "store to the slot",
                                      "out-parameter call rewriting the slot",
                                      "rebinding of a base register of the slot",
                                      "caller-saved base clobbered at an intervening call"],
                                  "method": "CFG path walk; every path is dropped once the "
                                            "object ends (slot redefined, base register "
                                            "rebound), never a reachable-block "
                                            "over-approximation"},
                window=view.window(first, 1, 1) + view.window(second, 1, 1),
                falsification=(
                    "show an unconditional slot reset (store of 0/NULL or out-parameter "
                    "call) between the two release sites on every path, that a base "
                    "register of the slot is rebound on every such path, or that the "
                    "release is skipped unless a reference count reached zero"
                ),
            )
        )
    return out


def _blocks_without_lock(view: FunctionView, lock_blocks: set) -> set:
    """Blocks reachable from the entry without entering any lock block.

    Legacy block-level helper retained for differential tests.  It cannot distinguish
    a store before a lock from a store after a lock in the same block; D3 now uses
    ``stores_before_any_lock`` for instruction-order-aware witnesses instead.
    """
    if not view.ins:
        return set()
    start = view.block_of(view.ins[0].address)
    if start is None or start in lock_blocks:
        return set()
    seen, stack = {start}, [start]
    while stack:
        block = stack.pop()
        for succ in view.succ.get(block, ()):
            if succ in lock_blocks or succ in seen:
                continue
            seen.add(succ)
            stack.append(succ)
    return seen


def detect_lock_coverage(view: FunctionView, ctx: ScanContext) -> List[Finding]:
    """A shared store that some path reaches without taking the lock.

    The Lapse shape: one branch takes the lock before mutating a shared object,
    the other path writes the same object without it.
    """
    lock_sites = [a for a, t in view.calls.items() if t in ctx.lock_calls]
    if not lock_sites:
        return []
    shared_stores = []
    for i in view.ins:
        key = _store_key(i)
        if not key or i.mnemonic in ("cmp", "test"):
            continue
        base = key.split("+")[0].split("[")[0]
        if base in SCRATCH or key.startswith("rip"):
            continue
        if base in ARGREGS or base.startswith("r"):
            shared_stores.append(i)
    if not shared_stores:
        return []
    # S1.9's block-granular check missed a store preceding a lock call in the
    # *same* block.  Preserve exact instruction ordering even inside a block.
    # This remains a rank-2 (may) heuristic, not a lock-identity proof.
    uncovered = stores_before_any_lock(
        view, lock_sites, (ins.address for ins in shared_stores)
    )
    if not uncovered:
        return []
    return [
        Finding(
            detector="D3_lock_coverage",
            bug_class="RACE_UNLOCKED_SHARED_WRITE",
            function_rva=view.rva,
            function_size=view.size,
            function_name=view.name,
            site_rvas=tuple(lock_sites[:2] + uncovered[:4]),
            slot=None,
            rank=2,
            subsystem=ctx.subsystem,
            claims={
                "lock_calls": [hex(a) for a in lock_sites][:6],
                "uncovered_stores": [hex(a) for a in uncovered][:8],
                "uncovered_count": len(uncovered),
            },
            counter_evidence={
                "coverage": "path-based and instruction-ordered: some path from entry "
                            "reaches the store before any observed lock acquisition",
                "dominators_computed": False,
                "note": "a shared store is not a shared *state* store by itself; "
                        "rank is capped at 2 until the object is shown to be shared",
            },
            window=tuple(
                w for a in lock_sites[:1] + uncovered[:2] for w in view.window(a, 1, 1)
            ),
            falsification=(
                "prove the store targets a per-thread object, or that a lock acquired "
                "in every caller already covers the store"
            ),
        )
    ]


def detect_table_slot_lifecycle(view: FunctionView, ctx: ScanContext) -> List[Finding]:
    """D4 over canonical index expressions; legacy rule kept for measurement."""
    if ctx.ownership is None:
        return detect_table_slot_lifecycle_legacy(view, ctx)
    if not _has_release_call(view, ctx):
        return []
    run = _lifecycle_run(view, ctx)
    out = []
    for finding in run.findings():
        if finding.detector == "D4_table_slot_lifecycle":
            finding.subsystem = ctx.subsystem
            out.append(finding)
    _emit_observations(run, ctx)
    return _stamp_trust(out)


def detect_table_slot_lifecycle_legacy(view: FunctionView, ctx: ScanContext) -> List[Finding]:
    """A release of a table element, then the table is walked again.

    Covers the aio entry-array and kqueue note-array families: an element is
    freed while the structure still points at it (no NULL store on all paths),
    or the array is iterated with a length read from the structure itself.
    """
    out = []
    sites = _release_sites(view, ctx)
    for addr, slot, _callee in sites:
        if not slot or "*" not in slot:
            continue
        uses, killinfo = _uses_after_release(view, addr, slot)
        idx_reload = [
            i.address
            for i in view.ins
            if i.address > addr
            and _load_key(i)
            and _load_key(i).split("+")[0] == slot.split("+")[0]
        ]
        null_stores = [
            i.address
            for i in view.ins_by[view.block_of(addr) or view.rva]
            if i.address > addr and _store_key(i) == slot and _imm(i) == 0
        ]
        rank = 1 if (uses and not null_stores) else (2 if uses or idx_reload else 3)
        out.append(
            Finding(
                detector="D4_table_slot_lifecycle",
                bug_class="AIO_KQUEUE_SLOT_UAF",
                function_rva=view.rva,
                function_size=view.size,
                function_name=view.name,
                site_rvas=tuple([addr] + uses[:3]),
                slot=slot,
                rank=rank,
                subsystem=ctx.subsystem,
                claims={
                    "release_of_element": hex(addr),
                    "element_key": slot,
                    "null_store_after_release": [hex(a) for a in null_stores],
                    "post_release_uses": [hex(u) for u in uses],
                    "array_base_reloaded": [hex(a) for a in idx_reload][:6],
                },
                counter_evidence={"null_store_present": bool(null_stores),
                                  "kill_forms_checked": ["store", "outparam"]},
                window=view.window(addr, 1, 2),
                falsification=(
                    "show that the element slot is NULLed before any other reader can "
                    "reach it, or that the free is not an element of a shared array"
                ),
            )
        )
    return out


def detect_release_then_indirect(view: FunctionView, ctx: ScanContext) -> List[Finding]:
    """Release, then an indirect call through memory (vtable/ops dispatch)."""
    out = []
    for addr, slot, _callee in _release_sites(view, ctx):
        later = [i for i in view.ins if i.address > addr and i.mnemonic == "call"]
        for i in later:
            if i.operands and i.operands[0].type == X86_OP_MEM:
                key = _mem_str(i)
                if not key or key.startswith("rip") or key.split("+")[0] in SCRATCH:
                    continue
                out.append(
                    Finding(
                        detector="D5_release_then_indirect",
                        bug_class="FD_SOCKET_CLOSE_DISPATCH",
                        function_rva=view.rva,
                        function_size=view.size,
                        function_name=view.name,
                        site_rvas=(addr, i.address),
                        slot=slot or key,
                        rank=2,
                        subsystem=ctx.subsystem,
                        claims={"release_site": hex(addr),
                                "indirect_call": hex(i.address),
                                "dispatch_key": key},
                        counter_evidence={
                            "note": "the indirect target object is not tied to the released "
                                    "slot by an alias proof; rank capped at 2"
                        },
                        window=view.window(addr, 1, 1) + view.window(i.address, 1, 1),
                        falsification=(
                            "show the indirect call reads a different object than the one "
                            "released (register redefinition between the two sites)"
                        ),
                    )
                )
                break
    return out


def detect_refcount_asymmetry(view: FunctionView, ctx: ScanContext) -> List[Finding]:
    """Atomic refcount ops with unequal inc/dec coverage."""
    inc, dec = {}, {}
    for i in view.ins:
        if not i.op_str:
            continue
        prefixed = i.prefix and any(p in str(i.prefix) for p in ("LOCK", "lock"))
        m = i.mnemonic
        if m not in ("inc", "dec", "xadd", "cmpxchg", "xchg") and not prefixed:
            continue
        key = _mem_str(i)
        if not key or key.startswith("rip") or key.split("+")[0] in SCRATCH:
            continue
        if m == "inc":
            inc[key] = inc.get(key, 0) + 1
        elif m == "dec":
            dec[key] = dec.get(key, 0) + 1
    if not dec:
        return []
    out = []
    for key, ndec in dec.items():
        ninc = inc.get(key, 0)
        if ndec == ninc:
            continue
        out.append(
            Finding(
                detector="D6_refcount_asymmetry",
                bug_class="REFCOUNT_IMBALANCE",
                function_rva=view.rva,
                function_size=view.size,
                function_name=view.name,
                site_rvas=tuple(
                    i.address for i in view.ins if _mem_str(i) == key and i.mnemonic in ("inc", "dec")
                ),
                slot=key,
                rank=3,
                subsystem=ctx.subsystem,
                claims={"slot": key, "inc": ninc, "dec": ndec},
                counter_evidence={
                    "note": "a single function may legitimately dec without inc (borrowed "
                            "reference); observation only"
                },
                window=tuple(
                    w
                    for i in view.ins
                    if _mem_str(i) == key and i.mnemonic in ("inc", "dec")
                    for w in view.window(i.address, 1, 0)
                )[:6],
                falsification="show the reference is borrowed (inc happens in the caller)",
            )
        )
    return out


def _release_predicate(ctx: ScanContext):
    """A stable test for "this callee releases a reference" for either context shape."""
    ownership = getattr(ctx, "ownership", None)
    if ownership is not None and hasattr(ownership, "is_release"):
        return ownership.is_release
    releases = frozenset(getattr(ctx, "release_calls", frozenset()))

    def _by_set(target: int) -> bool:
        return target in releases

    return _by_set


def _premise_domains(view: FunctionView, ctx: ScanContext, shape) -> List[dict]:
    """Identity domain of every callee that sits between acquire and first drop."""
    handles = getattr(ctx, "handles", None)
    if handles is None:
        return []
    out = []
    for site, target in shape.premise_calls:
        summary = handles.summary(target)
        if summary is None:
            continue
        out.append(
            {
                "call_site": site,
                "target": target,
                "domain": summary.domain(),
                "handle_compares": [
                    {"site": c.site, "offset": c.offset, "width": c.width,
                     "other": c.other_reg, "from_pointer": c.from_pointer,
                     "text": c.text}
                    for c in summary.handle_compares
                ],
                "object_compares": [
                    {"site": c.site, "offset": c.offset, "width": c.width,
                     "other": c.other_reg, "from_pointer": c.from_pointer,
                     "text": c.text}
                    for c in summary.object_compares
                ],
            }
        )
    return out


def detect_handle_object_identity(view: FunctionView, ctx: ScanContext) -> List[Finding]:
    """A reference is dropped on the strength of a *handle* comparison.

    Shape: one call fills an out-parameter slot with an object, a second call decides
    ownership by comparing a stored 4-byte field against a caller-supplied number, and
    the caller then drops the resolved object at least twice.  A handle number may be
    reused by a different object, so the matched record does not prove that *this*
    object holds the reference being dropped; the surplus drop lands on a foreign
    object.

    Silence is meaningful: when the decision callee compares an 8-byte object field,
    the ownership premise holds and no claim is made (counter recorded in analytics).
    """
    ownership = _release_predicate(ctx)
    shape = handles_mod.release_shape(view, ownership)
    if not shape.acquires or not shape.drops:
        return []
    premises = _premise_domains(view, ctx, shape)
    if not premises:
        return []
    handled = [p for p in premises if p["domain"] in ("handle", "mixed")]
    objects = [p for p in premises if p["domain"] in ("object", "mixed")]
    out: List[Finding] = []
    for acq in shape.acquires:
        drops = shape.drops_on(acq.obj_reg)
        if len(drops) < 2:
            continue
        # the acquire itself accounts for the first reference; explicit takes (a positive
        # refcount update) account for more.  Only the remainder is a surplus drop.
        takes = [t for t in shape.takes
                 if t.obj_reg == acq.obj_reg and t.offset == drops[0].offset]
        surplus_count = len(drops) - 1 - len(takes)
        if surplus_count < 1:
            continue
        if objects:
            ctx.analytics["handle_identity_premise_verified"] = (
                ctx.analytics.get("handle_identity_premise_verified", 0) + 1
            )
            continue
        if not handled:
            continue
        premise = handled[0]
        surplus = drops[1:]
        ctx.analytics["handle_identity_candidates"] = (
            ctx.analytics.get("handle_identity_candidates", 0) + 1
        )
        out.append(
            Finding(
                detector="D7_handle_object_identity",
                bug_class="HANDLE_REUSE_IDENTITY",
                function_rva=view.rva,
                function_size=view.size,
                function_name=view.name,
                site_rvas=tuple([acq.site, premise["call_site"]]
                                + [d.site for d in drops]
                                + [d.release_site for d in drops]),
                slot=f"{acq.obj_reg}+{drops[0].offset:#x}",
                rank=2,
                subsystem=ctx.subsystem,
                claims={
                    "object_acquired_at": hex(acq.site),
                    "object_register": acq.obj_reg,
                    "object_slot": f"stack{acq.slot:+#x}",
                    "decision_call": hex(premise["call_site"]),
                    "decision_target": hex(premise["target"]),
                    "decision_domain": premise["domain"],
                    "decision_compares": premise["handle_compares"],
                    "drops": [hex(d.site) for d in shape.drops],
                    "drops_on_object": len(drops),
                    "explicit_takes": [hex(t.site) for t in takes],
                    "surplus_drops": [hex(d.site) for d in surplus],
                    "surplus_count": surplus_count,
                    "refcount_field": f"{acq.obj_reg}+{drops[0].offset:#x}",
                    "release_target": hex(drops[0].release_target),
                },
                counter_evidence={
                    "premise": "ownership was decided by comparing a 4-byte handle field, "
                               "not the object; handles are reused",
                    "aliasing": "no proof that the stored handle still denotes the object "
                                "that owns a reference; the surplus drop is therefore "
                                "release-without-holding",
                    "would_be_resolved_by": "an object-identity comparison at the decision "
                                            "site, or exactly one drop per acquired reference",
                },
                window=view.window(acq.site, 2, 2) + view.window(premise["call_site"], 2, 2)
                       # the decision itself lives in the callee: quote the comparing
                       # instructions so the claim carries its own binary evidence
                       + tuple(f"   {c['site']:#x}  {c['text']}"
                               for c in premise["handle_compares"][:3])
                       + view.window(drops[-1].site, 2, 2),
                falsification=(
                    "show that the compared field holds the object pointer (8 bytes), or "
                    "that the handle cannot be re-assigned between the store and the drop"
                ),
            )
        )
        break
    return out


def detect_reference_balance(view: FunctionView, ctx: ScanContext) -> List[Finding]:
    """More drops than acquires on the same object, with no ownership premise.

    Reported as an observation (rank 3): a borrowed reference is legitimate, so this is
    evidence of an accounting question, never a claim.
    """
    ownership = _release_predicate(ctx)
    shape = handles_mod.release_shape(view, ownership)
    if not shape.acquires or not shape.drops:
        return []
    premises = _premise_domains(view, ctx, shape)
    if any(p["domain"] != "none" for p in premises):
        return []
    out: List[Finding] = []
    for acq in shape.acquires:
        drops = shape.drops_on(acq.obj_reg)
        takes = [t for t in shape.takes
                 if t.obj_reg == acq.obj_reg and drops and t.offset == drops[0].offset]
        if len(drops) - 1 - len(takes) < 1:
            continue
        out.append(
            Finding(
                detector="D8_reference_balance",
                bug_class="REFCOUNT_IMBALANCE",
                function_rva=view.rva,
                function_size=view.size,
                function_name=view.name,
                site_rvas=tuple([acq.site] + [d.site for d in drops]),
                slot=f"{acq.obj_reg}+{drops[0].offset:#x}",
                rank=3,
                subsystem=ctx.subsystem,
                claims={"acquired": 1, "drops": len(drops),
                        "explicit_takes": [hex(t.site) for t in takes],
                        "drops": [hex(d.site) for d in drops],
                        "surplus_count": len(drops) - 1 - len(takes),
                        "release_target": hex(drops[0].release_target)},
                counter_evidence={
                    "note": "a borrowed reference may legitimately be dropped; no identity "
                            "decision was found, so the count alone is not evidence"
                },
                window=view.window(acq.site, 2, 2) + view.window(drops[-1].site, 2, 2),
                falsification="show the extra reference is owned by the caller (inc before "
                              "the call)",
            )
        )
    return out


DETECTORS = (
    detect_use_after_release,
    detect_double_release,
    detect_lock_coverage,
    detect_table_slot_lifecycle,
    detect_release_then_indirect,
    detect_refcount_asymmetry,
    detect_handle_object_identity,
    detect_reference_balance,
)


def scan_function(
    image: KernelImage,
    rva: int,
    size: int,
    name: str,
    ctx: ScanContext,
) -> List[Finding]:
    if size <= 0:
        return []
    view = FunctionView(image, rva, size, name)
    if len(view.ins) < 3:
        return []
    out = []
    for det in DETECTORS:
        try:
            out.extend(det(view, ctx))
        except Exception as exc:  # a broken rule must not kill the sweep
            out.append(
                Finding(
                    detector=getattr(det, "__name__", "detector"),
                    bug_class="DETECTOR_ERROR",
                    function_rva=rva,
                    function_size=size,
                    function_name=name,
                    site_rvas=(),
                    slot=None,
                    rank=9,
                    subsystem=ctx.subsystem,
                    claims={"error": repr(exc)[:200]},
                )
            )
    return out
