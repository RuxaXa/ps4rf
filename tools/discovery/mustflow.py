"""Conservative intraprocedural CFG must-reach object argument provenance.

The result is a *caller-side* identity witness only. It does not establish
callee ownership, resource release, exploitability, or a complete interprocedural
chain. Production graph transfer claims still require an independent callee-side
same-object instruction witness.

Run must data-flow over FunctionView blocks, merging register generations by
intersection at every CFG join. A bypass of the acquisition, a clobber on any
path, an unmodelled control transfer or an exhausted budget cannot prove an
argument. This is intentionally stricter than possible-reachability.
"""
from __future__ import annotations

from collections import deque
from typing import Dict, FrozenSet, Optional

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
CALLER_SAVED = frozenset(("rax", "rcx", "rdx", "rsi", "rdi",
                         "r8", "r9", "r10", "r11"))
GPRS = frozenset(("rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                  "rbp", "rsp") + tuple(f"r{i}" for i in range(8, 16)))
ALIASES = {}
for full, partial in (
    ("rax", ("eax", "ax", "al", "ah")),
    ("rbx", ("ebx", "bx", "bl", "bh")),
    ("rcx", ("ecx", "cx", "cl", "ch")),
    ("rdx", ("edx", "dx", "dl", "dh")),
    ("rsi", ("esi", "si", "sil")),
    ("rdi", ("edi", "di", "dil")),
    ("rbp", ("ebp", "bp", "bpl")),
    ("rsp", ("esp", "sp", "spl")),
):
    ALIASES[full] = full
    ALIASES.update({name: full for name in partial})
for i in range(8, 16):
    name = f"r{i}"
    for suffix in ("", "d", "w", "b"):
        ALIASES[name + suffix] = name


def _reg(ins, operand) -> str:
    try:
        return str(ins.reg_name(operand.reg)).lower()
    except Exception:
        return ""


def _writes(ins) -> Optional[FrozenSet[str]]:
    """Return canonical explicit/implicit GPR writes; None is insufficient detail."""
    try:
        _reads, regids = ins.regs_access()
        return frozenset(ALIASES.get(str(ins.reg_name(reg)).lower(), "")
                         for reg in regids) & GPRS
    except Exception:
        return None


def _refusal(why: str, *, call_site: int, acquisition: int) -> dict:
    return {"status": "unknown", "argument": None, "site": None,
            "call_site": hex(call_site), "acquisition": hex(acquisition),
            "why": why}


def _successors(view) -> Optional[Dict[int, tuple]]:
    """Instruction successors from FunctionView, or None if CFG is not trustworthy."""
    blocks = getattr(view, "ins_by", None)
    succ = getattr(view, "succ", None)
    if not blocks or succ is None:
        return None
    successors = {}
    all_sites = set()
    for block, items in blocks.items():
        if not items or block not in succ:
            return None
        if any(ins.address in all_sites for ins in items):
            return None
        all_sites.update(ins.address for ins in items)
        for idx, ins in enumerate(items):
            if idx + 1 < len(items):
                successors[ins.address] = (items[idx+1].address,)
                continue
            targets = []
            for successor in succ.get(block, ()):
                other = blocks.get(successor)
                if not other:
                    return None
                targets.append(other[0].address)
            successors[ins.address] = tuple(sorted(set(targets)))
    return successors


def _transfer(ins, state: FrozenSet[str], acquire_site: int,
              source_reg: str) -> Optional[FrozenSet[str]]:
    if ins.address == acquire_site:
        # A new generation begins here, after the instruction's effects.
        return frozenset((source_reg,))
    writes = _writes(ins)
    if writes is None:
        return None
    mnemonic = ins.mnemonic.split()[-1].lower()
    if mnemonic in ("call", "syscall", "sysenter", "int", "int3"):
        writes = writes | CALLER_SAVED
    old = state
    next_state = set(old) - writes
    operands = getattr(ins, "operands", []) or []
    if (mnemonic in ("mov", "movabs", "lea") and len(operands) >= 2
            and operands[0].type == X86_OP_REG):
        dst = _reg(ins, operands[0])
        if dst in GPRS:
            src = operands[1]
            exact = False
            if (mnemonic in ("mov", "movabs") and src.type == X86_OP_REG
                    and _reg(ins, src) in old):
                exact = True
            elif mnemonic == "lea" and src.type == X86_OP_MEM:
                base = _reg(ins, type("Operand", (), {"reg": src.mem.base})())
                # Only LEA of the *same* address may transfer pointer identity.
                exact = (base in old and not src.mem.index and not src.mem.disp)
            if exact:
                next_state.add(dst)
    return frozenset(next_state)


def must_argument_placement(view, call_site: int, object_register: str,
                            acquire_site: int, max_states: int = 20_000) -> dict:
    """Prove one exact 64-bit object survives on ALL CFG paths to a call.

    This computes a must fixed-point for registers carrying a single acquired
    pointer generation. A branch can reach the call along multiple paths only
    when all incoming states still carry the pointer in the same argument
    register. The result is caller evidence, *never* a release verdict.

    Return UNKNOWN on missing disassembly, indirect control transfers, call
    sites not reached, partial source registers, missing CFG links or budget
    exhaustion. Do not turn an UNKNOWN into REFUTED: it is not a proof that
    some other argument never carried the pointer.
    """
    refuse = lambda reason: _refusal(reason, call_site=call_site,
                                     acquisition=acquire_site)
    source = str(object_register).lower()
    if source not in GPRS:
        return refuse("source is not a full-width 64-bit object register")
    if not isinstance(max_states, int) or max_states <= 0:
        return refuse("dataflow analysis has no positive budget")
    insns = list(getattr(view, "ins", []) or [])
    by_site = {ins.address: ins for ins in insns}
    if len(by_site) != len(insns) or call_site not in by_site:
        return refuse("call site is absent or instruction addresses overlap")
    if acquire_site not in by_site:
        return refuse("acquisition instruction is not in the function")
    if by_site[call_site].mnemonic.split()[-1].lower() != "call":
        return refuse("target instruction is not a call")
    successors = _successors(view)
    if not successors or set(successors) != set(by_site):
        return refuse("CFG is incomplete or does not match the disassembly")

    # Reject control transfers whose destinations are not represented by the
    # provided CFG. The current FunctionView does not model indirect branches.
    # Treating those as exits would let a computed jump bypass acquisition
    # or a copy and produce an unsupported must-proof.
    for site, ins in by_site.items():
        mnemonic = ins.mnemonic.split()[-1].lower()
        if (mnemonic in ("jmp", "call") or mnemonic.startswith("j")
                or mnemonic.startswith("loop")):
            if mnemonic == "call":
                continue
            operands = getattr(ins, "operands", []) or []
            if not operands or operands[0].type != X86_OP_IMM:
                return refuse("an indirect or unknown control transfer is unresolved")
            if mnemonic != "jmp" and not successors[site]:
                return refuse("a conditional branch has no resolved successors")

    entry = insns[0].address
    incoming: Dict[int, FrozenSet[str]] = {entry: frozenset()}
    queue = deque((entry,))
    queued = {entry}
    evaluations = 0
    while queue:
        site = queue.popleft()
        queued.discard(site)
        evaluations += 1
        if evaluations > max_states:
            return refuse("CFG reaching-definitions analysis exceeded its budget")
        if site == call_site:
            # The call itself would clobber its arguments; we need pre-call.
            continue
        after = _transfer(by_site[site], incoming[site], acquire_site, source)
        if after is None:
            return refuse(f"unavailable register-write metadata at {hex(site)}")
        for dest in successors[site]:
            if dest not in by_site:
                return refuse("CFG successor leaves the decoded function")
            old = incoming.get(dest)
            merged = after if old is None else old & after
            if old is None or merged != old:
                incoming[dest] = merged
                if dest not in queued:
                    queue.append(dest)
                    queued.add(dest)

    if call_site not in incoming:
        return refuse("target call is unreachable from function entry")
    carried = tuple(reg for reg in ARG_REGS if reg in incoming[call_site])
    if not carried:
        return refuse("no argument register retains this exact object on every path")
    return {"status": "proved", "argument": carried[0],
            "arguments": carried, "site": hex(call_site),
            "call_site": hex(call_site), "acquisition": hex(acquire_site),
            "source_register": source, "kind": "cfg-must-reach",
            "evaluated_states": evaluations,
            "text": (f"CFG must-reach from {hex(acquire_site)} ({source}) "
                     f"to call {hex(call_site)} via {', '.join(carried)}"),
            "why": "all analysed paths reaching the call retain exact object identity"}
