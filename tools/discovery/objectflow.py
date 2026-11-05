"""Object flow: prove that two sites act on the *same* object, and that an owner passes it on.

The rule this module exists to enforce: **a call edge is not a transfer.**  A call proves that
control reaches a function; it says nothing about which object was handed over or whether the
callee touched it.  A transfer is proved only when

1. the object register (or a tracked alias of it) is placed in an argument register before the
   call, and
2. the callee actually uses that argument as an object — it dereferences it, or it releases it.

Alias tracking covers the moves that matter here: plain `mov`, zero/sign extending movs, `lea`
(which produces a pointer *into* the object and is therefore an alias only when the base is
tracked), and stack spill/reload through a fixed frame slot.  The repaired store summary
(`handles.summarize().stores`) is the consumer that ties an identity claim to a field: a drop
that decrements the same field offset on the same base is evidence that both sites mean the
same object, not merely the same register number.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional

try:
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RBP, X86_REG_RSP
except Exception:                              # pragma: no cover - stub guard
    X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RBP, X86_REG_RSP = 2, 3, 1, 4, 5

#: System V argument registers, in order.
ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
#: Moves that copy a pointer unchanged (or into an interior pointer).
ALIAS_MOVES = ("mov", "movzx", "movsxd", "movsx", "lea", "xchg")
FRAME_REGS = ("rbp", "rsp")
MAX_TRACKED = 12
#: Alias chains longer than this are not accepted as identity: transitive closure over every
#: `mov` in a function turns almost every register into an "alias" of every other and makes the
#: identity claim worthless. Three hops covers the patterns that occur (move, spill/reload,
#: interior pointer via lea) without swallowing whole functions.
MAX_ALIAS_HOPS = 3
#: Upper bound for a function body when one is summarised without a size table.
MAX_FUNCTION_BYTES = 4096


def _reg_name(ins, operand) -> Optional[str]:
    try:
        name = ins.reg_name(operand.reg)
    except Exception:
        return None
    return name or None


def _is_frame_base(ins, operand) -> bool:
    base = getattr(operand.mem, "base", 0)
    return getattr(ins, "reg_name", lambda _r: "")(
        base) in FRAME_REGS if base else False


def _slot_key(ins, operand) -> Optional[str]:
    """A frame slot as a stable string, or None when the memory operand is not a frame slot."""
    mem = operand.mem
    if not getattr(mem, "base", 0):
        return None
    base = ins.reg_name(mem.base) if hasattr(ins, "reg_name") else None
    if base not in FRAME_REGS:
        return None
    if getattr(mem, "index", 0):
        return None
    return f"[{base}{mem.disp:+#x}]"


def track_register(insns: List, start_idx: int, reg: str) -> dict:
    """Forward alias closure for one register: bounded in depth, invalidated on clobber.

    Two rules keep this honest. A chain stops after ``MAX_ALIAS_HOPS`` links, because a
    transitive closure over every move in a function turns almost any register into an
    "alias" of any other and the identity claim becomes vacuous. And a register stops being an
    alias as soon as it is written by something that is not a pointer copy — ``add reg, imm``
    and ``sub reg, imm`` are kept, because an interior pointer is still the same object.
    """
    regs = {reg}
    depth = {reg: 0}
    slots = set()
    evidence: List[dict] = []
    for ins in insns[start_idx:]:
        mnemonic = ins.mnemonic
        operands = list(getattr(ins, "operands", []) or [])
        destination = operands[0] if operands else None

        # 1. does this instruction copy a tracked pointer somewhere?
        copied = False
        if destination is not None and mnemonic in ALIAS_MOVES and len(operands) >= 2:
            source = operands[1]
            if destination.type == X86_OP_REG and source.type == X86_OP_REG:
                src_name, dst_name = _reg_name(ins, source), _reg_name(ins, destination)
                if (src_name in regs and dst_name and dst_name not in regs
                        and depth.get(src_name, 0) < MAX_ALIAS_HOPS):
                    regs.add(dst_name)
                    depth[dst_name] = depth.get(src_name, 0) + 1
                    copied = True
                    evidence.append({"site": hex(ins.address), "kind": "register-alias",
                                     "text": f"{src_name} -> {dst_name}"})
                    if len(regs) > MAX_TRACKED:
                        return {"regs": sorted(regs), "slots": sorted(slots),
                                "evidence": evidence, "depths": dict(depth),
                                "truncated": True}
            elif destination.type == X86_OP_MEM and source.type == X86_OP_REG:
                slot = _slot_key(ins, destination)
                src_name = _reg_name(ins, source)
                if src_name in regs and slot and depth.get(src_name, 0) < MAX_ALIAS_HOPS:
                    slots.add(slot)
                    copied = True
                    evidence.append({"site": hex(ins.address), "kind": "spill",
                                     "text": f"spilled to {slot}"})
            elif destination.type == X86_OP_REG and source.type == X86_OP_MEM:
                slot = _slot_key(ins, source)
                dst_name = _reg_name(ins, destination)
                if slot in slots and dst_name and dst_name not in regs:
                    regs.add(dst_name)
                    depth[dst_name] = MAX_ALIAS_HOPS - 1
                    copied = True
                    evidence.append({"site": hex(ins.address), "kind": "reload",
                                     "text": f"reloaded from {slot} into {dst_name}"})

        # 2. otherwise, a write to a tracked register ends its alias (interior pointers stay)
        if (not copied and destination is not None
                and getattr(destination, "type", None) == X86_OP_REG):
            written = _reg_name(ins, destination)
            keeps_offset = (mnemonic in ("add", "sub") and len(operands) >= 2
                            and getattr(operands[1], "type", None) == X86_OP_IMM)
            if written and written in regs and written != reg and not keeps_offset:
                regs.discard(written)
                depth.pop(written, None)
                evidence.append({"site": hex(ins.address), "kind": "alias-killed",
                                 "text": f"{mnemonic} {ins.op_str} overwrites {written}"})
    return {"regs": sorted(regs), "slots": sorted(slots), "evidence": evidence,
            "depths": dict(depth), "truncated": False}


def object_field_writes(insns: List, regs: Iterable[str]) -> List[dict]:
    """Memory writes whose base is one of the tracked registers — the object's fields.

    This is where the repaired store summary earns its keep: an identity claim that names a
    field offset is checkable, a claim that only names a register is not.
    """
    writes = []
    regs = set(regs)
    for ins in insns:
        operands = list(getattr(ins, "operands", []) or [])
        if ins.mnemonic not in ("mov", "dec", "inc", "add", "sub", "or", "and") or not operands:
            continue
        destination = operands[0]
        if getattr(destination, "type", None) != X86_OP_MEM:
            continue
        mem = destination.mem
        base = ins.reg_name(mem.base) if (ins.reg_name and mem.base) else None
        if base in regs and not getattr(mem, "index", 0):
            writes.append({"site": hex(ins.address), "base": base,
                           "offset": int(getattr(mem, "disp", 0)),
                           "width": int(getattr(destination, "size", 0) or 0),
                           "text": f"{ins.mnemonic} {ins.op_str}"})
    return writes


def _argument_register_at(view, call_site_address: int, regs: Iterable[str],
                          window: int = 14) -> Optional[dict]:
    """Find the argument register that receives the tracked object before a call."""
    regs = set(regs)
    insns = view.ins
    position = next((i for i, ins in enumerate(insns)
                     if ins.address == call_site_address), None)
    if position is None:
        return None
    for back in range(position - 1, max(-1, position - 1 - window), -1):
        ins = insns[back]
        operands = list(getattr(ins, "operands", []) or [])
        if ins.mnemonic in ("mov", "lea") and len(operands) >= 2:
            destination, source = operands[0], operands[1]
            if destination.type != X86_OP_REG:
                continue
            name = _reg_name(ins, destination)
            source_name = _reg_name(ins, source) if source.type == X86_OP_REG else None
            if name in ARG_REGS and source_name in regs:
                return {"arg_register": name, "from": source_name, "site": hex(ins.address),
                        "text": f"{ins.mnemonic} {ins.op_str}"}
    return None


def callee_uses_object(callee_view, arg_register: str, limit: int = 24) -> Optional[dict]:
    """Does the callee treat the argument as an object? Deref, release, or pass it on."""
    for ins in callee_view.ins[:limit]:
        operands = list(getattr(ins, "operands", []) or [])
        for operand in operands:
            if getattr(operand, "type", None) != X86_OP_MEM:
                continue
            mem = operand.mem
            if mem.index:
                continue
            base = ins.reg_name(mem.base) if (ins.reg_name and mem.base) else None
            if base == arg_register:
                return {"site": hex(ins.address), "kind": "deref",
                        "text": f"{ins.mnemonic} {ins.op_str} dereferences {arg_register}"}
        if ins.mnemonic == "call":
            for operand in operands:
                if getattr(operand, "type", None) == X86_OP_REG:
                    name = _reg_name(ins, operand)
                    if name == arg_register:
                        return {"site": hex(ins.address), "kind": "handoff",
                                "text": f"passes {arg_register} on to another callee"}
    return None


def prove_transfer(caller_view, call_site_address: int, callee_view,
                   object_regs: Iterable[str]) -> dict:
    """Prove or refuse a reference transfer across one call. A call edge alone is not one."""
    placed = _argument_register_at(caller_view, call_site_address, object_regs)
    if not placed:
        return {"proved": False,
                "why": "no tracked alias of the object reaches an argument register before "
                       "the call; the call edge says nothing about which object was passed"}
    used = callee_uses_object(callee_view, placed["arg_register"])
    if not used:
        return {"proved": False,
                "why": f"the object is passed in {placed['arg_register']} but the callee does "
                       f"not use it as an object within its first instructions"}
    return {"proved": True,
            "evidence": f"{placed['text']} at {placed['site']} then {used['text']} at "
                        f"{used['site']}",
            "argument_register": placed["arg_register"],
            "caller_site": placed["site"],
            "callee_site": used["site"]}


def object_flow_for_drops(view, drop_sites: Iterable[dict], object_reg: str,
                          stores: Optional[dict] = None) -> dict:
    """Same-object evidence for the sites that act on the object inside one function.

    ``stores`` is the repaired summary (`{offset: {width, ...}}`): when a drop writes the same
    field offset on the same base as the other site, the two sites are talking about the same
    object field, which is what an identity claim has to mean.
    """
    insns = view.ins
    first = next((i for i, ins in enumerate(insns)
                  if object_reg in (ins.op_str or "")), 0)
    alias = track_register(insns, first, object_reg)
    # Field writes count only on the bases the sites themselves use. Collecting them over the
    # whole alias set produced "shared offsets" that were just the function touching memory.
    site_regs = {drop.get("object_register") or object_reg for drop in drop_sites}
    writes = object_field_writes(insns, site_regs)
    fields = {write["offset"]: write for write in writes}
    per_drop = []
    for drop in drop_sites:
        return_register = drop.get("object_register") or object_reg
        per_drop.append({
            "site": drop.get("site"),
            "register": return_register,
            "aliased": return_register in alias["regs"],
        })
    same_base = all(entry["aliased"] for entry in per_drop) if per_drop else False
    summary_fields = sorted((stores or {}).keys()) if isinstance(stores, dict) else []
    shared_fields = sorted(set(summary_fields) & set(fields))
    if same_base and per_drop:
        why = None
        evidence = (f"every site uses an alias of {object_reg} "
                    f"({', '.join(alias['regs'])})")
        if shared_fields:
            evidence += (f"; the same field offsets {shared_fields} are written on that base, "
                         f"so the sites mean the same object")
        proved = True
    else:
        proved = False
        why = (f"not every site acts on an alias of {object_reg}: "
               f"{[entry for entry in per_drop if not entry['aliased']]}")
        evidence = None
    return {
        "proved": proved,
        "evidence": evidence,
        "why": why,
        "alias": alias,
        "field_writes": writes,
        "shared_field_offsets": shared_fields,
        "sites": per_drop,
    }


def interprocedural_for(view, alias_regs: Iterable[str], callee_view_for, limit: int = 6) -> dict:
    """Reference transfers and return provenance across the calls this function makes.

    Kept apart from the local analysis on purpose: a local alias proof is about one function's
    own registers, and it must never be reported as an ownership transfer.  A transfer needs a
    tracked alias in an argument register *and* a callee that uses the argument as an object.

    Return provenance is a separate question again: whether a callee hands an object back in
    `rax` and whether *this* function passes it on can only be answered with the caller's
    context, which this function does not have.  It is recorded as unknown rather than guessed.
    """
    aliases = set(alias_regs)
    transfers: List[dict] = []
    calls_seen = 0
    for ins in view.ins:
        if ins.mnemonic != "call":
            continue
        calls_seen += 1
        if len(transfers) >= limit:
            break
        callee = (getattr(view, "calls", {}) or {}).get(ins.address)
        callee_view = callee_view_for(callee) if callee is not None else None
        if callee_view is None:
            continue
        verdict = prove_transfer(view, ins.address, callee_view, aliases)
        if verdict.get("proved"):
            transfers.append({"call_site": hex(ins.address), "callee": hex(callee),
                              "argument_register": verdict["argument_register"],
                              "evidence": verdict["evidence"]})
    if transfers:
        return {"proved": True, "transfers": transfers, "calls_seen": calls_seen,
                "return_provenance": {"verdict": "UNKNOWN",
                                      "why": "a returned object is passed on in the caller's "
                                             "context, which is not available here"},
                "evidence": "; ".join(entry["evidence"] for entry in transfers[:3])}
    return {"proved": False, "transfers": [], "calls_seen": calls_seen,
            "return_provenance": {"verdict": "UNKNOWN", "why": "no transfer to reason about"},
            "why": "no call in this function passes a tracked alias of the object in an "
                   "argument register to a callee that uses it"}


def _incomplete(why: str, basis: str = "") -> dict:
    """A record where neither the local nor the interprocedural question could be answered.

    Both halves are present and both say why: a caller reading only one of them must not see a
    missing key and mistake it for an absent problem.
    """
    local = {"proved": False, "why": why, "basis": basis, "sites": [],
             "shared_field_offsets": []}
    inter = {"proved": False, "why": why, "transfers": [],
             "return_provenance": {"verdict": "UNKNOWN", "why": why}}
    return {"local": local, "interprocedural": inter, "proved": False, "evidence": None,
            "why": why, "shared_field_offsets": []}


def analyse_finding(finding: dict, image, index,
                    release_targets: Optional[Iterable[int]] = None) -> dict:
    """Object-flow record for one finding, from the image rather than from a claim.

    The function's drops come from `handles.release_shape`, the field writes from the repaired
    `handles.summarize(...).stores` summary, and the identity question is answered by
    :func:`object_flow_for_drops`.  When the function has fewer than two sites acting on the
    object there is no identity question to answer, and that is recorded as such instead of
    being scored as a proof.
    """
    from . import handles, patterns

    rva = int(str(finding["function"]["rva"]), 16)
    try:
        summary = handles.summarize(image, rva, MAX_FUNCTION_BYTES)
    except Exception as exc:
        return _incomplete(f"the function could not be summarised: {type(exc).__name__}: {exc}")
    try:
        view = patterns.FunctionView(image, rva, MAX_FUNCTION_BYTES)
    except Exception as exc:
        return _incomplete(f"the function could not be decoded: {type(exc).__name__}: {exc}")
    anchors = {int(target) for target in (release_targets or [])}
    if not anchors:
        # Without a release anchor every call looks like "not a release" and the analysis
        # silently reports "no drop site" -- a confident wrong answer.
        return _incomplete("no release anchor was supplied; a drop site cannot be recognised "
                          "without knowing which callee releases the reference")
    shape = handles.release_shape(view, lambda target: target in anchors)
    drops = list(getattr(shape, "drops", []) or [])
    if not drops:
        return _incomplete("no refcount-drop site was found in this function, so there is no "
                          "object identity to prove")
    object_reg = drops[0].obj_reg
    sites = [{"site": hex(drop.site), "object_register": drop.obj_reg,
              "release_site": hex(drop.release_site), "field": hex(drop.offset)}
             for drop in drops]
    local = object_flow_for_drops(view, sites, object_reg, stores=summary.stores)
    local["drops"] = len(drops)
    local["guarded_drops"] = sum(1 for drop in drops if drop.guarded)

    def callee_view_for(target_rva):
        if target_rva is None or int(target_rva) not in index:
            return None
        try:
            return patterns.FunctionView(image, int(target_rva), MAX_FUNCTION_BYTES)
        except Exception:
            return None

    inter = interprocedural_for(view, local.get("alias", {}).get("regs") or [object_reg],
                               callee_view_for)
    return {"local": local, "interprocedural": inter,
            # Flat mirrors keep older callers working without pretending the two are the same.
            "proved": local.get("proved", False),
            "evidence": local.get("evidence"),
            "why": local.get("why"),
            "shared_field_offsets": local.get("shared_field_offsets", [])}
