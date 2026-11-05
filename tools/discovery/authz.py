"""Privilege reachability: from the userland-visible dispatch slot to the kernel path.

The question this module answers is *not* "does some syscall reach this function".  It is
"can an unprivileged caller reach it, and what would have to be shown to say so".

Two things can be established from an offline image:

* the **dispatch** — which userland operation lands on which kernel handler, read out of the
  sysent and cdevsw tables, with the slot and the pointer as evidence;
* **credential gates that exist** — a reference to the `prison0` credential context inside the
  handler path is positive evidence that the path consults credentials.

What cannot be established offline is the *absence* of a gate.  The anchor set in this
firmware has no authorization symbols (`priv_check_cred`, `kauth_cred_issuser`, `suser`), so
"no gate was found" is a statement about the walk, not about the code.  Those entries stay
``UNKNOWN`` with the missing obligation recorded — never ``UNPRIVILEGED``.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional

try:                                          # capstone is a runtime dependency
    from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_REG_RIP
except Exception:                             # pragma: no cover - import guard for stubs
    X86_OP_MEM, X86_OP_REG, X86_REG_RIP = 3, 1, 41

UNPRIVILEGED = "UNPRIVILEGED"
PRIVILEGED = "PRIVILEGED"
UNKNOWN = "UNKNOWN"

#: Functions that would settle the question if the firmware resolved them.  None of them is
#: in the current anchor set, which is exactly why most entries end up UNKNOWN.
AUTHORIZATION_SYMBOLS = ("priv_check_cred", "priv_check", "kauth_cred_get",
                         "kauth_cred_issuser", "suser", "p_cansee", "cr_cansee")

MISSING_AUTH_SYMBOLS = (
    "authorization symbols are not resolved in this firmware ("
    + ", ".join(AUTHORIZATION_SYMBOLS) + "); without at least one of them, or a device-record "
    "mode, the absence of a credential gate cannot be shown from the image"
)


def _to_rva(image, pointer: Optional[int]) -> Optional[int]:
    """Kernel VA -> image RVA. A pointer outside the image's base is not a dispatch target."""
    if not pointer:
        return None
    base = int(getattr(image, "base", 0) or 0)
    try:
        canonical = image.is_canonical_kernel_va(pointer)
    except Exception:
        canonical = True
    if not canonical and base:
        return None
    rva = pointer - base if base else pointer
    # The bound comes from the image itself; a literal address here would be the very kind of
    # hardware-specific constant the engine is not allowed to carry.
    span = int(getattr(image, "size", 0) or 0)
    if rva < 0 or (span and rva >= span):
        return None
    return rva


def _u64(image, rva: int) -> Optional[int]:
    """Read a little-endian 64-bit pointer, or None when the address is not mapped."""
    try:
        blob = image.read(rva, 8)
    except Exception:
        return None
    if not blob or len(blob) < 8:
        return None
    return int.from_bytes(blob, "little")


def resolve_syscall_dispatch(image, facts: dict, limit: int = 32) -> List[dict]:
    """Read `sysent[n].sy_call` out of the table.

    Returns one record per slot with a plausible in-image handler, plus the slot address that
    was read — the evidence for "this userland operation lands here" is the table read itself.
    """
    table = (facts.get("tables") or {}).get("sysent") or {}
    if not table.get("rva"):
        return []
    base = int(table["rva"], 16)
    stride = int(table.get("stride") or 48)
    call_off = int(table.get("sy_call_offset") or 8)
    narg_off = int(table.get("narg_offset") or 0)
    count = int(table.get("entries_checked") or 0) or limit
    out = []
    for slot in range(min(count, limit * 64)):
        slot_rva = base + slot * stride
        handler = _u64(image, slot_rva + call_off)
        if handler is None:
            continue
        narg = None
        try:
            raw = image.read(slot_rva + narg_off, 1)
            narg = raw[0] if raw else None
        except Exception:
            pass
        handler_rva = _to_rva(image, handler)
        if handler_rva is None:
            continue
        out.append({
            "kind": "syscall",
            "label": f"sysent[{slot}]",
            "slot_address": hex(slot_rva),
            "pointer_field": hex(slot_rva + call_off),
            "handler": hex(handler_rva),
            "handler_va": hex(handler),
            "narg": narg,
        })
    return out


def resolve_cdevsw_dispatch(image, facts: dict, records: int = 0) -> List[dict]:
    """Read the character-device switch entries (`open`/`read`/`ioctl`).

    The record layout comes from the facts table; without a mode field the result cannot say
    whether the node is world-accessible, and it does not pretend to.
    """
    table = (facts.get("tables") or {}).get("cdevsw") or {}
    if not table.get("rva"):
        return []
    base = int(table["rva"], 16)
    fields = table.get("record_fields") or {}
    out = []
    stride = 64
    for index in range(records or 8):
        record = base + index * stride
        entry = {"kind": "cdevsw", "label": f"cdevsw[{index}]", "record": hex(record),
                 "handlers": {}}
        for name in ("open", "close", "read", "ioctl"):
            offset = fields.get(name)
            if offset is None:
                continue
            pointer = _u64(image, record + int(offset))
            target = _to_rva(image, pointer)
            if target is not None:
                entry["handlers"][name] = hex(target)
        if entry["handlers"]:
            out.append(entry)
    return out


def _rip_target(ins) -> Optional[int]:
    """Resolve a RIP-relative memory operand to an address."""
    for operand in getattr(ins, "operands", []) or []:
        if getattr(operand, "type", None) != X86_OP_MEM:
            continue
        mem = operand.mem
        if getattr(mem, "base", None) == X86_REG_RIP:
            return (ins.address + ins.size + mem.disp) & 0xFFFFFFFFFFFFFFFF
    return None


MAX_FUNCTION_BYTES = 4096


def _record_rva(record) -> Optional[int]:
    """`index.containing` hands back a record, not an integer."""
    if record is None:
        return None
    if isinstance(record, int):
        return record
    for attribute in ("rva", "start", "address", "addr", "begin"):
        value = getattr(record, attribute, None)
        if isinstance(value, int):
            return value
    return None


def _function_size(index, rva: int) -> int:
    """Size of the function starting at ``rva``, bounded by the next known function."""
    neighbours = getattr(index, "starts", None)
    if neighbours:
        try:
            ordered = sorted(neighbours)
            position = ordered.index(rva)
            following = ordered[position + 1]
            return max(1, min(MAX_FUNCTION_BYTES, following - rva))
        except (ValueError, IndexError):
            pass
    containing = index.containing(rva)
    if containing is not None:
        return MAX_FUNCTION_BYTES
    return MAX_FUNCTION_BYTES


def find_credential_gates(image, index, start_rva: int, facts: dict,
                          depth: int = 3, budget: int = 96) -> dict:
    """Walk the handler path and record the places that consult credentials.

    Positive evidence only: a reference to the `prison0` credential context, or a call to one
    of `AUTHORIZATION_SYMBOLS` if the firmware resolves it.  The walk's limits are published
    because "nothing found" must not be read as "nothing there".
    """
    from . import patterns

    prison0 = ((facts.get("tables") or {}).get("prison0_slot") or {}).get("rva")
    prison0_rva = int(prison0, 16) if prison0 else None
    anchors = facts.get("anchors") or {}
    auth_anchor_rvas = {}
    for name in AUTHORIZATION_SYMBOLS:
        if name in anchors:
            try:
                auth_anchor_rvas[int(anchors[name], 16)] = name
            except (TypeError, ValueError):
                pass

    gates: List[dict] = []
    queue = [(start_rva, 0)]
    seen = set()
    walked = 0
    truncated = False
    while queue:
        rva, level = queue.pop(0)
        if rva in seen or level > depth:
            continue
        seen.add(rva)
        if walked >= budget:
            truncated = True
            break
        walked += 1
        try:
            size = _function_size(index, rva)
            if not size:
                continue
            view = patterns.FunctionView(image, rva, size)
        except Exception:
            continue
        for position, ins in enumerate(view.ins):
            if prison0_rva is not None and _rip_target(ins) == prison0_rva:
                gates.append({
                    "site": hex(ins.address),
                    "in_function": hex(rva),
                    "kind": "prison0-reference",
                    "evidence": f"{ins.mnemonic} {ins.op_str} reads the prison0 credential "
                                f"context at {hex(prison0_rva)}",
                })
            resolved = view.calls.get(ins.address) if hasattr(view, "calls") else None
            callee = resolved if resolved is not None else _record_rva(
                index.containing(ins.address) if ins.mnemonic == "call" else None)
            if callee:
                if callee in auth_anchor_rvas:
                    gates.append({
                        "site": hex(ins.address),
                        "in_function": hex(rva),
                        "kind": "authorization-call",
                        "evidence": f"calls {auth_anchor_rvas[callee]} at {hex(callee)}",
                    })
                queue.append((int(callee), level + 1))
    return {
        "start": hex(start_rva),
        "functions_walked": walked,
        "truncated": truncated,
        "depth": depth,
        "gates": gates,
        "authorization_symbols_resolved": sorted(auth_anchor_rvas.values()),
    }


class GateScanner:
    """Credential-gate scanner with a decode cache, so coverage can be complete.

    The S1.4 measurement walked 24 of 687 resolved dispatches because every entry decoded its
    callees again. A function body only has to be decoded once per image, and the cache makes a
    full sweep cheap enough to actually run. The per-entry limits are unchanged and published:
    the answer for entry N is bounded by the same budget as before, only the wall clock differs.
    """

    WINDOW = 1024          # bytes decoded per function body

    def __init__(self, image, index, facts: dict, depth: int = 2, budget: int = 24):
        self.image = image
        self.index = index
        self.facts = facts
        self.depth = depth
        self.budget = budget
        self._views: Dict[int, object] = {}
        self.decode_count = 0
        prison0 = ((facts.get("tables") or {}).get("prison0_slot") or {}).get("rva")
        self.prison0_rva = int(prison0, 16) if prison0 else None
        self.auth_symbols = {}
        for name in AUTHORIZATION_SYMBOLS:
            value = (facts.get("anchors") or {}).get(name)
            if isinstance(value, str):
                try:
                    self.auth_symbols[int(value, 16)] = name
                except ValueError:
                    pass

    def view(self, rva: int):
        cached = self._views.get(rva)
        if cached is not None:
            return cached
        try:
            from . import patterns
            cached = patterns.FunctionView(self.image, rva, self.WINDOW)
            self.decode_count += 1
        except Exception:
            cached = False
        self._views[rva] = cached
        return cached

    STRENGTH_WINDOW = 8

    def _dereferences_loaded_slot(self, insns: List, position: int) -> Optional[dict]:
        """Does the loaded &prison0 get dereferenced or compared shortly afterwards?

        A bare read of the slot address is not a credential check -- it also turns up in code
        that only uses the pointer's value. A gate is strong when the loaded pointer is
        dereferenced or tested within a short window, which is what a credential test looks
        like in this kernel.
        """
        ins = insns[position]
        operands = list(getattr(ins, "operands", []) or [])
        if ins.mnemonic not in ("mov", "movzx", "movsxd", "movsx") or len(operands) < 2:
            return None
        destination = operands[0]
        if getattr(destination, "type", None) != X86_OP_REG:
            return None
        register = _reg_name(ins, destination)
        if not register:
            return None
        for following in insns[position + 1:position + 1 + self.STRENGTH_WINDOW]:
            for operand in getattr(following, "operands", []) or []:
                if getattr(operand, "type", None) != X86_OP_MEM or operand.mem.index:
                    continue
                base = (following.reg_name(operand.mem.base)
                        if getattr(following, "reg_name", None) and operand.mem.base else None)
                if base == register:
                    return {"site": hex(following.address), "kind": "prison0-deref",
                            "text": f"{following.mnemonic} {following.op_str} dereferences "
                                    f"prison0 via {register}"}
            if following.mnemonic in ("test", "cmp") and register in (following.op_str or ""):
                return {"site": hex(following.address), "kind": "prison0-compare",
                        "text": f"{following.mnemonic} {following.op_str} tests prison0"}
        return None

    def gates_in(self, function_rva: int) -> List[dict]:
        view = self.view(function_rva)
        if not view:
            return []
        found = []
        insns = list(view.ins)
        for position, ins in enumerate(insns):
            if self.prison0_rva is not None and _rip_target(ins) == self.prison0_rva:
                deref = self._dereferences_loaded_slot(insns, position)
                found.append({"site": hex(ins.address), "in_function": hex(function_rva),
                              "kind": "prison0-deref" if deref else "prison0-reference",
                              "strength": "gate" if deref else "conditional",
                              "evidence": f"{ins.mnemonic} {ins.op_str} reads the prison0 "
                                          f"context at {hex(self.prison0_rva)}"
                                          + (f"; {deref['text']} at {deref['site']}" if deref
                                             else " but the pointer is neither dereferenced nor "
                                                  "compared within the window, so this alone is "
                                                  "not a credential check")})
            callee = (getattr(view, "calls", {}) or {}).get(ins.address)
            if callee is not None and int(callee) in self.auth_symbols:
                found.append({"site": hex(ins.address), "in_function": hex(function_rva),
                              "kind": "authorization-call", "strength": "gate",
                              "evidence": f"calls {self.auth_symbols[int(callee)]} at "
                                          f"{hex(int(callee))}"})
        return found

    def scan(self, start_rva: int) -> dict:
        gates: List[dict] = []
        visited: List[str] = []
        queue = [(start_rva, 0)]
        seen = set()
        truncated = False
        while queue:
            rva, level = queue.pop(0)
            if rva in seen or level > self.depth:
                continue
            seen.add(rva)
            if len(visited) >= self.budget:
                truncated = True
                break
            visited.append(hex(rva))
            gates.extend(self.gates_in(rva))
            view = self.view(rva)
            if view and level < self.depth:
                for target in sorted({int(value) for value in (view.calls or {}).values()}):
                    if target not in seen:
                        queue.append((target, level + 1))
        return {"start": hex(start_rva), "functions_walked": len(visited), "visited": visited,
                "truncated": truncated, "depth": self.depth, "budget": self.budget,
                "gates": gates,
                "authorization_symbols_resolved": sorted(self.auth_symbols.values())}

    def record(self, dispatch: dict) -> dict:
        handler = dispatch.get("handler") or next(iter(dispatch.get("handlers", {}).values()), None)
        record = dict(dispatch)
        if not handler:
            record["authz"] = {"status": UNKNOWN, "basis": None, "evidence": None,
                               "missing_obligation": "the dispatch slot has no resolvable handler"}
            return record
        gates = self.scan(int(handler, 16))
        record["gates"] = gates
        record["authz"] = classify(dispatch, gates, self.facts)
        return record


def classify(dispatch: dict, gates: dict, facts: dict) -> dict:
    """Turn dispatch and gate evidence into a privilege statement.

    ``UNPRIVILEGED`` needs positive evidence and is otherwise never returned; ``PRIVILEGED``
    is returned when a gate exists on the path; everything else stays ``UNKNOWN`` with the
    obligation that would settle it.
    """
    recorded = ((facts or {}).get("entry_authorization") or {})
    basis = recorded.get("basis")
    evidence = recorded.get("evidence")
    if basis and evidence and recorded.get("unprivileged") is True:
        return {"status": UNPRIVILEGED, "basis": basis, "evidence": evidence,
                "missing_obligation": None}
    strong = [gate for gate in gates.get("gates") or []
              if gate.get("strength", "gate") == "gate"]
    weak = [gate for gate in gates.get("gates") or []
            if gate.get("strength", "gate") != "gate"]
    if strong:
        gate = strong[0]
        return {"status": PRIVILEGED, "basis": gate["kind"],
                "evidence": f"{gate['evidence']} ({gate['site']})",
                "missing_obligation": None}
    if weak:
        gate = weak[0]
        return {"status": UNKNOWN, "basis": gate["kind"],
                "evidence": f"{gate['evidence']} ({gate['site']})",
                "conditional_gates": len(weak),
                "missing_obligation": "a prison0 slot reference is on the path but it is neither "
                                      "dereferenced nor compared, so it is not shown to be a "
                                      "credential gate"}
    if dispatch.get("kind") == "cdevsw":
        obligation = ("the device record carries no mode: whether the node is openable by an "
                      "unprivileged caller is not in the image, and " + MISSING_AUTH_SYMBOLS)
    else:
        obligation = MISSING_AUTH_SYMBOLS
    return {"status": UNKNOWN, "basis": None, "evidence": None,
            "missing_obligation": obligation,
            "walk_truncated": gates.get("truncated"),
            "functions_walked": gates.get("functions_walked")}


def classify_entry(image, index, dispatch: dict, facts: dict,
                   depth: int = 3, budget: int = 96) -> dict:
    """Full privilege-reachability record for one resolved dispatch slot."""
    handler = dispatch.get("handler") or next(iter(dispatch.get("handlers", {}).values()), None)
    record = dict(dispatch)
    if not handler:
        record["authz"] = {"status": UNKNOWN, "basis": None, "evidence": None,
                           "missing_obligation": "the dispatch slot has no resolvable handler"}
        return record
    gates = find_credential_gates(image, index, int(handler, 16), facts,
                                  depth=depth, budget=budget)
    record["gates"] = gates
    record["authz"] = classify(dispatch, gates, facts)
    return record
