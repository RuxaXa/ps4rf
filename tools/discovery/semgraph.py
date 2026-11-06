"""Semantic primitive graph (S1.3): object identities, reference operations, locks,
entries -- joined only where the binary proves the join.

Design rule: **no edge without a witness**.  Every edge carries the instruction (or the
decoded table) that establishes it.  Two functions being "similar", living in the same
subsystem or touching the same struct layout never creates an edge on its own; that is the
difference between a graph that can support a chain argument and one that only repeats the
detector's own guess.

Node kinds
    function:<rva>          function carrier
    entry:<label>           reachable entry point (syscall / cdevsw / dispatch table)
    object:<fn>:<reg>       object acquired inside a function
    lock:<fn>:<site>        lock site (lock scope findings)

Edge kinds, all evidence bearing
    reaches                     entry -> function (entry attribution record)
    calls, tail-jumps           control flow, witness = the instruction
    acquires-object             function -> object (acquire call)
    drops-reference             function -> object (negative refcount update)
    takes-reference             function -> object (positive refcount update)
    guards-drop                 object -> function (conditional / unconditional)
    releases-object             object -> function (release call)
    decides-identity            function -> function (handle|object domain)
    transfers-reference         function -> function (object register becomes an argument
                                of a callee that drops a reference)
    cross-subsystem             control-flow edge whose endpoints sit in different
                                subsystems -- derived, never asserted on its own
"""
from __future__ import annotations

from dataclasses import asdict, is_dataclass
import json
from collections import Counter
from typing import Dict, List, Optional, Tuple

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

CONTROL_FLOW = ("calls", "tail-jumps")

#: System V argument registers, in order.  An object that is "handed to" a callee has
#: to appear in one of these at the call site; naming a register that the call never
#: receives is how a plausible-looking ownership edge appears with no provenance.
ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")

#: Bounds for the entry-rooted expansion.  A scan may not turn into an unbounded
#: whole-image decode, so the expansion stops at a fixed function budget and says so.
MAX_EXPANDED_FUNCTIONS = 96
MAX_EXPANSION_DEPTH = 2
#: Whole-program mode (A1-07): seed the walk from every function the scan actually
#: analysed instead of from the finding functions only, so a route that passes through a
#: function without a finding exists in the graph.  The budget is larger but still finite,
#: and the graph publishes it: an unbounded walk over a 4000-function image would decode
#: the whole text section and then claim coverage it cannot show.
MAX_WHOLE_PROGRAM_FUNCTIONS = 2000
MAX_WHOLE_PROGRAM_DEPTH = 64

# hop status vocabulary for chain reasoning
PROVED = "proved"
POSSIBLE = "possible"
UNKNOWN = "unknown"
REFUTED = "refuted"
STATUS_ORDER = {PROVED: 0, POSSIBLE: 1, UNKNOWN: 2, REFUTED: 3}


def _witness(site, kind: str, text: str) -> dict:
    return {"site": site, "kind": kind, "text": text}


class Graph:
    """Deterministic node/edge container."""

    def __init__(self) -> None:
        self.nodes: Dict[str, dict] = {}
        self.edges: List[dict] = []
        self._keys = set()      # exact evidence records
        self._by_site = {}      # one structural edge per source/destination/kind/site
        self._observations = {} # all distinct witnesses for each structural edge

    def node(self, nid: str, kind: str, **attrs) -> str:
        cur = self.nodes.get(nid)
        if cur is None:
            self.nodes[nid] = dict(attrs, id=nid, kind=kind)
            return nid
        for key, value in attrs.items():
            if value is not None and cur.get(key) in (None, "", [], {}):
                cur[key] = value
        if kind == "function":
            detectors = attrs.get("detectors") or []
            if detectors:
                cur["detectors"] = sorted(set(cur.get("detectors") or []) | set(detectors))
        return nid

    def edge(self, src: str, dst: str, kind: str, witness: dict, **attrs) -> bool:
        if not witness or not witness.get("site") or not witness.get("text"):
            raise AssertionError(f"edge {src}->{dst} ({kind}) has no witness")
        if kind == "transfers-reference" and attrs.get("status") == PROVED:
            # Proving caller placement alone does not identify callee's object.
            # Require both independently checkable witness halves.
            callee = attrs.get("callee_identity_witness")
            if (not attrs.get("argument_proven") or not isinstance(callee, dict)
                    or not callee.get("site") or not callee.get("text")):
                raise AssertionError("proved transfer requires a callee object-identity witness")
        # Structural graph edges must remain unique. Otherwise independent
        # detector findings at each hop can multiply path enumeration
        # exponentially. Preserve all evidence without duplicating the edge.
        structural = (src, dst, kind, str(witness["site"]))
        record = {"witness": dict(witness), "attrs": dict(attrs)}
        record_key = json.dumps([structural, record], sort_keys=True, default=str)
        if record_key in self._keys:
            return False
        self._keys.add(record_key)
        if structural not in self._by_site:
            edge = dict(attrs, src=src, dst=dst, kind=kind, witness=dict(witness))
            self._by_site[structural] = edge
            self._observations[structural] = [record]
            self.edges.append(edge)
            return True

        observations = self._observations[structural]
        observations.append(record)
        defaults = {"calls": PROVED, "tail-jumps": PROVED, "reaches": PROVED,
                    "transfers-reference": POSSIBLE}

        def rank(item):
            status = item["attrs"].get("status", defaults.get(kind, UNKNOWN))
            return (STATUS_ORDER.get(status, STATUS_ORDER[UNKNOWN]),
                    json.dumps(item, sort_keys=True, default=str))

        observations.sort(key=rank)
        preferred = observations[0]
        edge = self._by_site[structural]
        edge.clear()
        edge.update(preferred["attrs"])
        edge.update(src=src, dst=dst, kind=kind, witness=preferred["witness"],
                    evidence=list(observations))
        levels = {item["attrs"].get("status", defaults.get(kind, UNKNOWN))
                  for item in observations}
        if REFUTED in levels and (PROVED in levels or POSSIBLE in levels):
            edge["status"] = UNKNOWN
            edge["evidence_conflict"] = True
        return False

    def out_edges(self, nid: str, kinds: Optional[Iterable[str]] = None) -> List[dict]:
        wanted = set(kinds) if kinds else None
        return [e for e in self.edges
                if e["src"] == nid and (wanted is None or e["kind"] in wanted)]

    def in_edges(self, nid: str, kinds: Optional[Iterable[str]] = None) -> List[dict]:
        wanted = set(kinds) if kinds else None
        return [e for e in self.edges
                if e["dst"] == nid and (wanted is None or e["kind"] in wanted)]

    def export(self) -> dict:
        edges = sorted(self.edges, key=lambda e: (e["src"], e["kind"], e["dst"],
                                                  str(e["witness"]["site"]),
                                                  json.dumps(e, sort_keys=True, default=str)))
        edge_counts: Dict[str, int] = {}
        for edge in edges:
            edge_counts[edge["kind"]] = edge_counts.get(edge["kind"], 0) + 1
        node_counts: Dict[str, int] = {}
        for node in self.nodes.values():
            node_counts[node["kind"]] = node_counts.get(node["kind"], 0) + 1
        return {
            "schema": "ps4rf.discovery.semantic-graph/1",
            "nodes": [self.nodes[k] for k in sorted(self.nodes)],
            "edges": edges,
            "counts": {"nodes": node_counts, "edges": edge_counts},
        }


def _transfer_status(argument_placement_proven: bool) -> str:
    """Never call a release transfer PROVED from a caller-only witness.

    Proving that a register value enters a callee does not prove the callee
    drops that particular object. ReleaseShape.drops is local and has no
    argument-to-drop identity mapping, so PROVED cannot be produced here.
    """
    return POSSIBLE if argument_placement_proven else UNKNOWN


def _argument_carries(insns, call_site: int, obj_reg: str,
                      obj_load_site: Optional[int] = None) -> bool:
    """Conservative local argument-placement witness for an acquired object.

    Operand-text matching is not provenance: a field load through an object
    register does not yield the same object, and later argument overwrites
    invalidate earlier placements. Only a full-width register move or an
    identity LEA can establish this bounded local witness.

    This is not an interprocedural lifetime proof. Unknown indirect branches
    and aliases beyond the window stay UNKNOWN.
    """
    idx = next((pos for pos, ins in enumerate(insns)
                if ins.address == call_site), None)
    if idx is None:
        return False

    # Partial-register writes invalidate the corresponding 64-bit argument.
    # A sub-register write kills the *whole pointer identity*, even for
    # non-argument source registers (rbx/rbp/rsp).  In particular, 'mov ebx,'
    # zero-extends into rbx, while 'mov bl,' changes its low byte.
    aliases = {"edi": "rdi", "di": "rdi", "dil": "rdi",
               "esi": "rsi", "si": "rsi", "sil": "rsi",
               "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
               "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
               "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
               "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
               "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
               "esp": "rsp", "sp": "rsp", "spl": "rsp"}
    for num in (8, 9, 10, 11, 12, 13, 14, 15):
        aliases.update({f"r{num}d": f"r{num}",
                        f"r{num}w": f"r{num}",
                        f"r{num}b": f"r{num}"})

    def canonical(reg: str) -> str:
        return aliases.get(reg, reg)

    if canonical(obj_reg) != obj_reg:
        return False  # A partial pointer is not a full object identity.

    def target(ins) -> Optional[int]:
        if ins.operands and ins.operands[0].type == X86_OP_IMM:
            return int(ins.operands[0].imm)
        return None

    def writes(ins) -> set:
        try:
            _reads, regs = ins.regs_access()
            return {canonical(ins.reg_name(r)) for r in regs}
        except Exception:
            # Missing Capstone detail is not proof of register preservation.
            return set(ARG_REGS) | {obj_reg}

    clobbered = set()
    # At most 13 preceding instructions: no guessed long-range provenance.
    for back in range(idx - 1, max(-1, idx - 14), -1):
        ins = insns[back]
        mnemonic = ins.mnemonic.split()[-1].lower()
        if (mnemonic in ("call", "ret", "jmp") or mnemonic.startswith("j")
                or mnemonic.startswith("loop")):
            return False

        written_args = writes(ins) & set(ARG_REGS)
        if not written_args:
            continue
        # Include implicit and second-operand writes, e.g. xchg.
        eligible = written_args - clobbered
        clobbered.update(written_args)
        if not eligible or not ins.operands or ins.operands[0].type != X86_OP_REG:
            continue
        dst = ins.reg_name(ins.operands[0].reg)
        arg = canonical(dst)
        if arg not in eligible:
            continue
        if dst != arg or len(ins.operands) < 2:
            continue  # Partial-width assignment truncates/changes pointer.

        src = ins.operands[1]
        carries = (mnemonic in ("mov", "movabs") and src.type == X86_OP_REG
                   and ins.reg_name(src.reg) == obj_reg)
        if mnemonic == "lea" and src.type == X86_OP_MEM:
            # Interior and indexed addresses do NOT prove identical objects.
            carries = (ins.reg_name(src.mem.base) == obj_reg
                       and not src.mem.index and src.mem.disp == 0)
        if not carries:
            continue

        if obj_load_site is not None:
            if not (obj_load_site <= ins.address < call_site):
                continue
            # Clobbers after acquisition and before placement destroy identity.
            for mid in insns:
                if not (obj_load_site < mid.address < ins.address):
                    continue
                if mid.mnemonic.split()[-1].lower() in ("call", "syscall"):
                    return False
                if obj_reg in writes(mid):
                    return False
            # A direct branch can skip acquisition but reach placement.
            if any(other.address < obj_load_site
                   and (other.mnemonic.split()[-1].lower().startswith("j")
                        or other.mnemonic.split()[-1].lower().startswith("loop"))
                   and (jump := target(other)) is not None
                   and obj_load_site < jump <= ins.address for other in insns):
                return False

        # A direct branch can skip the placement and reach the call.
        if any(other.address < ins.address
               and (other.mnemonic.split()[-1].lower().startswith("j")
                    or other.mnemonic.split()[-1].lower().startswith("loop"))
               and (jump := target(other)) is not None
               and ins.address < jump <= call_site for other in insns):
            return False
        return True
    return False

def build(scan: dict, handles_mod, image, index, ownership=None,
          entry_meta: Optional[Dict[str, int]] = None,
          whole_program: bool = False,
          function_budget: Optional[int] = None,
          depth_budget: Optional[int] = None) -> dict:
    """Build the semantic primitive graph for one ``cli scan`` artefact.

    ``ownership`` is the ownership catalog (or a plain callable) the detectors used, so
    object and reference edges are read exactly as the findings read them; without it the
    graph keeps only the control-flow and identity edges.
    """
    from .patterns import FunctionView

    g = Graph()
    catalog = handles_mod.HandleCatalog(image, index)
    subsystem: Dict[int, str] = {}
    entry_meta = entry_meta or {}
    shapes: Dict[int, object] = {}

    def view_of(rva: int):
        rec = index.get(rva) or index.containing(rva)
        size = max(rec.size, 1) if rec is not None else 0x400
        start = rva if index.get(rva) is None else rec.rva
        return FunctionView(image, start, size)

    is_release = None
    if ownership is not None:
        is_release = (ownership.is_release
                      if hasattr(ownership, "is_release") else ownership)

    def shape_of(rva: int):
        if rva in shapes:
            return shapes[rva]
        try:
            shapes[rva] = handles_mod.release_shape(view_of(rva), is_release) \
                if is_release else None
        except Exception:
            shapes[rva] = None
        return shapes[rva]

    def argument_carries(insns, call_site: int, obj_reg: str,
                         obj_load_site: Optional[int] = None) -> bool:
        return _argument_carries(insns, call_site, obj_reg, obj_load_site)

    for finding in scan.get("findings", []):
        func = finding["function"]
        rva = int(func["rva"], 16)
        label = finding.get("entry") or func.get("label") or f"func:{func['rva']}"
        sub = finding.get("subsystem") or "unknown"
        subsystem.setdefault(rva, sub)
        fid = g.node(f"function:{func['rva']}", "function", subsystem=sub, entry=label,
                     rank=finding.get("rank"), detectors=[finding["detector"]])
        meta = entry_meta.get(label) or {}
        # Authorization evidence travels with the entry node so the chain composer
        # reads it from the graph instead of re-deriving "a syscall reaches it" as
        # if that were permission.  No production path invents this dict yet.
        eid = g.node(f"entry:{label}", "entry", subsystem=sub,
                     entry_kind=meta.get("kind"),
                     narg=meta.get("narg"),
                     node_mode=meta.get("mode"),
                     authorization=meta.get("authorization"))
        handler = meta.get("handler_rva")
        chain = meta.get("chain") or []
        direct = func["rva"] == handler or func["rva"] in chain
        site = meta.get("site") or func.get("entry_site") or func["rva"]
        if handler:
            text = (f"{label}.sy_call -> {handler}; wrapper chain {chain}; "
                    f"scanner reachability depth {func.get('depth')}")
        else:
            text = (f"{label} structural-entry attribution; scanner reachability "
                    f"depth {func.get('depth')}")
        # The scan artefact keeps the entry table and minimum depth, but not every
        # predecessor instruction.  Only a target that is the handler/wrapper chain is
        # proved here; all deeper attributions remain possible instead of silently
        # becoming a proved chain edge.
        g.edge(eid, fid, "reaches", _witness(site, "entry-table", text),
               detector=finding["detector"], status=PROVED if direct else POSSIBLE,
               candidates=finding.get("entry_candidates") or [label])

        try:
            insns = view_of(rva).ins
        except Exception:
            insns = []
        for ins in insns:
            if ins.mnemonic not in ("call", "jmp"):
                continue
            try:
                tgt = int(ins.op_str, 16)
            except Exception:
                continue
            rec = index.containing(tgt)
            if rec is None or (ins.mnemonic == "jmp" and rec.rva == rva):
                continue
            tid = g.node(f"function:{hex(rec.rva)}", "function", subsystem=subsystem.get(rec.rva))
            kind = "calls" if ins.mnemonic == "call" else "tail-jumps"
            g.edge(fid, tid, kind,
                   _witness(hex(ins.address), kind, f"{ins.mnemonic} {hex(rec.rva)}"),
                   detector=finding["detector"])

        shape = shape_of(rva)
        objects: Dict[str, str] = {}
        if shape is not None:
            for acq in shape.acquires:
                oid = g.node(f"object:{func['rva']}:{acq.obj_reg}", "object",
                             register=acq.obj_reg, slot=acq.slot, function=func["rva"],
                             subsystem=sub)
                objects[acq.obj_reg] = oid
                g.edge(fid, oid, "acquires-object",
                       _witness(hex(acq.site), "acquire-call", f"call {hex(acq.target)}"),
                       detector=finding["detector"])
            for take in shape.takes:
                oid = objects.get(take.obj_reg)
                if oid:
                    g.edge(fid, oid, "takes-reference",
                           _witness(hex(take.site), "refcount-increment",
                                    f"positive refcount update on +{hex(take.offset)}"),
                           detector=finding["detector"])
            for drop in shape.drops:
                oid = objects.get(drop.obj_reg)
                if not oid:
                    continue
                g.edge(fid, oid, "drops-reference",
                       _witness(hex(drop.site), "refcount-decrement",
                                f"negative refcount update on +{hex(drop.offset)}"),
                       detector=finding["detector"])
                g.edge(oid, fid, "guards-drop",
                       _witness(hex(drop.site),
                                "conditional" if drop.guarded else "unconditional",
                                "decrement sits behind an ==1 test" if drop.guarded
                                else "decrement executes unconditionally"),
                       detector=finding["detector"])
                tid = g.node(f"function:{hex(drop.release_target)}", "function",
                             subsystem=subsystem.get(drop.release_target))
                g.edge(oid, tid, "releases-object",
                       _witness(hex(drop.release_site), "release-call",
                                f"release call {hex(drop.release_target)}"),
                       detector=finding["detector"])
            # reference transfer into a callee that itself drops a reference
            call_sites = {}
            for ins in insns:
                if ins.mnemonic != "call":
                    continue
                try:
                    tgt = int(ins.op_str, 16)
                except Exception:
                    continue
                call_sites[ins.address] = tgt
            for site, tgt in sorted(call_sites.items()):
                callee = shape_of(tgt)
                if callee is None or not getattr(callee, "drops", None):
                    continue
                for acq in shape.acquires:
                    if acq.site == site:
                        continue
                    tid = g.node(f"function:{hex(tgt)}", "function",
                                 subsystem=subsystem.get(tgt))
                    oid = objects.get(acq.obj_reg)
                    if oid is None:
                        continue
                    # The call-site placement is only HALF of an ownership
                    # transfer: ReleaseShape tells us the callee drops *some*
                    # reference, not that its drop consumes the passed argument.
                    # It may dereference an unrelated global, a different argument,
                    # or overwrite the register before the drop. Keep this hop
                    # possible until a callee-side identity/lifetime witness exists.
                    placement_proven = argument_carries(
                        insns, site, acq.obj_reg, acq.obj_load)
                    status = _transfer_status(placement_proven)
                    text = (f"{acq.obj_reg} reaches an argument register of "
                            f"{hex(tgt)} at {hex(site)}, but the callee's drop "
                            f"has not been tied to that argument"
                            if placement_proven else
                            f"{hex(tgt)} drops a reference, but no argument register "
                            f"is proven to receive {acq.obj_reg} at {hex(site)}")
                    g.edge(fid, tid, "transfers-reference",
                           _witness(hex(site), "argument-placement-only"
                                    if placement_proven else "argument-passing-unproven", text),
                           detector=finding["detector"],
                           status=status,
                           argument_proven=placement_proven,
                           callee_identity_proven=False)

        claims = finding.get("claims") or {}
        target = claims.get("decision_target")
        domain = claims.get("decision_domain")
        if target and domain:
            tid = g.node(f"function:{target}", "function",
                         subsystem=subsystem.get(int(target, 16)))
            text = ("caller supplied value compared against the 4-byte handle field"
                    if domain == "handle" else
                    "comparison against the 8-byte object pointer")
            g.edge(fid, tid, "decides-identity",
                   _witness(claims.get("decision_call_site") or claims.get("decision_site")
                            or func["rva"], f"identity-{domain}", text),
                   domain=domain, detector=finding["detector"])

    # ---------------------------------------------------------------- expansion
    # The graph used to hold control-flow edges only for functions that carried a
    # finding, so a real two-hop path through a function without a finding simply
    # did not exist and multi-hop reconstruction under-reported.  Expand the
    # call graph outward from the finding functions under an explicit budget, and
    # publish the budget and the truncation reason with the graph.
    expanded: List[int] = []
    truncated = False
    truncated_reason = ""
    queue: List[tuple] = []
    seen: set = set()
    # The budgets are parameters, not constants, so that the seeding effect and the budget
    # effect can be measured separately: comparing 96/finding-centred against 2000/whole-program
    # mixes two changes and would credit both to the seeding.
    if function_budget is None:
        function_budget = MAX_WHOLE_PROGRAM_FUNCTIONS if whole_program else MAX_EXPANDED_FUNCTIONS
    if depth_budget is None:
        depth_budget = MAX_WHOLE_PROGRAM_DEPTH if whole_program else MAX_EXPANSION_DEPTH
    if whole_program:
        roots = sorted({int(rva_hex, 16) for rva_hex in (scan.get("scanned_rvas") or [])
                        if isinstance(rva_hex, str) and rva_hex.startswith("0x")})
        # Truncating by ascending address is arbitrary about relevance: on FW 13.52 it dropped
        # two syscall handlers simply because they live at the top of the text section. Seed in
        # priority order instead -- resolved entry handlers, then functions carrying a finding,
        # then everything else -- so a budget that bites loses the least interesting roots.
        handlers = {int(meta["handler_rva"], 16)
                    for meta in (entry_meta or {}).values()
                    if isinstance(meta.get("handler_rva"), str)
                    and meta["handler_rva"].startswith("0x")}
        finding_rvas = {int(nid.split(":", 1)[1], 16) for nid in g.nodes
                        if nid.startswith("function:")}
        roots = sorted(roots, key=lambda rva: (0 if rva in handlers
                                               else 1 if rva in finding_rvas else 2, rva))
        if not roots:
            # No scanned list in the artefact: say so instead of silently falling back,
            # because a whole-program graph over the findings is not a whole-program graph.
            truncated = True
            truncated_reason = "the scan artefact lists no scanned_rvas; whole-program mode had no roots"
    else:
        roots = sorted({int(nid.split(":", 1)[1], 16) for nid in g.nodes
                        if nid.startswith("function:")})
    seeded_roots: List[int] = []
    dropped_roots: List[int] = []
    for rva in roots:
        # Count what was seeded, not what was expanded: a root whose body fails to decode
        # never reaches `expanded`, and the budget must still bite on the seeding.
        if len(queue) >= function_budget:
            truncated = True
            truncated_reason = f"function budget {function_budget} reached"
            dropped_roots = [r for r in roots if r not in set(seeded_roots)]
            break
        queue.append((rva, 0))
        seeded_roots.append(rva)
    while queue:
        rva, depth_from_finding = queue.pop(0)
        if rva in seen:
            continue
        seen.add(rva)
        if depth_from_finding > depth_budget:
            truncated = True
            truncated_reason = f"depth budget {depth_budget} reached"
            continue
        if len(expanded) >= function_budget:
            truncated = True
            truncated_reason = f"function budget {function_budget} reached"
            break
        fid = g.node(f"function:{hex(rva)}", "function", subsystem=subsystem.get(rva))
        if g.out_edges(fid, CONTROL_FLOW):
            continue                      # already decoded with a witness
        try:
            extra = view_of(rva).ins
        except Exception:
            continue
        expanded.append(rva)
        for ins in extra:
            if ins.mnemonic not in ("call", "jmp"):
                continue
            try:
                tgt = int(ins.op_str, 16)
            except Exception:
                continue
            rec = index.containing(tgt)
            if rec is None or (ins.mnemonic == "jmp" and rec.rva == rva):
                continue
            kind = "calls" if ins.mnemonic == "call" else "tail-jumps"
            tid = g.node(f"function:{hex(rec.rva)}", "function",
                         subsystem=subsystem.get(rec.rva))
            g.edge(fid, tid, kind,
                   _witness(hex(ins.address), kind, f"{ins.mnemonic} {hex(rec.rva)}"))
            queue.append((rec.rva, depth_from_finding + 1))

    for edge in list(g.edges):
        if edge["kind"] not in CONTROL_FLOW:
            continue
        src, dst = g.nodes[edge["src"]], g.nodes[edge["dst"]]
        if src.get("subsystem") and dst.get("subsystem") \
                and src["subsystem"] != dst["subsystem"]:
            g.edge(edge["src"], edge["dst"], "cross-subsystem", edge["witness"],
                   detector=edge.get("detector"), from_subsystem=src["subsystem"],
                   to_subsystem=dst["subsystem"])
    doc = g.export()
    doc["expansion"] = {
        "mode": "whole-program" if whole_program else "finding-centred",
        "roots": len(roots),
        "root_source": "scanned_rvas" if whole_program else "finding-functions",
        "root_priority": ("entry-handlers, then finding-functions, then the rest"
                          if whole_program else "finding-functions only"),
        "expanded_functions": len(expanded),
        "function_budget": function_budget,
        "depth_budget": depth_budget,
        "truncated": truncated,
        "truncated_reason": truncated_reason,
        "roots_requested": len(roots),
        "roots_seeded": len(seeded_roots),
        "roots_dropped_count": len(dropped_roots),
        # The dropped list is published so that "which roots the budget left out" is a
        # question about data, not an assumption that they were unimportant.
        "roots_dropped": [hex(rva) for rva in dropped_roots[:256]],
        "control_flow_edges": len([e for e in doc["edges"]
                                   if e["kind"] in CONTROL_FLOW]),
    }
    return doc


def check_evidence(graph: dict) -> List[str]:
    """Every edge must carry a site and a text.  Returns the violations."""
    bad = []
    for edge in graph.get("edges", []):
        w = edge.get("witness") or {}
        if not w.get("site") or not w.get("text"):
            bad.append(f"{edge['src']}->{edge['dst']}:{edge['kind']}")
    return bad


MAX_CHAIN_DEPTH = 6
MAX_PATH_EXPANSIONS = 20000
MAX_PATH_ALTERNATIVES = 4


def _hop(edge: dict, nodes: Dict[str, dict]) -> dict:
    src_node = nodes.get(edge["src"], {})
    dst_node = nodes.get(edge["dst"], {})
    crosses = (bool(src_node.get("subsystem"))
               and bool(dst_node.get("subsystem"))
               and src_node.get("subsystem") != dst_node.get("subsystem"))
    hop = {"from": edge["src"], "to": edge["dst"], "kind": edge["kind"],
           "status": edge.get("status", UNKNOWN),
           "witness": edge["witness"],
           "detector": edge.get("detector"),
           "cross_subsystem": crosses}
    if "evidence" in edge:
        hop["evidence"] = edge["evidence"]
    if edge.get("evidence_conflict"):
        hop["evidence_conflict"] = True
    return hop


def _path_key(hops: List[dict]) -> tuple:
    """Ordering rule for competing entry paths: strongest evidence, then shortest.

    A synthetic ``reaches`` summary hop carries ``possible``; a concrete two-hop
    proved path through real functions carries ``proved`` twice.  Sorting by hop
    count alone let the one-hop summary win and hid the proved path -- the audit's
    A1-01 counterexample -- so the evidence class is the primary key.
    """
    worst = max((STATUS_ORDER[hop["status"]] for hop in hops), default=STATUS_ORDER[UNKNOWN])
    return (worst, len(hops),
            tuple((hop["from"], hop["kind"], hop["to"]) for hop in hops))


def _entry_paths(start: str, by_dst: Dict[str, List[dict]], back_kinds: tuple,
                 max_depth: int = MAX_CHAIN_DEPTH,
                 budget: int = MAX_PATH_EXPANSIONS) -> tuple:
    """Find bounded entry paths, prioritizing evidence during exploration.

    A depth-first walk sorted only *after* exhausting its budget can report a
    weak path while missing a fully proved one solely due to edge ordering.
    Explore stronger paths first, then shorter paths, with deterministic ties.
    A truncated result is still incomplete, never a proof of path absence.
    """
    from heapq import heappop, heappush
    from itertools import count

    defaults = {"calls": PROVED, "tail-jumps": PROVED, "reaches": PROVED,
                "transfers-reference": POSSIBLE}

    def strength(edge: dict) -> int:
        status = edge.get("status", defaults.get(edge["kind"], UNKNOWN))
        return STATUS_ORDER.get(status, STATUS_ORDER[UNKNOWN])

    def edge_key(edge: dict) -> tuple:
        witness = edge.get("witness") or {}
        return (edge["src"], edge["kind"], edge["dst"],
                str(witness.get("site", "")),
                str(edge.get("status", "")), str(witness.get("text", "")))

    paths: List[List[dict]] = []
    serial = count()
    # Queue priority: weakest hop on the trail, depth, stable edge signatures.
    frontier = [(STATUS_ORDER[PROVED], 0, (), next(serial),
                 start, (), frozenset((start,)))]
    expansions = 0
    truncated = False
    while frontier:
        if expansions >= budget:
            truncated = True
            break
        worst, depth, signature, _, node, trail, visited = heappop(frontier)
        expansions += 1
        if trail and node.startswith("entry:"):
            paths.append(list(reversed(trail)))
            continue
        if depth >= max_depth:
            truncated = True
            continue
        for edge in sorted(by_dst.get(node, []), key=edge_key):
            if edge["kind"] not in back_kinds or edge["src"] in visited:
                continue
            heappush(frontier, (max(worst, strength(edge)), depth + 1,
                                signature + (edge_key(edge),), next(serial),
                                edge["src"], trail + (edge,),
                                visited | {edge["src"]}))

    def path_key(path: List[dict]) -> tuple:
        return (max((strength(edge) for edge in path),
                    default=STATUS_ORDER[UNKNOWN]), len(path),
                tuple(edge_key(edge) for edge in reversed(path)))

    paths.sort(key=path_key)
    return paths, truncated


def chains(graph: dict, scan: dict, facts: dict, chains_mod=None, limit: int = 200,
           object_flow: Optional[Dict[str, dict]] = None) -> dict:
    """Entry-rooted chains from defect primitives, with every hop classified.

    For each primitive every entry-rooted reverse path is enumerated and ranked by
    evidence first (proved before possible before unknown), then by length.  The
    chosen path is reported with the witness of every hop; the runner-up paths are
    reported beside it instead of being dropped, because "which route was taken"
    is exactly the question a chain artefact has to answer.

    A hop is *proved* when a witnessed control-flow or entry edge carries it,
    *possible* when the edge exists but the target is ambiguous, *unknown* when the
    walk runs out of graph.  Missing requirements are never assumed to hold.
    """
    nodes = {n["id"]: n for n in graph["nodes"]}
    by_dst: Dict[str, List[dict]] = {}
    for edge in graph["edges"]:
        by_dst.setdefault(edge["dst"], []).append(edge)
    back_kinds = ("calls", "tail-jumps", "reaches", "transfers-reference")
    status_of = {"calls": PROVED, "tail-jumps": PROVED, "reaches": PROVED,
                 "transfers-reference": POSSIBLE}

    def with_status(edge: dict) -> dict:
        hop = _hop(edge, nodes)
        hop["status"] = edge.get("status", status_of.get(edge["kind"], UNKNOWN))
        return hop

    primitives = [f for f in scan.get("findings", []) if f.get("rank", 9) <= 2]
    out, seen = [], set()
    for finding in primitives:
        start = f"function:{finding['function']['rva']}"
        if start not in nodes:
            continue
        raw_paths, truncated = _entry_paths(start, by_dst, back_kinds)
        candidates = [[with_status(edge) for edge in path] for path in raw_paths]
        candidates.sort(key=_path_key)
        candidate_keys = {_path_key(hops_) for hops_ in candidates}
        chosen = candidates[0] if candidates else []
        found = chosen[0]["from"] if chosen else None
        hops = chosen
        statuses = [h["status"] for h in hops]
        worst = max(statuses, key=lambda x: STATUS_ORDER[x]) if statuses else UNKNOWN
        key = (finding["detector"], finding["function"]["rva"], found)
        if key in seen:
            continue
        seen.add(key)
        alternatives = []
        for hops_alt in candidates[1:MAX_PATH_ALTERNATIVES]:
            statuses_alt = [h["status"] for h in hops_alt]
            alternatives.append({
                "entry": hops_alt[0]["from"],
                "hop_status": max(statuses_alt, key=lambda x: STATUS_ORDER[x]),
                "hop_count": len(hops_alt),
                "cross_subsystem": sum(1 for h in hops_alt if h.get("cross_subsystem")),
                "hops": [{"from": h["from"], "to": h["to"], "kind": h["kind"],
                          "status": h["status"], "witness": h["witness"]}
                         for h in hops_alt],
            })
        chain = {
            "primitive": {"detector": finding["detector"], "rank": finding.get("rank"),
                          "function": finding["function"]["rva"],
                          "bug_class": finding.get("bug_class")},
            "entry": found,
            "hops": hops,
            "hop_status": worst,
            "hop_count": len(hops),
            "proved_hops": statuses.count(PROVED),
            "cross_subsystem": sum(1 for h in hops if h.get("cross_subsystem")),
            "path_selection": {
                "rule": "strongest evidence first (proved < possible < unknown), "
                        "then fewest hops",
                "paths_considered": len(candidate_keys),
                "distinct_paths": len(candidate_keys),
                "truncated": truncated,
                "alternatives": alternatives,
            },
        }
        if chains_mod is not None:
            try:
                entry_node = nodes.get(found or "", {})
                entry_evidence = {
                    "authorization": entry_node.get("authorization"),
                    "kind": entry_node.get("entry_kind"),
                    "narg": entry_node.get("narg"),
                    "node_mode": entry_node.get("node_mode"),
                }
                finding = dict(finding)
                if object_flow:
                    flow = object_flow.get(str(finding["function"]["rva"]))
                    if flow:
                        finding["object_flow"] = flow
                composed = chains_mod.compose(
                    finding, found or "", facts,
                    entry_kind=entry_node.get("entry_kind") or "",
                    entry_proved=bool(hops) and all(s == PROVED for s in statuses),
                    entry_evidence=entry_evidence)
                # `as_dict()` is the published shape and carries `next_obligation`;
                # `dataclasses.asdict` silently drops it, which is how an artefact can look
                # like it has no open obligation at all.
                chain["requirements"] = (composed.as_dict()
                                         if hasattr(composed, "as_dict") else composed)
            except Exception as exc:
                chain["requirements"] = {"error": f"{type(exc).__name__}: {exc}"}
        out.append(chain)
    out.sort(key=lambda c: (c["hop_status"] != PROVED, c["hop_count"],
                            str(c["primitive"]["function"])))
    # The held-back family may sit below the first 400 candidates.  Truncating here
    # silently turns "not exported" into "blind recall zero", so the artefact always
    # contains the complete, deduplicated candidate set.  Presentation may apply its
    # own limit later.
    levels = Counter()
    for chain in out:
        requirements = chain.get("requirements") or {}
        levels[requirements.get("proof_level") or "NOT-COMPOSED"] += 1
    return {"schema": "ps4rf.discovery.chains/1", "chains": out,
            "counts": {"chains": len(out), "shown": len(out),
                       "entry_rooted": sum(1 for c in out if c["entry"]),
                       "proof_levels": dict(levels)}}
