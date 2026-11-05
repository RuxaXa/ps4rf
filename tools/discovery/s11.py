"""Sprint 1.1 semantic-lock verification and reporting.

This module resolves the Lapse pair from a syscall table entry, recovers each
body from its tail-jump and CFG, builds a bounded call closure, and runs D3.  It
contains no firmware address, exploit name offset or expected verdict.
"""
from __future__ import annotations

import hashlib
import json
import resource
import time
import tracemalloc
from collections import deque
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .callee_match import call_profile, match_callees
from .entries import entry_chain
from .image import FunctionIndex, FunctionRecord, KernelImage
from .locks import SyncCatalog
from .lockscope import LockScope, compare_scope
from .patterns import FunctionView


@dataclass
class Extent:
    rva: int
    size: int
    blocks: int
    calls: tuple
    returns: tuple
    capped: bool
    errors: tuple = ()

    def as_dict(self) -> dict:
        return {"rva": hex(self.rva), "size": hex(self.size), "blocks": self.blocks,
                "calls": [hex(x) for x in self.calls],
                "returns": [hex(x) for x in self.returns], "capped": self.capped,
                "errors": list(self.errors)}


def discover_extent(image: KernelImage, rva: int, cap: int = 4608) -> Extent:
    """Recover the reachable CFG extent from a bounded disassembly window.

    Bytes after a reachable ``ret`` may contain the next function.  They are
    decoded so branch targets can be resolved, but are excluded by reachability.
    Reaching the cap without a return is explicit ``capped=True`` -- never a
    silent boundary guess.
    """
    available = max(0, int(image.size) - rva)
    span = min(cap, available)
    if span <= 0:
        return Extent(rva, 0, 0, (), (), True, ("rva outside image",))
    view = FunctionView(image, rva, span, strict_cfg=True)
    if not view.blocks:
        return Extent(rva, 0, 0, (), (), True, ("no decoded block",))
    entry = next(iter(view.blocks))
    reachable = set(view.reachable_blocks(entry))
    calls: Set[int] = set()
    returns = []
    hi = rva
    for block in reachable:
        hi = max(hi, view.blocks[block])
        for ins in view.ins_by.get(block, ()):
            if ins.mnemonic == "call":
                try:
                    calls.add(int(ins.op_str, 16))
                except ValueError:
                    pass
            if ins.mnemonic == "ret":
                returns.append(ins.address)
    capped = not returns or hi >= rva + span
    return Extent(rva, max(0, hi - rva), len(reachable), tuple(sorted(calls)),
                  tuple(sorted(returns)), capped)


def call_closure(image: KernelImage, roots: Sequence[int], depth: int = 2,
                 budget: int = 512, extent_cap: int = 4608) -> Tuple[FunctionIndex, dict]:
    """Bounded direct-call closure; every refusal/truncation is reported."""
    queue = deque((r, 0) for r in roots)
    seen: Dict[int, Extent] = {}
    refused = []
    ranges = image.executable_ranges()

    def executable(rva: int) -> bool:
        return any(lo <= rva < hi for lo, hi in ranges)

    while queue and len(seen) < budget:
        rva, level = queue.popleft()
        if rva in seen:
            continue
        if not executable(rva):
            refused.append({"rva": hex(rva), "reason": "outside executable ranges"})
            continue
        ext = discover_extent(image, rva, cap=extent_cap)
        seen[rva] = ext
        if level >= depth:
            continue
        for target in ext.calls:
            if target not in seen:
                queue.append((target, level + 1))
    if queue:
        refused.append({"reason": "function budget exhausted", "budget": budget,
                        "remaining_queue": len(queue)})
    records = [FunctionRecord(rva, max(ext.size, 1), "", "cfg-closure")
               for rva, ext in sorted(seen.items())]
    report = {
        "roots": [hex(x) for x in roots], "depth": depth, "budget": budget,
        "functions": len(records),
        "capped_functions": [hex(r) for r, e in seen.items() if e.capped],
        "refused": refused,
        "decoded_bytes": sum(e.size for e in seen.values()),
    }
    return FunctionIndex(records), report


def _anchors(facts: dict) -> Set[int]:
    """Release vocabulary from independently byte-verified anchor facts."""
    out = set()
    for name, value in (facts.get("anchors") or {}).items():
        low = name.lower()
        if low == "free" or "fdrop" in low or "release" in low:
            out.add(int(value, 16))
    return out


def _profile(image: KernelImage, rva: int, size: int) -> dict:
    p = call_profile(image, rva, size)
    return {"function": hex(rva), "size": hex(size),
            "direct_calls": sum(p.counts.values()),
            "unique_callees": len(p.counts),
            "callees": [hex(x) for x in sorted(p.counts)]}


def analyze_lapse_pair(env, syscall_number: int, closure_depth: int = 2,
                       closure_budget: int = 512) -> dict:
    """Resolve and compare one syscall pair without consulting detector labels."""
    started = time.time()
    tracemalloc.start()
    resolved = {}
    scopes = {}
    catalogs = {}
    for fw in ("9.00", "13.52"):
        image = env.images[fw]
        entry = env.sysent[fw].get(syscall_number)
        if entry is None or not entry.valid:
            return {"verdict": "UNRESOLVED", "reason": f"invalid sysent entry on {fw}"}
        chain = entry_chain(image, entry.handler_rva, index=env.indexes[fw])
        if len(chain) < 2:
            return {"verdict": "UNRESOLVED", "reason": f"no tail-jump body on {fw}",
                    "chain": [hex(x) for x in chain]}
        body = chain[-1]
        extent = discover_extent(image, body)
        if extent.capped or not extent.returns:
            return {"verdict": "UNRESOLVED", "reason": f"CFG extent unresolved on {fw}",
                    "extent": extent.as_dict()}
        closure, closure_report = call_closure(
            image, [body], depth=closure_depth, budget=closure_budget)
        cat_t0 = time.time()
        catalog = SyncCatalog(image, closure)
        catalog_s = time.time() - cat_t0
        scope = LockScope(image, body, extent.size, catalog,
                          release_targets=_anchors(env.facts[fw].doc),
                          name="syscall_body")
        catalogs[fw] = catalog
        scopes[fw] = scope
        assessments = scope.mutation_assessments()
        findings = scope.findings()
        verdict_counts = {}
        for assessment in assessments:
            verdict = assessment["lock_state"]["verdict"]
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        unknown_count = verdict_counts.get("UNKNOWN", 0)
        body_bytes = image.read(body, extent.size)
        resolved[fw] = {
            "syscall": syscall_number,
            "narg": entry.narg,
            "handler": hex(entry.handler_rva),
            "entry_chain": [hex(x) for x in chain],
            "body": hex(body),
            "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
            "extent": extent.as_dict(),
            "callgraph": _profile(image, body, extent.size),
            "closure": closure_report,
            "catalog_elapsed_s": round(catalog_s, 3),
            "catalog": catalog.stats(),
            "scope": scope.summary(),
            "scope_metrics": {
                "blocks": len(scope.view.blocks),
                "lock_events": len(scope.events),
                "mutations": len(assessments),
                "verdict_counts": verdict_counts,
                "unknown_calls": len(scope.unknown_calls),
                "unknown_rate": (round(unknown_count / len(assessments), 6)
                                 if assessments else 0.0),
            },
            "assessments": assessments,
            "findings": findings,
            "exit_states": scope.exit_states(),
        }
    # Structural callee correspondence is independent of names and addresses.
    p13 = call_profile(env.images["13.52"], int(resolved["13.52"]["body"], 16),
                       int(resolved["13.52"]["extent"]["size"], 16))
    p9 = call_profile(env.images["9.00"], int(resolved["9.00"]["body"], 16),
                      int(resolved["9.00"]["extent"]["size"], 16))
    matched = match_callees(env.images["13.52"], p13, env.images["9.00"], p9)
    comparison = compare_scope(scopes["9.00"], scopes["13.52"])
    pos = [f for f in resolved["9.00"]["findings"]
           if f["pattern"] == "LOCK_SCOPE_PATH_DEPENDENT" and f["rank"] <= 2]
    neg = [f for f in resolved["13.52"]["findings"]
           if f["pattern"] == "LOCK_SCOPE_PATH_DEPENDENT" and f["rank"] <= 2]
    verdict = "PASS" if pos and not neg else "FAIL"
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "schema": "ps4rf.discovery.s11.lock-pair/1",
        "verdict": verdict,
        "mapping_basis": "sysent entry -> tail-jump chain -> reachable CFG; labels not read",
        "firmware": resolved,
        "callee_correspondence": {
            "pairs": int(matched.get("pairs", 0)),
            "ambiguities": (len(matched.get("ambiguous_a", [])) +
                            len(matched.get("ambiguous_b", []))),
            "mapping": matched.get("mapping", {}),
        },
        "scope_comparison": comparison,
        "acceptance": {
            "vulnerable_positive_findings": len(pos),
            "fixed_actionable_false_positives": len(neg),
            "positive": pos,
        },
        "runtime": {
            "elapsed_s": round(time.time() - started, 3),
            "python_peak_bytes": peak,
            "max_rss_kib": int(usage.ru_maxrss),
        },
    }
