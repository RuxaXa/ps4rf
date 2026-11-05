"""CLI: run the Sprint-1 pipeline and write one machine-readable report.

    python -m tools.discovery.cli all --outdir <dir>
    python -m tools.discovery.cli facts
    python -m tools.discovery.cli validate --out <file>
    python -m tools.discovery.cli scan --fw 13.52 --depth 2 --max-functions 4000
    python -m tools.discovery.cli queue --out <file>
    python -m tools.discovery.cli graph --out <file>
    python -m tools.discovery.cli blind --out <file>

Nothing here writes to an image, talks to a console or executes target code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from typing import Dict, List, Optional

from . import chains as chains_mod
from . import graph as graph_mod
from . import ownership as ownership_mod
from . import handles, patterns, queue as queue_mod, validate
from .entries import entry_chain, subsystem_map
from .image import FirmwareFacts, KernelImage

DATA_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def _load_json(*parts: str) -> dict:
    with open(os.path.join(DATA_ROOT, *parts), "rt", encoding="utf-8") as fh:
        return json.load(fh)


def _sha(obj) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def build_entry_index(env: validate.Environment, fw: str, depth: int = 2,
                      per_entry_budget: int = 250,
                      entry_mode: str = "frozen") -> Dict[str, dict]:
    """Map every reachable function to the entry that reaches it first.

    ``entry_mode``: ``frozen`` is the S1.1/S1.2b behaviour (chain of tail jumps, direct
    calls only).  ``extended`` additionally follows split-record continuations, relative
    jump-table case bodies and code-pointer dispatch tables in the data segment, and
    raises the per-entry budget so a wrapper three hops in is still analysed.
    """
    if entry_mode not in ("frozen", "extended"):
        raise SystemExit(f"unknown entry mode: {entry_mode}")
    if entry_mode == "extended" and per_entry_budget == 250:
        per_entry_budget = 2000
    image = env.images[fw]
    index = env.indexes[fw]
    table = env.sysent[fw]
    groups = subsystem_map(table, _load_json("entries", "syscall-groups.json"))
    from .entries import EntryIndex

    ei = EntryIndex(image, index)
    entry_map: Dict[str, dict] = {}
    entries: List[dict] = []
    coverage = {"mode": entry_mode, "sysent": 0, "expanded_nodes": 0,
                "dispatch_tables": 0, "dispatch_targets": 0, "cdevsw": 0}
    valid_entries = list(table.valid_entries())
    handler_roots = {entry.handler_rva for entry in valid_entries}
    for entry in valid_entries:
        subs = groups.get(entry.number, [])
        chain = entry_chain(image, entry.handler_rva, index=index)
        label = f"sysent[{entry.number}]"
        info = {
            "kind": "syscall",
            "syscall": entry.number,
            "narg": entry.narg,
            "handler_rva": hex(entry.handler_rva),
            "chain": [hex(c) for c in chain],
            "subsystem": subs[0] if subs else f"syscall:{entry.number}",
            "label": label,
            "evidence": f"sysent[{entry.number}].sy_call",
        }
        entries.append(info)
        coverage["sysent"] += 1
        seeds = list(chain)
        if entry_mode == "extended":
            seeds = sorted(set(seeds) | set(ei.expand_entry(
                entry.handler_rva, barrier_roots=handler_roots)))
            coverage["expanded_nodes"] += len(seeds)
        for rva, d in ei.reachable(seeds, depth=depth, budget=per_entry_budget).items():
            key = hex(rva)
            cur = entry_map.get(key)
            if cur is None:
                entry_map[key] = dict(info, depth=d, entries=[info["label"]])
            else:
                # a function is usually reachable from several entries and shortest-path
                # order decides which one is seen first; keeping every label at the
                # minimal depth stops the first-seen label from reading as ownership
                if d < cur.get("depth", 99):
                    cur["depth"] = d
                    cur.update({k: v for k, v in info.items() if k != "entries"})
                    cur["entries"] = [info["label"]]
                elif d == cur.get("depth", 99):
                    labels = cur.setdefault("entries", [cur.get("label")])
                    if info["label"] not in labels:
                        labels.append(info["label"])
    cdev = env.cdevsw.get(fw)
    if cdev is not None:
        for dev in cdev.devices:
            info = {
                "kind": "cdevsw",
                "name": dev.name,
                "open_rva": hex(dev.open_rva),
                "ioctl_rva": hex(dev.ioctl_rva),
                "subsystem": "devfs",
                "label": f"cdevsw:{dev.name}",
                "evidence": f"cdevsw record at {hex(dev.record_rva)}",
            }
            entries.append(info)
            coverage["cdevsw"] += 1
            for rva, d in ei.reachable([dev.open_rva, dev.ioctl_rva], depth=depth,
                                       budget=per_entry_budget).items():
                key = hex(rva)
                if key not in entry_map:
                    entry_map[key] = dict(info, depth=d)
    if entry_mode == "extended":
        from .entries import dispatch_tables
        for table in dispatch_tables(image, index):
            info = {
                "kind": "dispatch-table",
                "table_rva": hex(table["table_rva"]),
                "subsystem": f"table:{hex(table['table_rva'])}",
                "label": f"dispatch:{hex(table['table_rva'])}",
                "evidence": f"{table['entries']} consecutive code pointers",
            }
            entries.append(dict(info, targets=len(table["targets"])))
            coverage["dispatch_tables"] += 1
            coverage["dispatch_targets"] += len(table["targets"])
            for rva, d in ei.reachable(table["targets"], depth=depth,
                                       budget=per_entry_budget).items():
                key = hex(rva)
                if key not in entry_map:
                    entry_map[key] = dict(info, depth=d)
    coverage["entry_map"] = len(entry_map)
    return {"entry_map": entry_map, "entries": entries, "coverage": coverage}


def scan(env: validate.Environment, fw: str, entry_map: Optional[Dict[str, dict]],
         depth: int = 2, max_functions: Optional[int] = 4000,
         order: str = "rva") -> dict:
    """Analyse the reachable functions.

    ``order="rva"`` is the frozen selection order (S1.1/S1.2b): it is reproduced byte for
    byte by the D3 freeze.  ``order="depth"`` selects by reachability first, so a wrapper
    three hops behind a dispatcher is not cut off by the budget; it is used by the
    extended entry set, where the candidate count exceeds any sane ``max_functions``.
    """
    image = env.images[fw]
    index = env.indexes[fw]
    named = {r.rva: r.name for r in index.named()}
    ctx_base = patterns.ScanContext.from_names(named)
    ownership = env.ownership(fw)
    targets = []
    for rec in index:
        key = hex(rec.rva)
        info = (entry_map or {}).get(key)
        if info is None:
            continue
        if info.get("depth", 0) > depth:
            continue
        targets.append((rec, info))
    if order == "depth":
        targets.sort(key=lambda t: (t[1].get("depth", 0), t[0].rva))
    else:
        targets.sort(key=lambda t: t[0].rva)
    if max_functions is not None:
        targets = targets[:max_functions]
    findings: List[dict] = []
    observations: List[dict] = []
    analytics: Dict[str, int] = {}
    t0 = time.time()
    scan_errors = 0
    for rec, info in targets:
        ctx = patterns.ScanContext(ctx_base.release_calls, ctx_base.lock_calls,
                                   ctx_base.unlock_calls,
                                   subsystem=info.get("subsystem", ""),
                                   ownership=ownership,
                                   handles=handles.HandleCatalog(image, index))
        got = patterns.scan_function(image, rec.rva, rec.size, rec.name, ctx)
        for f in got:
            if f.bug_class == "DETECTOR_ERROR":
                scan_errors += 1
            d = f.as_dict()
            d["entry"] = info.get("label")
            d["entry_candidates"] = list(info.get("entries") or [info.get("label")])
            findings.append(d)
        for obs in ctx.observations:
            obs["entry"] = info.get("label")
            observations.append(obs)
        for key, value in ctx.analytics.items():
            if isinstance(value, dict):
                # per-cause counters: merge, never add a dict to an int
                bucket = analytics.setdefault(key, {})
                for cause, count in value.items():
                    bucket[cause] = bucket.get(cause, 0) + int(count)
                continue
            analytics[key] = analytics.get(key, 0) + value
    findings.sort(key=lambda f: (f["rank"], f["function"]["rva"], f["detector"]))
    observations.sort(key=lambda o: (o["detector"], o["release_site"], o["use_site"]))
    return {
        "firmware": fw,
        "scanned_functions": len(targets),
        "scanned_rvas": [hex(rec.rva) for rec, _info in targets],
        "reachable_functions": len(entry_map or {}),
        "elapsed_s": round(time.time() - t0, 1),
        "detector_errors": scan_errors,
        "ownership": ownership.stats(),
        "counts_by_rank": {
            str(r): sum(1 for f in findings if f["rank"] == r) for r in (1, 2, 3, 9)
        },
        "counts_by_detector": {
            d: sum(1 for f in findings if f["detector"] == d)
            for d in sorted({f["detector"] for f in findings})
        },
        "lifecycle_analytics": analytics,
        "observation_counts": {
            kind: sum(1 for o in observations if o["kind"] == kind)
            for kind in sorted({o["kind"] for o in observations})
        },
        "observations": observations[:400],
        "findings": findings,
    }


def blind_probe(env: validate.Environment, fw: str, entry_map: Dict[str, dict],
                targets: dict, scan_report: Optional[dict] = None) -> dict:
    """Held-out check: does the scan reach the subsystems afterglow uses?

    The scan output is frozen (its hash is recorded) *before* this function runs,
    so the comparison cannot influence the scan.  The probe only asks whether the
    subsystems claimed by the held-out family appear among the entries and the
    findings of the primary firmware.
    """
    subsystem_hits = {}
    findings = (scan_report or {}).get("findings") or []
    for sub in targets["subsystems"]:
        matching_entries = [
            e for e in entry_map["entries"] if e.get("subsystem") == sub
        ]
        matching_functions = [
            k for k, v in entry_map["entry_map"].items() if v.get("subsystem") == sub
        ]
        in_sub = [f for f in findings if (f.get("entry") or "") and
                  next((v.get("subsystem") for k, v in entry_map["entry_map"].items()
                        if v.get("label") == f.get("entry")), "") == sub]
        subsystem_hits[sub] = {
            "entries": [e.get("label") for e in matching_entries],
            "reachable_functions": len(matching_functions),
            "sample_functions": sorted(matching_functions)[:10],
            "findings": len(in_sub),
            "findings_by_detector": {
                d: sum(1 for f in in_sub if f["detector"] == d)
                for d in sorted({f["detector"] for f in in_sub})
            },
            "same_family_as_aio": sorted({f["bug_class"] for f in in_sub}),
        }
    return {"firmware": fw, "held_out_family": targets["family"],
            "subsystems": subsystem_hits,
            "claimed_anchors": targets.get("anchors", {}),
            "expected_shape": targets.get("expected_shape", ""),
            "note": targets.get("note", "")}


def run_all(args) -> dict:
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    env = validate.Environment.load(DATA_ROOT)
    families = _load_json("families", "families.json")
    references = _load_json("families", "references.json")
    prior = queue_mod.load_negative_results(os.path.join(DATA_ROOT, "negative", "prior-results.json"))

    report = {
        "schema": "ps4rf.discovery.report/1",
        "started_utc": started,
        "data_root": DATA_ROOT,
        "firmware_loaded": sorted(env.facts),
    }
    report["purity"] = validate.purity_report(env)
    if args.sources:
        report["source_pins"] = validate.check_source_pins(families, args.sources)
    report["reference_matrix"] = validate.run(env, references)
    report["reference_matrix_hash"] = _sha(report["reference_matrix"])

    primary = args.fw
    entries = build_entry_index(env, primary, depth=args.depth)
    report["entry_index"] = {
        "firmware": primary,
        "entries": entries["entries"],
        "reachable_functions": len(entries["entry_map"]),
    }
    scan_report = scan(env, primary, entries["entry_map"], depth=args.depth,
                       max_functions=args.max_functions)
    report["scan"] = scan_report
    report["scan_frozen_hash"] = _sha(
        {k: v for k, v in scan_report.items() if k != "elapsed_s"}
    )

    if args.blind:
        targets = _load_json("blind", "afterglow-targets.json")
        report["blind"] = blind_probe(env, primary, entries, targets, scan_report)

    facts = env.facts[primary].doc
    q = queue_mod.build(scan_report["findings"], entries["entry_map"], facts, prior,
                        limit=args.queue_limit)
    report["queue"] = q
    report["graph"] = graph_mod.build(report["entry_index"], families, q, prior)

    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "sprint1-report.json"), "wt", encoding="utf-8") as fh:
        json.dump(report, fh, indent=1, sort_keys=False)
    with open(os.path.join(outdir, "cross-subsystem-graph.json"), "wt", encoding="utf-8") as fh:
        json.dump(report["graph"], fh, indent=1)
    with open(os.path.join(outdir, "cross-subsystem-graph.dot"), "wt", encoding="utf-8") as fh:
        fh.write(graph_mod.to_dot(report["graph"]))
    with open(os.path.join(outdir, "candidate-queue.json"), "wt", encoding="utf-8") as fh:
        json.dump(q, fh, indent=1)
    return report


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="tools.discovery.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_all = sub.add_parser("all", help="run the whole Sprint-1 pipeline")
    p_all.add_argument("--outdir", required=True)
    p_all.add_argument("--fw", default="13.52")
    p_all.add_argument("--depth", type=int, default=2)
    p_all.add_argument("--max-functions", type=int, default=4000)
    p_all.add_argument("--queue-limit", type=int, default=10)
    p_all.add_argument("--sources", default=None)
    p_all.add_argument("--blind", action="store_true")

    p_facts = sub.add_parser("facts", help="print the resolved table facts")
    p_facts.add_argument("--fw", default="13.52")

    p_val = sub.add_parser("validate", help="run the reference matrix")
    p_val.add_argument("--out", default=None)
    p_val.add_argument("--sources", default=None)

    p_scan = sub.add_parser("scan", help="scan reachable functions")
    p_scan.add_argument("--fw", default="13.52")
    p_scan.add_argument("--depth", type=int, default=2)
    p_scan.add_argument("--entry-set", choices=("frozen", "extended"), default="frozen")
    p_scan.add_argument("--max-functions", type=int, default=4000)
    p_scan.add_argument("--out", default=None)

    p_q = sub.add_parser("queue", help="build the candidate queue")
    p_q.add_argument("--fw", default="13.52")
    p_q.add_argument("--depth", type=int, default=2)
    p_q.add_argument("--entry-set", choices=("frozen", "extended"), default="frozen")
    p_q.add_argument("--max-functions", type=int, default=4000)
    p_q.add_argument("--limit", type=int, default=10)
    p_q.add_argument("--out", default=None)

    p_g = sub.add_parser("graph", help="export the cross-subsystem graph")
    p_g.add_argument("--out", default=None)

    p_sg = sub.add_parser("semgraph", help="semantic primitive graph for a scan artefact")
    p_sg.add_argument("--fw", default="13.52")
    p_sg.add_argument("--scan", required=True, help="path to a cli scan artefact")
    p_sg.add_argument("--out", default=None)
    p_sg.add_argument("--whole-program", action="store_true",
                      help="seed the graph from every scanned function, not only from "
                           "the finding functions (A1-07); the budget is published")
    p_sg.add_argument("--function-budget", type=int, default=None,
                      help="override the function budget (for controlled comparisons)")
    p_sg.add_argument("--depth-budget", type=int, default=None,
                      help="override the depth budget (for controlled comparisons)")

    p_cm = sub.add_parser("chainmap", help="chain reasoning over the semantic graph")
    p_cm.add_argument("--fw", default="13.52")
    p_cm.add_argument("--scan", required=True, help="path to a cli scan artefact")
    p_cm.add_argument("--out", default=None)
    p_cm.add_argument("--whole-program", action="store_true",
                      help="same as for semgraph: whole-program seeding")
    p_cm.add_argument("--function-budget", type=int, default=None)
    p_cm.add_argument("--depth-budget", type=int, default=None)

    p_b = sub.add_parser("blind", help="run the held-out probe")
    p_b.add_argument("--fw", default="13.52")
    p_b.add_argument("--depth", type=int, default=2)
    p_b.add_argument("--entry-set", choices=("frozen", "extended"), default="frozen")
    p_b.add_argument("--max-functions", type=int, default=4000)
    p_b.add_argument("--out", default=None)

    args = ap.parse_args(argv)

    if args.cmd in ("semgraph", "chainmap"):
        import json as _json
        import pathlib as _pathlib
        from . import semgraph as semgraph_mod
        from . import handles as handles_mod
        from . import chains as chains_mod
        env = validate.Environment.load(DATA_ROOT, only=[args.fw])
        scan_doc = _json.loads(_pathlib.Path(args.scan).read_text())
        own = env.ownership(args.fw)
        entry_meta = {}
        for ent in env.sysent[args.fw].valid_entries():
            label = f"sysent[{ent.number}]"
            entry_meta[label] = {
                "handler_rva": hex(ent.handler_rva),
                "site": f"sysent[{ent.number}].sy_call",
                "chain": [hex(x) for x in entry_chain(
                    env.images[args.fw], ent.handler_rva,
                    index=env.indexes[args.fw])],
            }
        graph_doc = semgraph_mod.build(scan_doc, handles_mod, env.images[args.fw],
                                       env.indexes[args.fw], ownership=own,
                                       entry_meta=entry_meta,
                                       whole_program=bool(getattr(args, "whole_program",
                                                                  False)),
                                       function_budget=getattr(args, "function_budget", None),
                                       depth_budget=getattr(args, "depth_budget", None))
        violations = semgraph_mod.check_evidence(graph_doc)
        if violations:
            raise SystemExit(f"edges without witness: {violations[:5]}")
        payload = graph_doc
        if args.cmd == "chainmap":
            payload = semgraph_mod.chains(graph_doc, scan_doc, env.facts[args.fw].doc,
                                          chains_mod)
            payload["graph_counts"] = graph_doc["counts"]
        text = _json.dumps(payload, indent=1, sort_keys=True)
        if args.out:
            _pathlib.Path(args.out).write_text(text)
            print(_json.dumps({"written": args.out,
                               "counts": payload.get("counts"),
                               "edges": graph_doc["counts"]["edges"],
                               "chain_status": payload.get("chain_status")}, indent=1,
                              sort_keys=True))
        else:
            print(text[:4000])
        return 0

    if args.cmd == "facts":
        env = validate.Environment.load(DATA_ROOT)
        fw = args.fw
        print(json.dumps({
            "firmware": fw,
            "purity": validate.purity_report(env)[fw],
            "sysent": env.sysent[fw].stats(),
            "functions": len(env.indexes[fw]),
            "named_functions": len(env.indexes[fw].named()),
            "cdevsw_devices": len(env.cdevsw[fw].devices) if env.cdevsw.get(fw) else 0,
        }, indent=1))
        return 0

    if args.cmd == "validate":
        env = validate.Environment.load(DATA_ROOT)
        rep = validate.run(env, _load_json("families", "references.json"))
        if args.sources:
            rep["source_pins"] = validate.check_source_pins(
                _load_json("families", "families.json"), args.sources)
        text = json.dumps(rep, indent=1)
        if args.out:
            with open(args.out, "wt", encoding="utf-8") as fh:
                fh.write(text)
        print(text if not args.out else json.dumps(rep["summary"], indent=1))
        return 0

    if args.cmd in ("scan", "queue", "blind"):
        env = validate.Environment.load(DATA_ROOT)
        entries = build_entry_index(env, args.fw, depth=args.depth,
                                    entry_mode=getattr(args, "entry_set", "frozen"))
        mode = getattr(args, "entry_set", "frozen")
        scan_report = scan(env, args.fw, entries["entry_map"], depth=args.depth,
                           max_functions=args.max_functions,
                           order="depth" if mode == "extended" else "rva")
        scan_report["entry_coverage"] = entries.get("coverage")
        if args.cmd == "scan":
            payload = scan_report
        elif args.cmd == "queue":
            prior = queue_mod.load_negative_results(
                os.path.join(DATA_ROOT, "negative", "prior-results.json"))
            payload = queue_mod.build(scan_report["findings"], entries["entry_map"],
                                      env.facts[args.fw].doc, prior, limit=args.limit)
        else:
            payload = blind_probe(env, args.fw, entries, _load_json("blind", "afterglow-targets.json"), scan_report)
        text = json.dumps(payload, indent=1)
        if args.out:
            with open(args.out, "wt", encoding="utf-8") as fh:
                fh.write(text)
            print(json.dumps({"written": args.out, "summary": {
                k: payload[k] for k in ("scanned_functions", "counts_by_rank", "counts_by_detector", "counts")
                if k in payload}}, indent=1))
        else:
            print(text)
        return 0

    if args.cmd == "graph":
        rep = run_all(argparse.Namespace(outdir=os.path.dirname(args.out or ".") or ".",
                                         fw="13.52", depth=2, max_functions=4000,
                                         queue_limit=10, sources=None, blind=False))
        print(json.dumps({"nodes": len(rep["graph"]["nodes"]),
                          "edges": len(rep["graph"]["edges"])}, indent=1))
        return 0

    if args.cmd == "all":
        rep = run_all(args)
        print(json.dumps({
            "report": os.path.join(args.outdir, "sprint1-report.json"),
            "hard_facts": rep["reference_matrix"]["summary"],
            "scanner_score": rep["reference_matrix"]["scanner_score"],
            "scan": {k: rep["scan"][k] for k in
                     ("firmware", "scanned_functions", "counts_by_rank", "counts_by_detector")},
            "queue": rep["queue"]["counts"],
            "graph": {"nodes": len(rep["graph"]["nodes"]), "edges": len(rep["graph"]["edges"])},
        }, indent=1))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
