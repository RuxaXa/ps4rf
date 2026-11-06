"""Read-only discovery shortlist from existing PS4RF scan and chainmap JSON.

Does not load firmware, invent permissions, or claim a bug from a scanner rank.
"""
import argparse
import json
from pathlib import Path

TRACKS = {
    "D5": "post-release indirect use: verify same object, CFG path and target control",
    "D3": "lock-free shared write: verify shared identity, two contexts and lock coverage",
    "D1": "lifetime: verify same object survives release-to-use path",
    "D4": "lifetime: verify table slot generation and reuse",
    "D2": "double release: verify identity, guards and intervening kills",
    "D6": "refcount asymmetry: verify paired paths and counter updates",
}
UNPRIV = "BLOCK_REQ_UNPRIV_ENTRY"
OBLIGATIONS = {
    "D5": ["same-object alias across free/use", "reachable indirect use", "target control"],
    "D3": ["shared object not stack-local", "two independent contexts", "lock-free conflicting access"],
    "D1": ["release/use same generation", "path without reinitialization"],
    "D4": ["slot generation and stale access"],
    "D2": ["same object twice", "no refcount guard or reset"],
    "D6": ["counter delta and concurrent paths"],
}

def shortlist(scan, chainmap, limit=15):
    if limit < 1:
        raise ValueError("limit must be positive")
    indexed = {}
    for c in chainmap.get("chains", []):
        p = c.get("primitive") or {}
        key = (p.get("detector"), p.get("function"))
        indexed.setdefault(key, []).append(c)
    results = []
    for f in scan.get("findings", []):
        det = f.get("detector", "")
        track = det.split("_", 1)[0]
        if track not in TRACKS:
            continue
        rva = (f.get("function") or {}).get("rva")
        matches = indexed.get((det, rva), [])
        matches.sort(key=lambda c: (c.get("hop_status") != "proved", c.get("hop_count", 999)))
        c = matches[0] if matches else {}
        req = c.get("requirements") or {}
        blockers = req.get("blockers") or []
        blocker_ids = [b.get("id") for b in blockers]
        privilege = req.get("entry_privilege", "UNKNOWN")
        if privilege != "UNPRIVILEGED":
            # An entry node or proved path is not authorization evidence.
            if UNPRIV not in blocker_ids:
                blocker_ids.append(UNPRIV)
        record = {
            "track": track, "detector": det, "function_rva": rva,
            "rank": f.get("rank"), "entry": c.get("entry"),
            "reachability": c.get("hop_status", "unknown"),
            "entry_privilege": privilege,
            "open_blockers": sorted(set(blocker_ids)),
            "hypothesis": TRACKS[track],
            "falsify": OBLIGATIONS[track],
            "source_sites": f.get("sites") or f.get("site_rvas") or [],
            "counter_evidence": f.get("counter_evidence") or {},
            "provenance": "scan+chainmap only; no runtime proof",
        }
        # Keep candidate score separate from evidence grade.
        score = (2 if c.get("hop_status") == "proved" else 0)
        score += (1 if f.get("rank") == 1 else 0)
        score += (1 if privilege == "UNPRIVILEGED" else 0)
        record["triage_score"] = score
        results.append(record)
    results.sort(key=lambda x: (-x["triage_score"], x["track"], str(x["function_rva"])))
    # Deduplicate multiple slots in the same detector/function without losing all sites.
    unique = {}
    for r in results:
        key = (r["detector"], r["function_rva"])
        if key not in unique:
            unique[key] = r
        else:
            sites = unique[key]["source_sites"] + r["source_sites"]
            unique[key]["source_sites"] = list(dict.fromkeys(map(str, sites)))
    return {"schema": "ps4rf.discovery.shortlist/1",
            "evidence_grade": "STATIC_TRIAGE_ONLY",
            "candidates": list(unique.values())[:limit],
            "total_candidate_functions": len(unique)}

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scan", required=True)
    ap.add_argument("--chainmap", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit", type=int, default=15)
    args = ap.parse_args()
    scan = json.loads(Path(args.scan).read_text())
    chains = json.loads(Path(args.chainmap).read_text())
    report = shortlist(scan, chains, args.limit)
    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"written": args.out, "candidates": len(report["candidates"]),
                      "total": report["total_candidate_functions"],
                      "grade": report["evidence_grade"]}))

if __name__ == "__main__":
    main()
