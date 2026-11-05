"""S1.2 integration checks: D3 freeze, candidate queue, determinism inputs.

* **D3 freeze** -- the D3 findings of the S1.2 scan must be identical to the
  frozen S1.1 baseline, site for site.  D1/D4 are expected to change; D3 is not.
* **queue** -- D1/D4 findings must reach the regular candidate queue, with the
  nine required fields.  A finding that cannot produce a falsification test is
  dropped by the queue, and the drop reason is part of the result.
* **determinism** -- the scan artefact is re-hashed with the timing field removed,
  so "reproducible" means the analysis, not the stopwatch.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from typing import Dict, List

from . import queue as queue_mod
from . import validate

AUDIT = pathlib.Path("/home/hermes/audits/ps4-exploit-discovery-s1")
S12 = AUDIT / "sprint1.2"
S11 = AUDIT / "sprint1.1"
DATA = pathlib.Path(__file__).resolve().parent / "data"


def _read(path: pathlib.Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"required run artefact missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _sha(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def d3_signature(scan: dict) -> List[tuple]:
    out = []
    for finding in scan.get("findings", []):
        if finding["detector"] != "D3_lock_coverage":
            continue
        out.append((finding["function"]["rva"], tuple(finding.get("sites") or ()),
                    finding.get("rank"), str(finding.get("slot"))))
    return sorted(out)


def run() -> dict:
    now = _read(S12 / "s12-scan-fw1352.json")
    frozen = _read(S11 / "sprint1-scan-current.json")
    env = validate.Environment.load(str(DATA), only=["13.52"])
    entries = {}
    prior = queue_mod.load_negative_results(str(DATA / "negative" / "prior-results.json"))
    facts = env.facts["13.52"].doc

    from .cli import build_entry_index

    entries = build_entry_index(env, "13.52", depth=2)
    candidates = queue_mod.build(now["findings"], entries["entry_map"], facts, prior, limit=12)

    by_detector: Dict[str, int] = {}
    for candidate in candidates.get("queue", []):
        detector = (candidate.get("evidence") or {}).get("detector") or "unknown"
        by_detector[detector] = by_detector.get(detector, 0) + 1

    signature_now = d3_signature(now)
    signature_frozen = d3_signature(frozen)
    return {
        "d3_freeze": {
            "frozen_count": len(signature_frozen),
            "current_count": len(signature_now),
            "identical": signature_now == signature_frozen,
            "added": [s[0] for s in signature_now if s not in signature_frozen][:8],
            "removed": [s[0] for s in signature_frozen if s not in signature_now][:8],
        },
        "queue": {
            "admitted": len(candidates.get("queue", [])),
            "counts": candidates.get("counts", {}),
            "by_detector": by_detector,
            "drop_reasons": sorted({d.get("why", "") for d in (candidates.get("dropped") or [])})[:6],
            "detectors_in_scan": sorted(now.get("counts_by_detector", {})),
            "d1_d4_admitted": sum(v for k, v in by_detector.items() if k.startswith(("D1", "D4"))),
        },
        "determinism": {
            "scan_hash_without_timing": _sha({k: v for k, v in now.items() if k != "elapsed_s"}),
            "scanned_functions": now["scanned_functions"],
        },
        "lifecycle_analytics": now.get("lifecycle_analytics", {}),
        "observation_counts": now.get("observation_counts", {}),
    }
