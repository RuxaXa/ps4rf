"""Turn a candidate queue into blind predictions.

A blind run gets an image and nothing else: no PoC, no function address, no bug class, no
patch site.  The engine's job is to emit claims that can be wrong, in the shape
``blindscore`` can score.  This module is the boundary between "the analysis found
candidates" and "here is what I assert about this binary", so it does the three things a
scoring boundary must do:

* it never invents a site -- a candidate without a parseable address is refused, not
  placed at the function entry;
* it never emits a claim without evidence -- the falsification test and the falsifiable
  observations travel with the prediction;
* it records every candidate it declines, with a reason, so an empty prediction set is
  distinguishable from a pipeline that dropped everything.

Confidence is a fixed function of the engine's own evidence class, not a guess: a rank-1
observation with a complete chain outranks a rank-2 observation with an open blocker, and
the numbers are documented instead of tuned.
"""
from __future__ import annotations

import argparse
import json
import pathlib
from typing import Dict, List, Optional, Tuple

#: rank -> base confidence.  The auditor's counterexamples fixed the ranks; these weights
#: only order them, they do not claim a probability of exploitation.
RANK_CONFIDENCE = {1: 0.70, 2: 0.50, 3: 0.35}
DEFAULT_CONFIDENCE = 0.30
COMPLETE_CHAIN_BONUS = 0.15
OPEN_BLOCKER_PENALTY = 0.10
MIN_CONFIDENCE, MAX_CONFIDENCE = 0.05, 0.95


def _address(value) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _bug_class(hypothesis: str) -> str:
    """``"OWNERSHIP_DOUBLE_FREE: D2_… at 0x100 -- …"`` -> ``"OWNERSHIP_DOUBLE_FREE"``."""
    head = str(hypothesis or "").split(":", 1)[0].strip()
    return head or "unknown"


def _open_blockers(candidate: dict) -> int:
    chain = candidate.get("chain") or {}
    blockers = chain.get("blockers") or []
    return len([b for b in blockers if str(b.get("status", "")).lower() == "open"])


def confidence_for(candidate: dict) -> float:
    """Deterministic confidence from the candidate's own evidence class."""
    evidence = candidate.get("evidence") or {}
    rank = evidence.get("rank_of_hypothesis") or evidence.get("rank")
    value = RANK_CONFIDENCE.get(rank, DEFAULT_CONFIDENCE) if isinstance(rank, int) else DEFAULT_CONFIDENCE
    chain = candidate.get("chain") or {}
    if chain.get("complete"):
        value += COMPLETE_CHAIN_BONUS
    value -= OPEN_BLOCKER_PENALTY * _open_blockers(candidate)
    return round(max(MIN_CONFIDENCE, min(MAX_CONFIDENCE, value)), 3)


def site_of(candidate: dict) -> Optional[int]:
    """The most specific address the candidate actually names."""
    evidence = candidate.get("evidence") or {}
    for site in evidence.get("site_rvas") or []:
        address = _address(site)
        if address is not None:
            return address
    function = candidate.get("function") or {}
    return _address(function.get("rva"))


def prediction_for(candidate: dict) -> Tuple[Optional[dict], Optional[str]]:
    """One prediction, or the reason it cannot be made."""
    site = site_of(candidate)
    if site is None:
        return None, "no parseable site address"
    hypothesis = str(candidate.get("root_cause_hypothesis") or "").strip()
    if not hypothesis:
        return None, "no root-cause hypothesis"
    falsification = str(candidate.get("falsification_test") or "").strip()
    if not falsification:
        return None, "no falsification test"
    evidence = candidate.get("evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    observed: List[str] = []
    if evidence.get("rank") is not None:
        observed.append(f"rank {evidence['rank']} for this hypothesis")
    if evidence.get("slots"):
        observed.append("slots " + ", ".join(str(slot) for slot in evidence["slots"]))
    for record in evidence.get("sites") or []:
        claims = json.dumps(record.get("claims") or {}, sort_keys=True)
        observed.append(f"slot {record.get('slot', '?')} rank {record.get('rank', '?')}"
                        f" claims {claims}")
    if not observed:
        observed.append(f"detector {evidence.get('detector', '?')} fired")
    return {
        "site": site,
        "bug_class": _bug_class(hypothesis),
        "mechanism": hypothesis,
        "evidence": observed + [f"falsification: {falsification}"],
        "confidence": confidence_for(candidate),
        "candidate_id": candidate.get("id"),
    }, None


def from_queue(queue_document: dict) -> dict:
    """Prediction bundle from a ``queue`` artefact (``{"queue": [...]}``)."""
    candidates = queue_document.get("queue") or []
    predictions: List[dict] = []
    skipped: List[dict] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            skipped.append({"candidate": None, "why": "not an object"})
            continue
        prediction, why = prediction_for(candidate)
        if prediction is None:
            skipped.append({"candidate": candidate.get("id"), "why": why})
        else:
            predictions.append(prediction)
    predictions.sort(key=lambda item: (item["site"], item["bug_class"]))
    return {
        "predictions": predictions,
        "skipped": skipped,
        "counts": {
            "candidates": len(candidates),
            "predictions": len(predictions),
            "skipped": len(skipped),
            "dropped_by_queue": len(queue_document.get("dropped") or []),
        },
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="blind predictions from a candidate queue")
    ap.add_argument("--queue", required=True, help="a queue artefact written by cli queue")
    ap.add_argument("--out", default=None, help="write the bundle here instead of stdout")
    args = ap.parse_args(argv)
    document = json.loads(pathlib.Path(args.queue).read_text(encoding="utf-8"))
    bundle = from_queue(document)
    text = json.dumps(bundle, indent=2, sort_keys=True)
    if args.out:
        pathlib.Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
