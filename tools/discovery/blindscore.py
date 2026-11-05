"""Blind-run predictions and their scoring.

The point of a blind run is a claim that can be wrong.  This module defines the shape
of that claim and the arithmetic that decides it, so a rediscovery result is measured
against a held-out answer key instead of against how many findings the engine emitted.

Two rules keep the numbers honest:

* a prediction is a *site plus a bug class*, not a sentence — mechanism text is reported
  next to the score but never matched by keyword, because keyword matching rewards
  restating the answer key's vocabulary;
* several predictions that land on one key site are one hit and the rest are false
  positives, so spraying addresses cannot buy recall.
"""
from __future__ import annotations

import json
import pathlib
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

#: The engine's own vocabulary is the reference (``OWNERSHIP_DOUBLE_FREE``,
#: ``RACE_UNLOCKED_SHARED_WRITE``, …).  A fixed enum here would silently reject correct
#: predictions the day a detector is added, so the class is free-form by default and a
#: caller that wants a closed vocabulary passes ``allowed``.
DETECTOR_CLASSES = ("uaf", "double-free", "race", "oob-write", "oob-read", "type-confusion",
                    "refcount", "integer-overflow", "info-leak", "other")


def _as_site(value) -> Optional[int]:
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


def validate_prediction(prediction: dict,
                        allowed: Optional[Sequence[str]] = None) -> List[str]:
    """Problems in one prediction; empty means usable.

    ``allowed`` is optional: without it any non-empty bug class is accepted, because the
    class has to match the detector that produced it, not a list frozen in this module.
    """
    problems: List[str] = []
    if _as_site(prediction.get("site")) is None:
        problems.append("site must be a non-negative address (int or '0x…' string)")
    bug_class = prediction.get("bug_class")
    if not isinstance(bug_class, str) or not bug_class.strip():
        problems.append("bug_class must be a non-empty string")
    elif allowed is not None and bug_class not in allowed:
        problems.append(f"bug_class must be one of {tuple(allowed)}")
    if not str(prediction.get("mechanism", "")).strip():
        problems.append("mechanism must state what is wrong, not only where")
    confidence = prediction.get("confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        problems.append("confidence must be a number in 0..1")
    elif not 0.0 <= float(confidence) <= 1.0:
        problems.append("confidence must be in 0..1")
    evidence = prediction.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        problems.append("evidence must name at least one fact from the image")
    return problems


def load_predictions(path: pathlib.Path) -> Tuple[List[dict], List[str]]:
    """Predictions from a JSON file (``{"predictions": [...]}`` or a bare list)."""
    document = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if isinstance(document, dict):
        predictions = document.get("predictions", [])
    else:
        predictions = document
    if not isinstance(predictions, list):
        return [], ["predictions must be a list"]
    problems: List[str] = []
    usable: List[dict] = []
    for index, prediction in enumerate(predictions):
        if not isinstance(prediction, dict):
            problems.append(f"predictions[{index}] must be an object")
            continue
        issues = validate_prediction(prediction)
        if issues:
            problems.extend(f"predictions[{index}]: {issue}" for issue in issues)
            continue
        usable.append(dict(prediction, site=_as_site(prediction["site"])))
    return usable, problems


def _key_site(entry: dict) -> Optional[int]:
    site = entry.get("site", entry.get("address"))
    return _as_site(site)


def score(predictions: Sequence[dict], key: Sequence[dict],
          tolerance: int = 0x40) -> Dict[str, object]:
    """Match predictions against a held-out key.

    A prediction hits when its bug class equals the key entry's and its site lies within
    ``tolerance`` bytes of the key site.  Each key entry can be claimed once; extra
    predictions on an already claimed site are false positives.
    """
    if tolerance < 0:
        raise ValueError("tolerance must not be negative")
    keyed: List[Tuple[int, dict]] = []
    for entry in key:
        site = _key_site(entry)
        if site is None:
            raise ValueError(f"key entry {entry.get('id', '?')} has no site")
        keyed.append((site, entry))

    claimed: Dict[str, dict] = {}
    false_positives: List[dict] = []

    def _site_of(prediction: dict) -> int:
        value = _as_site(prediction["site"])
        if value is None:
            raise ValueError(f"prediction site is not an address: {prediction['site']!r}")
        return value

    for prediction in sorted(predictions, key=_site_of):
        site = _site_of(prediction)
        best: Optional[dict] = None
        best_distance: Optional[int] = None
        for key_site, entry in keyed:
            if entry.get("bug_class") != prediction["bug_class"]:
                continue
            distance = abs(key_site - site)
            if distance <= tolerance and (best_distance is None or distance < best_distance):
                best, best_distance = entry, distance
        if best is None:
            false_positives.append(prediction)
            continue
        identifier = str(best.get("id"))
        if identifier in claimed:
            false_positives.append(prediction)
            continue
        claimed[identifier] = {
            "prediction": prediction,
            "key": best,
            "distance": best_distance,
            "confidence": prediction.get("confidence"),
        }
    missed = [entry for _, entry in keyed if str(entry.get("id")) not in claimed]
    hits = len(claimed)
    return {
        "tolerance": tolerance,
        "predicted": len(predictions),
        "key_total": len(keyed),
        "hits": hits,
        "missed": [str(entry.get("id")) for entry in missed],
        "false_positives": len(false_positives),
        "false_positive_sites": [prediction["site"] for prediction in false_positives],
        "recall": round(hits / len(keyed), 4) if keyed else None,
        "precision": round(hits / len(predictions), 4) if predictions else None,
        "matched": [
            {"id": identifier,
             "site": claimed[identifier]["prediction"]["site"],
             "key_site": _key_site(claimed[identifier]["key"]),
             "distance": claimed[identifier]["distance"],
             "bug_class": claimed[identifier]["prediction"]["bug_class"],
             "confidence": claimed[identifier]["confidence"],
             "mechanism": claimed[identifier]["prediction"]["mechanism"]}
            for identifier in sorted(claimed)
        ],
    }


def _number(case: Dict[str, object], field: str) -> float:
    value = case.get(field)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"score field {field!r} is not a number: {value!r}")
    return float(value)


def summarise(scores: Iterable[Dict[str, object]]) -> Dict[str, object]:
    """Aggregate per-case scores.  Missing cases are counted, never skipped."""
    cases = list(scores)
    with_recall = [case for case in cases if case.get("recall") is not None]
    hits = int(sum(_number(case, "hits") for case in cases))
    predicted = int(sum(_number(case, "predicted") for case in cases))
    key_total = int(sum(_number(case, "key_total") for case in cases))
    return {
        "cases": len(cases),
        "hits": hits,
        "predicted": predicted,
        "micro_recall": round(hits / key_total, 4) if key_total else None,
        "micro_precision": round(hits / predicted, 4) if predicted else None,
        "cases_with_any_hit": sum(1 for case in cases if _number(case, "hits") > 0),
        "mean_case_recall": round(sum(_number(case, "recall") for case in with_recall)
                                  / len(with_recall), 4) if with_recall else None,
        "false_positives": int(sum(_number(case, "false_positives") for case in cases)),
    }
