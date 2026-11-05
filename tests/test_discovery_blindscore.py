"""Blind-run scoring tests.

The scorer decides whether a blind rediscovery "worked", so its arithmetic is pinned
here rather than trusted: spraying addresses must not buy recall, a hit must be one key
site claimed once, and a wrong bug class at the right address is a miss.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.discovery import blindscore


def prediction(site, bug_class="uaf", confidence=0.5, mechanism="a reference is dropped twice"):
    return {"site": site, "bug_class": bug_class, "confidence": confidence,
            "mechanism": mechanism, "evidence": ["two drops on the same field"]}


KEY = [
    {"id": "fam-a", "site": 0x1000, "bug_class": "uaf"},
    {"id": "fam-b", "site": 0x5000, "bug_class": "race"},
]


def test_a_prediction_within_tolerance_is_a_hit():
    result = blindscore.score([prediction(0x1020)], KEY, tolerance=0x40)
    assert result["hits"] == 1
    assert result["missed"] == ["fam-b"]
    assert result["matched"][0]["id"] == "fam-a"
    assert result["matched"][0]["distance"] == 0x20
    assert result["precision"] == 1.0


def test_a_prediction_outside_tolerance_is_a_false_positive():
    result = blindscore.score([prediction(0x1041)], KEY, tolerance=0x40)
    assert result["hits"] == 0
    assert result["false_positives"] == 1
    assert result["recall"] == 0.0


def test_tolerance_is_inclusive_at_the_boundary():
    assert blindscore.score([prediction(0x1040)], KEY, tolerance=0x40)["hits"] == 1
    assert blindscore.score([prediction(0x1041)], KEY, tolerance=0x40)["hits"] == 0


def test_the_right_address_with_the_wrong_bug_class_does_not_hit():
    result = blindscore.score([prediction(0x1000, bug_class="oob-write")], KEY)
    assert result["hits"] == 0
    assert result["false_positives"] == 1


def test_spraying_addresses_around_one_key_site_yields_one_hit():
    spray = [prediction(0x1000), prediction(0x1008), prediction(0x1010), prediction(0x1018)]
    result = blindscore.score(spray, KEY, tolerance=0x40)
    assert result["hits"] == 1
    assert result["false_positives"] == 3
    assert result["predicted"] == 4
    assert result["precision"] == 0.25


def test_the_nearest_key_site_wins():
    key = [{"id": "near", "site": 0x1010, "bug_class": "uaf"},
           {"id": "far", "site": 0x1000, "bug_class": "uaf"}]
    result = blindscore.score([prediction(0x100c)], key, tolerance=0x40)
    assert result["matched"][0]["id"] == "near"
    assert result["missed"] == ["far"]


def test_hex_string_sites_are_accepted():
    result = blindscore.score([prediction("0x1000")], KEY)
    assert result["hits"] == 1


def test_no_predictions_gives_zero_recall_not_none():
    result = blindscore.score([], KEY)
    assert result["hits"] == 0
    assert result["recall"] == 0.0
    assert result["precision"] is None
    assert result["missed"] == ["fam-a", "fam-b"]


def test_a_key_entry_without_a_site_is_an_error():
    with pytest.raises(ValueError):
        blindscore.score([], [{"id": "broken", "bug_class": "uaf"}])


def test_negative_tolerance_is_refused():
    with pytest.raises(ValueError):
        blindscore.score([], KEY, tolerance=-1)


def test_validate_rejects_a_claim_without_mechanism_or_evidence():
    problems = blindscore.validate_prediction({"site": 0x10, "bug_class": "uaf",
                                          "confidence": 0.5, "mechanism": " ",
                                          "evidence": []})
    assert any("mechanism" in p for p in problems)
    assert any("evidence" in p for p in problems)


def test_validate_rejects_an_empty_class_and_an_out_of_range_confidence():
    problems = blindscore.validate_prediction({"site": "0x10", "bug_class": " ",
                                              "confidence": 2, "mechanism": "x",
                                              "evidence": ["a"]})
    assert any("bug_class" in p for p in problems)
    assert any("confidence" in p for p in problems)


def test_a_detector_class_from_the_engine_is_accepted():
    """OWNERSHIP_DOUBLE_FREE is what the engine actually emits; a frozen enum would
    reject the truth."""
    prediction_ = {"site": 0x10, "bug_class": "OWNERSHIP_DOUBLE_FREE", "confidence": 0.4,
                   "mechanism": "two drops on one object", "evidence": ["drop pair"]}
    assert blindscore.validate_prediction(prediction_) == []
    assert blindscore.validate_prediction(prediction_, allowed=("uaf",)) != []


def test_validate_accepts_a_complete_prediction():
    assert blindscore.validate_prediction(prediction("0x1000")) == []


def test_load_predictions_keeps_valid_entries_and_reports_the_rest(tmp_path):
    path = tmp_path / "pred.json"
    path.write_text('{"predictions": ['
                    '{"site": "0x1000", "bug_class": "uaf", "confidence": 0.9, '
                    '"mechanism": "double drop", "evidence": ["x"]},'
                    '{"site": 5, "bug_class": "", "confidence": 0.1, '
                    '"mechanism": "y", "evidence": ["z"]}]}', encoding="utf-8")
    usable, problems = blindscore.load_predictions(path)
    assert len(usable) == 1
    assert usable[0]["site"] == 0x1000
    assert any("bug_class" in problem for problem in problems)


def test_summarise_counts_every_case_including_misses():
    scores = [blindscore.score([prediction(0x1000)], KEY), blindscore.score([], KEY)]
    summary = blindscore.summarise(scores)
    assert summary["cases"] == 2
    assert summary["hits"] == 1
    assert summary["cases_with_any_hit"] == 1
    assert summary["mean_case_recall"] == 0.25     # (0.5 + 0.0) / 2
    assert summary["micro_recall"] == 0.25         # 1 hit of 4 key sites
    assert summary["false_positives"] == 0
