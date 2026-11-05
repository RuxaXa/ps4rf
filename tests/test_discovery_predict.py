"""Blind-prediction tests.

The predictor is the scoring boundary, so what it refuses matters as much as what it
emits: no site means no prediction, no falsification test means no prediction, and a
declined candidate has to appear in ``skipped`` with a reason. A pipeline that silently
drops everything and a pipeline that found nothing must not look the same.
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.discovery import blindscore, predict


def candidate(**overrides):
    base = {
        "id": "C-D2-0x100",
        "function": {"rva": "0x100", "name": "sys_foo"},
        "root_cause_hypothesis": ("OWNERSHIP_DOUBLE_FREE: D2_double_release at 0x100 -- "
                                  "same_object=True; case=strong"),
        "falsification_test": "the two release sites must name the same object",
        "evidence": {"detector": "D2_double_release", "rank": 2, "rank_of_hypothesis": 1,
                     "slots": ["A"], "site_rvas": ["0x110"],
                     "sites": [{"slot": "A", "rank": 1,
                                "claims": {"same_object": True, "case": "strong"}}]},
        "chain": {"complete": True, "blockers": []},
    }
    base.update(overrides)
    return base


def test_a_complete_candidate_becomes_a_valid_prediction():
    bundle = predict.from_queue({"queue": [candidate()]})
    assert bundle["counts"]["predictions"] == 1
    prediction = bundle["predictions"][0]
    assert prediction["site"] == 0x110                      # the specific site, not 0x100
    assert prediction["bug_class"] == "OWNERSHIP_DOUBLE_FREE"
    assert blindscore.validate_prediction(prediction) == []
    assert any("falsification" in item for item in prediction["evidence"])


def test_the_function_entry_is_only_used_when_no_site_is_named():
    bundle = predict.from_queue({"queue": [candidate(evidence={"detector": "D1", "rank": 1})]})
    assert bundle["predictions"][0]["site"] == 0x100


def test_a_candidate_without_an_address_is_refused_with_a_reason():
    bundle = predict.from_queue({"queue": [candidate(function={}, evidence={"rank": 1})]})
    assert bundle["predictions"] == []
    assert bundle["skipped"][0]["why"] == "no parseable site address"


def test_a_candidate_without_a_falsification_test_is_refused():
    bundle = predict.from_queue({"queue": [candidate(falsification_test=" ")]})
    assert bundle["predictions"] == []
    assert bundle["skipped"][0]["why"] == "no falsification test"


def test_an_empty_prediction_set_still_reports_what_the_queue_dropped():
    bundle = predict.from_queue({"queue": [],
                                 "dropped": [{"function": "0x200", "detector": "D3",
                                              "why": "no falsification test"}]})
    assert bundle["predictions"] == []
    assert bundle["counts"]["dropped_by_queue"] == 1


def test_confidence_follows_the_rank_and_the_chain_not_the_input_order():
    strong = predict.confidence_for(candidate())
    weak = predict.confidence_for(candidate(evidence={"rank": 3, "rank_of_hypothesis": 3}))
    assert strong > weak
    with_blocker = predict.confidence_for(
        candidate(chain={"complete": False, "blockers": [{"status": "open"}]}))
    assert with_blocker < strong


def test_confidence_stays_inside_its_bounds():
    many = candidate(chain={"complete": True,
                            "blockers": [{"status": "open"}] * 20})
    assert predict.MIN_CONFIDENCE <= predict.confidence_for(many) <= predict.MAX_CONFIDENCE


def test_predictions_are_sorted_so_two_runs_are_comparable():
    a = candidate(id="C-A", evidence={"rank": 1, "site_rvas": ["0x500"]})
    b = candidate(id="C-B", evidence={"rank": 1, "site_rvas": ["0x100"]})
    forward = predict.from_queue({"queue": [a, b]})
    reverse = predict.from_queue({"queue": [b, a]})
    assert [p["site"] for p in forward["predictions"]] == [0x100, 0x500]
    assert forward["predictions"] == reverse["predictions"]


def test_the_bundle_can_be_scored_against_a_key_unchanged():
    bundle = predict.from_queue({"queue": [candidate()]})
    key = [{"id": "fam", "site": 0x110, "bug_class": "OWNERSHIP_DOUBLE_FREE"}]
    result = blindscore.score(bundle["predictions"], key, tolerance=0x10)
    assert result["hits"] == 1
    assert result["recall"] == 1.0


def test_a_rank_floor_drop_is_recorded_not_silent():
    """A queue with zero candidates must say why: the floor used to hide them."""
    from tools.discovery.queue import build

    finding = {"detector": "D2_double_release", "function": {"rva": "0x100"},
               "bug_class": "OWNERSHIP_DOUBLE_FREE", "falsification": "check identity",
               "slot": "A", "sites": ["0x110"], "rank": 3,
               "claims": {"same_object": True}, "window": ["strong"]}
    entry = {"0x100": {"kind": "syscall", "syscall": 99, "narg": 2,
                       "label": "sysent[99]", "subsystem": "socket"}}
    out = build([finding], entry, {}, [], min_rank=2)
    assert out["queue"] == []
    assert any("above the floor 2" in record["why"] for record in out["dropped"]), out


def test_the_cli_writes_a_bundle(tmp_path):
    queue_path = tmp_path / "queue.json"
    queue_path.write_text(json.dumps({"queue": [candidate()]}), encoding="utf-8")
    out = tmp_path / "predictions.json"
    assert predict.main(["--queue", str(queue_path), "--out", str(out)]) == 0
    bundle = json.loads(out.read_text(encoding="utf-8"))
    assert bundle["counts"]["predictions"] == 1
