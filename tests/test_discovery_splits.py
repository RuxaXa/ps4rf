"""The split manifest must be unable to claim blindness it does not have."""
from __future__ import annotations

import json
import pathlib

import pytest

from tools.discovery import splits


def _tree(tmp_path):
    discovery = tmp_path / "discovery"
    evaluator = tmp_path / "eval"
    (discovery / "tools").mkdir(parents=True)
    (evaluator / "solutions" / "holdback-r1").mkdir(parents=True)
    answers = {"answers": [
        {"case_id": "case-a", "site": "0x401000", "bug_class": "OWNERSHIP_DOUBLE_FREE",
         "mechanism": "the second release uses the first object"},
        {"case_id": "case-b", "site": "0x402000", "bug_class": "RACE_UNLOCKED_SHARED_WRITE",
         "mechanism": "the field is written without the lock"},
    ]}
    (evaluator / "solutions" / "holdback-r1" / "answers.json").write_text(
        json.dumps(answers), encoding="utf-8")
    return discovery, evaluator


def _cases():
    return [
        {"case_id": "case-a", "firmware": "13.52", "image_sha256": "a" * 64,
         "scope": "kernel"},
        {"case_id": "case-b", "firmware": "13.52", "image_sha256": "b" * 64,
         "scope": "kernel"},
    ]


def test_a_frozen_split_records_hashes_for_every_question_and_answer(tmp_path):
    discovery, evaluator = _tree(tmp_path)
    manifest = splits.create_manifest(evaluator, "holdback-r1", "holdback", _cases(),
                                      discovery, now=0)
    assert manifest["frozen"] is True
    assert len(manifest["cases"]) == 2
    for case in manifest["cases"]:
        assert len(case["question_sha256"]) == 64
        assert len(case["answer_sha256"]) == 64
    on_disk = json.loads((evaluator / "splits" / "holdback-r1" / "manifest.json").read_text())
    assert on_disk["answers_file_sha256"] == manifest["answers_file_sha256"]


def test_a_split_id_cannot_be_reused(tmp_path):
    discovery, evaluator = _tree(tmp_path)
    splits.create_manifest(evaluator, "holdback-r1", "holdback", _cases(), discovery, now=0)
    with pytest.raises(splits.SplitError, match="already frozen"):
        splits.create_manifest(evaluator, "holdback-r1", "holdback", _cases(), discovery, now=0)


def test_answers_inside_the_discovery_tree_are_refused(tmp_path):
    """The realistic mistake is pointing the evaluator root into the repository, so that the
    oracle ends up next to the engine. That is refused at creation and again at verification."""
    discovery, evaluator = _tree(tmp_path)
    inside = discovery / "ps4rf-eval"
    (inside / "solutions" / "holdback-r1").mkdir(parents=True)
    (inside / "solutions" / "holdback-r1" / "answers.json").write_text(
        (evaluator / "solutions" / "holdback-r1" / "answers.json").read_text(), encoding="utf-8")
    with pytest.raises(splits.SplitError, match="discovery tree"):
        splits.create_manifest(inside, "holdback-r1", "holdback", _cases(), discovery, now=0)
    hidden = inside / "solutions" / "holdback-r1" / "answers.json"
    # the same refusal must hold at verification time, not only at creation
    (evaluator / "splits" / "holdback-r1").mkdir(parents=True, exist_ok=True)
    (evaluator / "splits" / "holdback-r1" / "manifest.json").write_text(json.dumps({
        "split_id": "holdback-r1", "kind": "holdback", "frozen": True,
        "created_at": "2026-01-01T00:00:00Z", "discovery_root": str(discovery),
        "answers_path": str(hidden), "answers_file_sha256": splits.sha256_file(hidden),
        "cases": [],
    }))
    report = splits.verify(evaluator, "holdback-r1", discovery)
    assert report["blind_claim"] is False
    assert any("inside the discovery tree" in problem for problem in report["problems"])


def test_a_question_without_an_oracle_is_refused(tmp_path):
    discovery, evaluator = _tree(tmp_path)
    cases = _cases() + [{"case_id": "case-c", "firmware": "13.52", "image_sha256": "c" * 64}]
    with pytest.raises(splits.SplitError, match="no answer"):
        splits.create_manifest(evaluator, "holdback-r1", "holdback", cases, discovery, now=0)


def test_an_answer_changed_after_the_freeze_is_caught(tmp_path):
    discovery, evaluator = _tree(tmp_path)
    splits.create_manifest(evaluator, "holdback-r1", "holdback", _cases(), discovery, now=0)
    answers = {"answers": [{"case_id": "case-a", "site": "0x999999",
                            "bug_class": "OWNERSHIP_DOUBLE_FREE", "mechanism": "x"},
                           {"case_id": "case-b", "site": "0x402000",
                            "bug_class": "RACE_UNLOCKED_SHARED_WRITE", "mechanism": "y"}]}
    (evaluator / "solutions" / "holdback-r1" / "answers.json").write_text(
        json.dumps(answers), encoding="utf-8")
    report = splits.verify(evaluator, "holdback-r1", discovery)
    assert report["blind_claim"] is False
    assert any("changed after the split was frozen" in p for p in report["problems"])


def test_a_clean_holdback_split_may_carry_a_blind_claim(tmp_path):
    discovery, evaluator = _tree(tmp_path)
    splits.create_manifest(evaluator, "holdback-r1", "holdback", _cases(), discovery, now=0)
    report = splits.verify(evaluator, "holdback-r1", discovery)
    assert report["problems"] == [] and report["chain_problems"] == []
    assert report["blind_claim"] is True


def test_a_train_or_retro_split_never_carries_a_blind_claim(tmp_path):
    discovery, evaluator = _tree(tmp_path)
    source = (evaluator / "solutions" / "holdback-r1" / "answers.json").read_text()
    for kind in ("train", "retro"):
        target = evaluator / "solutions" / f"{kind}-r1"
        target.mkdir(parents=True)
        (target / "answers.json").write_text(source, encoding="utf-8")
        splits.create_manifest(evaluator, f"{kind}-r1", kind, _cases(), discovery, now=0)
        report = splits.verify(evaluator, f"{kind}-r1", discovery)
        assert report["blind_claim"] is False
        assert any("can never carry a blind claim" in reason for reason in report["reasons"])


def test_root_cause_exposure_downgrades_the_split(tmp_path):
    discovery, evaluator = _tree(tmp_path)
    splits.create_manifest(evaluator, "holdback-r1", "holdback", _cases(), discovery, now=0)
    splits.record_exposure(evaluator, "holdback-r1", "case-a", actor="hermes",
                           channel="chat", detail="root cause discussed", 
                           contamination="root_cause", now=0)
    report = splits.verify(evaluator, "holdback-r1", discovery)
    assert report["blind_claim"] is False
    assert report["contaminated_cases"] == ["case-a"]
    with pytest.raises(splits.SplitError, match="not blind evidence"):
        splits.assert_blind(evaluator, "holdback-r1", discovery)


def test_the_exposure_log_is_an_append_only_hash_chain(tmp_path):
    discovery, evaluator = _tree(tmp_path)
    splits.create_manifest(evaluator, "holdback-r1", "holdback", _cases(), discovery, now=0)
    first = splits.record_exposure(evaluator, "holdback-r1", "case-a", "hermes", "chat",
                                   "metadata only", "metadata", now=0)
    second = splits.record_exposure(evaluator, "holdback-r1", "case-b", "hermes", "chat",
                                    "nothing read", "none", now=0)
    assert second["prev"] == first["hash"]
    assert splits.verify_chain(evaluator) == []
    # a deleted line breaks the chain instead of going unnoticed
    log = evaluator / splits.EXPOSURE_LOG
    lines = log.read_text(encoding="utf-8").splitlines()
    log.write_text(lines[1] + "\n", encoding="utf-8")
    assert splits.verify_chain(evaluator)


def test_an_edited_exposure_event_breaks_the_chain(tmp_path):
    discovery, evaluator = _tree(tmp_path)
    splits.create_manifest(evaluator, "holdback-r1", "holdback", _cases(), discovery, now=0)
    splits.record_exposure(evaluator, "holdback-r1", "case-a", "hermes", "chat",
                           "metadata only", "metadata", now=0)
    log = evaluator / splits.EXPOSURE_LOG
    event = json.loads(log.read_text(encoding="utf-8"))
    event["contamination"] = "none"          # the interesting forgery: clean up the history
    log.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")
    assert splits.verify_chain(evaluator)


def test_an_unknown_case_or_level_is_refused(tmp_path):
    discovery, evaluator = _tree(tmp_path)
    splits.create_manifest(evaluator, "holdback-r1", "holdback", _cases(), discovery, now=0)
    with pytest.raises(splits.SplitError, match="no case"):
        splits.record_exposure(evaluator, "holdback-r1", "case-zz", "hermes", "chat", "", "none")
    with pytest.raises(splits.SplitError, match="contamination level"):
        splits.record_exposure(evaluator, "holdback-r1", "case-a", "hermes", "chat", "",
                               "probably-fine")
