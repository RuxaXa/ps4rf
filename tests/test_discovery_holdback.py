"""Holdback tests.

Withholding a family is the step that makes a blind test possible and the step most
likely to go wrong quietly: a key written inside the sealed tree, a family still explained
in a neighbouring note, or a "held-back" entry that kept its root cause. Each of those is a
test here, and the audit reports described vs. blind so the count cannot be assumed.
"""
from __future__ import annotations

import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.discovery import corpus, holdback


def entry(**overrides):
    base = {
        "id": "fam-x",
        "name": "Fam X overflow",
        "role": "training",
        "burned_reason": "",
        "platform": ["ps4"],
        "bug_class": "HEAP_OVERFLOW",
        "subsystem": "kernel/x",
        "root_cause": {"summary": "an unchecked length reaches a copy",
                       "primitive": "linear overflow", "trigger": "a long field",
                       "consequence": "adjacent object corrupted"},
        "discovery_approach": {"summary": "diff two builds", "signals": ["len"],
                               "blind_usable": False},
        "firmware": {"affected": ["9.00"], "fixed_in": "9.03", "differences": ["guard"]},
        "patch_evidence": {"available": True, "what": "advisory", "limits": "no bytes"},
        "sources": [{"url": "https://example.invalid/a", "supports": "mechanism",
                     "kind": "writeup"}],
        "confidence": "medium",
        "gaps": [],
    }
    base.update(overrides)
    return base


@pytest.fixture()
def tree(tmp_path):
    data = tmp_path / "data"
    (data / "corpus").mkdir(parents=True)
    (data / "corpus" / "fam-x.json").write_text(json.dumps(entry()), encoding="utf-8")
    return data


def test_withholding_splits_question_and_answer(tree, tmp_path):
    keys = tmp_path / "keys"
    result = holdback.withhold("fam-x", corpus_dir=tree / "corpus", key_dir=keys)
    assert result["dry_run"] is False
    held = json.loads((tree / "corpus" / "fam-x.json").read_text())
    assert held["role"] == "held_back"
    assert held["root_cause"] == {}
    assert held["discovery_approach"] == {}
    assert held["subsystem"] == "kernel/x"          # the question survives
    answer = json.loads((keys / "fam-x.key.json").read_text())
    assert "unchecked length" in answer["root_cause"]["summary"]
    assert answer["bug_class"] == "HEAP_OVERFLOW"


def test_the_held_back_entry_still_validates(tree, tmp_path):
    holdback.withhold("fam-x", corpus_dir=tree / "corpus", key_dir=tmp_path / "keys")
    held = json.loads((tree / "corpus" / "fam-x.json").read_text())
    assert corpus.validate(held) == []


def test_a_key_inside_the_sealed_root_is_refused(tree):
    with pytest.raises(holdback.WithholdRefused) as exc:
        holdback.withhold("fam-x", corpus_dir=tree / "corpus", key_dir=tree / "keys")
    assert "outside the sealed data root" in str(exc.value)


def test_a_family_described_elsewhere_cannot_be_withheld(tree, tmp_path):
    (tree / "notes.md").write_text(
        "note: in the Fam X overflow the length reaches the copy unchecked", encoding="utf-8")
    with pytest.raises(holdback.WithholdRefused) as exc:
        holdback.withhold("fam-x", corpus_dir=tree / "corpus", key_dir=tmp_path / "keys")
    assert "still described elsewhere" in str(exc.value)


def test_a_family_without_a_root_cause_is_refused(tree, tmp_path):
    (tree / "corpus" / "fam-x.json").write_text(
        json.dumps(entry(root_cause={}, discovery_approach={}, role="held_back")),
        encoding="utf-8")
    with pytest.raises(holdback.WithholdRefused) as exc:
        holdback.withhold("fam-x", corpus_dir=tree / "corpus", key_dir=tmp_path / "keys")
    assert "no root cause to withhold" in str(exc.value)


def test_an_unknown_family_is_refused(tree, tmp_path):
    with pytest.raises(holdback.WithholdRefused):
        holdback.withhold("nope", corpus_dir=tree / "corpus", key_dir=tmp_path / "keys")


def test_dry_run_changes_nothing(tree, tmp_path):
    before = (tree / "corpus" / "fam-x.json").read_text()
    result = holdback.withhold("fam-x", corpus_dir=tree / "corpus",
                               key_dir=tmp_path / "keys", dry_run=True)
    assert result["dry_run"] is True
    assert (tree / "corpus" / "fam-x.json").read_text() == before
    assert not (tmp_path / "keys").exists()


def test_the_audit_counts_what_is_actually_blind(tree):
    holdback_audit = holdback.audit(tree / "corpus")
    assert holdback_audit["described"] == ["fam-x"]
    assert holdback_audit["held_back"] == []


def test_the_audit_sees_a_withheld_family(tmp_path):
    data = tmp_path / "data"
    (data / "corpus").mkdir(parents=True)
    holdback_audit = holdback.audit(data / "corpus")
    assert holdback_audit["total"] == 0
