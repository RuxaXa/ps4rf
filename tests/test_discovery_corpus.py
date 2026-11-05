"""Corpus shape and separation tests.

The separation policy is a claim about what the repository does *not* contain. These
tests are what makes that claim checkable: a held-back family must not describe its bug
and must not be described anywhere else in the data directory.
"""
from __future__ import annotations

import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.discovery import corpus

DATA = ROOT / "tools" / "discovery" / "data"
CORPUS = DATA / "corpus"


def entry(**overrides) -> dict:
    base = {
        "id": "example",
        "name": "Example family",
        "role": "training",
        "burned_reason": "",
        "platform": ["ps4"],
        "bug_class": "UAF",
        "subsystem": "kernel/example",
        "root_cause": {"summary": "a reference is dropped twice",
                       "primitive": "double drop",
                       "trigger": "closing a handle twice",
                       "consequence": "freed object stays reachable"},
        "discovery_approach": {"summary": "read the teardown path",
                               "signals": ["unbalanced drop"],
                               "blind_usable": False},
        "firmware": {"affected": ["9.00"], "fixed_in": "10.00", "differences": ["check added"]},
        "patch_evidence": {"available": True, "what": "writeup", "limits": "no bytes stored"},
        "sources": [{"url": "https://example.invalid/writeup",
                     "supports": "the mechanism", "kind": "writeup"}],
        "confidence": "medium",
        "gaps": [],
    }
    base.update(overrides)
    return base


def test_a_complete_training_entry_is_valid():
    assert corpus.validate(entry()) == []


def test_held_back_entry_may_not_describe_the_bug():
    held = entry(role="held_back", name="Held family",
                 root_cause={"summary": "a reference is dropped twice"},
                 sources=[])
    problems = corpus.validate(held)
    assert any("held_back" in p and "may not describe" in p for p in problems), problems


def test_held_back_metadata_alone_is_valid():
    held = entry(role="held_back", name="Held family",
                 root_cause={}, sources=[], confidence="low")
    assert corpus.validate(held) == []


def test_burned_entry_must_state_why():
    problems = corpus.validate(entry(role="burned", burned_reason=""))
    assert any("why it is burned" in p for p in problems), problems


def test_a_described_root_cause_cannot_claim_blind_usable():
    problems = corpus.validate(entry(discovery_approach={
        "summary": "read it", "signals": [], "blind_usable": True}))
    assert any("blind_usable" in p for p in problems), problems


def test_high_confidence_needs_a_source():
    problems = corpus.validate(entry(confidence="high", sources=[]))
    assert any("source" in p for p in problems), problems


def test_sources_must_say_what_they_support():
    problems = corpus.validate(entry(sources=[{"url": "https://example.invalid",
                                               "supports": "", "kind": "writeup"}]))
    assert any("what it supports" in p for p in problems), problems


def test_unknown_role_and_platform_are_refused():
    problems = corpus.validate(entry(role="maybe", platform=["ps6"]))
    assert any("role must be" in p for p in problems)
    assert any("unknown platform" in p for p in problems)


def test_a_held_back_family_described_elsewhere_is_a_leak(tmp_path):
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    held = entry(role="held_back", name="Spppzone overflow family",
                 root_cause={}, sources=[], confidence="low")
    (corpus_dir / "spppzone.json").write_text(json.dumps(held), encoding="utf-8")
    (tmp_path / "notes.md").write_text(
        "training note: the Spppzone overflow family lives in the ppp driver",
        encoding="utf-8")
    problems = corpus.validate_all(corpus_dir, tmp_path)
    assert any("leak" in p.lower() or "described in" in p for p in problems), problems


def test_an_unrelated_note_is_not_a_leak(tmp_path):
    corpus_dir = tmp_path / "corpus"
    corpus_dir.mkdir()
    held = entry(role="held_back", name="Spppzone overflow family",
                 root_cause={}, sources=[], confidence="low")
    (corpus_dir / "spppzone.json").write_text(json.dumps(held), encoding="utf-8")
    (tmp_path / "notes.md").write_text("training note about http parsing",
                                       encoding="utf-8")
    assert corpus.validate_all(corpus_dir, tmp_path) == []


def test_the_committed_corpus_is_valid():
    """Whatever is committed must satisfy the policy — no exceptions, no skips."""
    if not CORPUS.exists():
        pytest.skip("corpus directory not created yet")
    problems = corpus.validate_all(CORPUS, DATA)
    assert problems == [], "\n".join(problems)


def mitigation(**overrides):
    base = {"id": "ps4-kaslr", "feature": "PS4: kernel ASLR", "first_firmware_seen": "2.xx",
            "evidence": "S1 slide: 'Enabled in 2.xx'", "confidence": "high",
            "notes": "exact 2.xx version not established"}
    base.update(overrides)
    return base


def test_a_complete_mitigation_row_is_valid():
    assert corpus.validate_mitigation(mitigation()) == []


def test_a_null_first_firmware_seen_needs_an_explanation():
    problems = corpus.validate_mitigation(mitigation(first_firmware_seen=None, notes=""))
    assert any("null first_firmware_seen" in p for p in problems), problems


def test_a_mitigation_without_evidence_is_refused():
    problems = corpus.validate_mitigation(mitigation(evidence=" "))
    assert any("no evidence" in p for p in problems), problems


def test_duplicate_mitigation_ids_are_refused():
    problems = corpus.validate_mitigations([mitigation(), mitigation()])
    assert any("duplicate mitigation ids" in p for p in problems), problems


def test_the_committed_mitigation_table_is_valid():
    path = ROOT / "tools" / "discovery" / "data" / "reference" / "mitigations.json"
    if not path.exists():
        pytest.skip("mitigation table not present")
    rows = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(rows, list) and rows, "the table must be a non-empty list"
    assert corpus.validate_mitigations(rows) == [], corpus.validate_mitigations(rows)


def test_the_firmware_map_marks_every_row_as_sourced_inferred_or_unknown():
    """The map is allowed to say UNKNOWN; it is not allowed to state a fact unmarked."""
    path = ROOT / "tools" / "discovery" / "data" / "reference" / "FIRMWARE-MAP.md"
    if not path.exists():
        pytest.skip("firmware map not present")
    text = path.read_text(encoding="utf-8")
    assert "UNKNOWN" in text and "SOURCED" in text and "INFERRED" in text
    for mark in ("SOURCED", "INFERRED", "UNKNOWN"):
        assert text.count(mark) > 1, f"{mark} appears only as a definition, not in rows"


def test_a_reference_table_in_the_same_directory_does_not_break_loading(tmp_path):
    """Reported from a sibling pass: a top-level list made load_corpus raise."""
    (tmp_path / "mitigations.json").write_text('[{"id": "ps4-kaslr"}]', encoding="utf-8")
    (tmp_path / "family.json").write_text(json.dumps(entry()), encoding="utf-8")
    loaded = corpus.load_corpus(tmp_path)
    assert [item["id"] for item in loaded] == ["example"]


def test_families_that_are_burned_are_not_used_as_blind_cases():
    """A family named in families.json has its root cause in the repo: it is burned.

    Matching is by family prefix as well as by id, because the corpus names a concrete
    bug (``lapse-aio-multi-delete``) while ``families.json`` names the family (``lapse``).
    An exact-id check let four described families keep a training role.
    """
    families_path = DATA / "families" / "families.json"
    if not families_path.exists():
        pytest.skip("families.json not present")
    families = {fam["id"] for fam in json.loads(families_path.read_text())["families"]}
    described = []
    for item in corpus.load_corpus(CORPUS) if CORPUS.exists() else []:
        matches = {fam for fam in families
                   if item["id"] == fam or item["id"].startswith(f"{fam}-")}
        if matches:
            described.append(item["id"])
            assert item["role"] == "burned", (
                f"{item['id']} belongs to the described family {sorted(matches)[0]} but is "
                f"marked {item['role']}: a described root cause is burned by definition")
            assert item["burned_reason"].strip(), f"{item['id']} must say why it is burned"
        assert item["discovery_approach"].get("blind_usable") is not True
    assert described, ("no corpus entry maps to families.json -- either the families were "
                       "renamed or this test stopped checking anything")


def test_the_committed_label_scope_says_unlabelled_is_unknown():
    """A1-09 is a labelling rule, and until this test existed nothing stopped the rule from
    being dropped in the next corpus revision."""
    doc = json.loads((DATA / "training" / "references.json").read_text(encoding="utf-8"))
    entries = {row["id"]: row for row in doc["references"] if "id" in row}
    scope = entries["fw1352-frozen-corpus"]
    assert scope["label_scope"] == "corrected-functions-only"
    assert scope["unlabeled_functions"] == "unknown"
    assert "never a true negative" in scope["note"].lower()
