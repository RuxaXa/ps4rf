"""Withhold a family: keep the question, move the answer outside the repository.

A blind case is only blind if the repository stops describing it.  That is not a promise a
maintainer can keep by being careful, so it is a mechanical split:

* the corpus entry stays, reduced to what a test case may legitimately tell the engine --
  platform, subsystem, firmware band, bug class at most, and the sources it may look up;
* the root cause, the mechanism and the firmware difference move to an answer key written
  **outside** the data root, where ``seal`` refuses to read them during a run.

``withhold`` therefore refuses to write a key inside the sealed area, and it refuses to
withhold a family that is described anywhere else in the data directory -- withholding a
family that is still explained in a neighbouring note would produce a blind case that is
blind only on paper.
"""
from __future__ import annotations

import json
import pathlib
from typing import Iterable, List, Optional, Sequence

from . import corpus as corpus_mod

#: Fields the held-back case keeps.  Anything that would answer the question is not here.
KEPT = ("id", "name", "role", "platform", "subsystem", "firmware", "sources", "confidence",
        "gaps")
#: Fields that move to the answer key.  ``bug_class`` is in here because the engine is
#: given an image and nothing else; a held-back case that names the bug class has already
#: answered a third of the question.
MOVED = ("root_cause", "discovery_approach", "patch_evidence", "burned_reason", "bug_class")


class WithholdRefused(RuntimeError):
    """The split cannot be made without leaking or without a silent loss."""


def _leaks(entry: dict, data_directory: pathlib.Path,
           own_filename: str = "") -> List[str]:
    """A family may not be described anywhere else in the data directory.

    ``check_separation`` only inspects held-back entries, so the candidate is checked as
    the held-back case it is about to become -- otherwise the leak check would pass because
    of the role the entry still has.
    """
    candidate = dict(entry, role="held_back", _file=own_filename)
    return corpus_mod.check_separation([candidate], data_directory)


def withhold(family_id: str, *, corpus_dir: pathlib.Path, key_dir: pathlib.Path,
             data_directory: Optional[pathlib.Path] = None,
             dry_run: bool = False) -> dict:
    """Split one corpus entry into a held-back case and an out-of-tree answer key."""
    corpus_dir = pathlib.Path(corpus_dir)
    key_dir = pathlib.Path(key_dir)
    data_directory = pathlib.Path(data_directory) if data_directory else corpus_dir.parent
    entry_path = corpus_dir / f"{family_id}.json"
    if not entry_path.exists():
        raise WithholdRefused(f"no corpus entry {entry_path.name}")
    if str(key_dir.resolve()).startswith(str(data_directory.resolve()) + "/"):
        raise WithholdRefused(
            f"the answer key must live outside the sealed data root; {key_dir} is inside "
            f"{data_directory}")

    entry = json.loads(entry_path.read_text(encoding="utf-8"))
    if not str((entry.get("root_cause") or {}).get("summary", "")).strip():
        raise WithholdRefused(
            f"{family_id} has no root cause to withhold -- it may already be held back")
    leaks = _leaks(entry, data_directory, entry_path.name)
    if leaks:
        raise WithholdRefused(
            "the family is still described elsewhere, so withholding it would not make it "
            "blind: " + "; ".join(leaks))

    held_back = {key: entry[key] for key in KEPT if key in entry}
    held_back["role"] = "held_back"
    for field in MOVED:
        held_back.pop(field, None)
    held_back["root_cause"] = {}
    held_back["discovery_approach"] = {}
    held_back["burned_reason"] = ""
    answer_key = {
        "id": family_id,
        "site": None,          # filled in by whoever pins the key to a firmware build
        "bug_class": entry.get("bug_class"),
        "root_cause": entry.get("root_cause"),
        "discovery_approach": entry.get("discovery_approach"),
        "patch_evidence": entry.get("patch_evidence"),
        "withheld_from": str(entry_path.name),
    }
    problems = corpus_mod.validate(held_back)
    if problems:
        raise WithholdRefused("the held-back case would be invalid: " + "; ".join(problems))

    result = {
        "family": family_id,
        "held_back_file": str(entry_path),
        "key_file": str(key_dir / f"{family_id}.key.json"),
        "dry_run": dry_run,
        "moved_fields": [field for field in MOVED if field in entry],
        "kept_fields": sorted(held_back),
    }
    if dry_run:
        return result
    key_dir.mkdir(parents=True, exist_ok=True)
    (key_dir / f"{family_id}.key.json").write_text(
        json.dumps(answer_key, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    entry_path.write_text(json.dumps(held_back, indent=2, ensure_ascii=False) + "\n",
                          encoding="utf-8")
    return result


def audit(corpus_dir: pathlib.Path, data_directory: Optional[pathlib.Path] = None) -> dict:
    """Which entries are still answerable from the repository, and which are not.

    Reported before a blind run so that "we have blind cases" is a count and not a feeling.
    """
    corpus_dir = pathlib.Path(corpus_dir)
    data_directory = pathlib.Path(data_directory) if data_directory else corpus_dir.parent
    entries = corpus_mod.load_corpus(corpus_dir)
    blind: List[str] = []
    described: List[str] = []
    for entry in entries:
        if str((entry.get("root_cause") or {}).get("summary", "")).strip():
            described.append(entry["id"])
        else:
            blind.append(entry["id"])
    return {"total": len(entries), "described": described, "held_back": blind,
            "data_directory": str(data_directory)}
