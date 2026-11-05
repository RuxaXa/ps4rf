"""Corpus validation and training/blind separation checks.

The corpus is only useful if a held-back case stays unknown. That property does not
survive good intentions, so it is enforced here: an entry has a fixed shape, a
`held_back` entry may not describe a root cause, and a `burned` entry must say why it
is burned. `check_separation()` looks for the other half of the leak — a held-back
family described somewhere else in the data directory.

Nothing in this module reads firmware or touches a console.
"""
from __future__ import annotations

import json
import pathlib
import re
from typing import Dict, Iterable, List, Optional

ROLES = ("training", "held_back", "burned", "negative")
PLATFORMS = ("ps4", "ps5")
CONFIDENCE = ("high", "medium", "low")
SOURCE_KINDS = ("writeup", "repo", "advisory")

REQUIRED = ("id", "name", "role", "platform", "bug_class", "subsystem", "root_cause",
            "discovery_approach", "firmware", "patch_evidence", "sources", "confidence",
            "gaps")

#: Fields that would describe the bug itself.  A held-back entry may carry metadata
#: about the case (which firmware family, which subsystem to look at) but must not
#: hand the analyst the answer.
DESCRIPTIVE = ("summary", "primitive", "trigger", "consequence")


def load_corpus(directory: pathlib.Path) -> List[dict]:
    """Every corpus entry under ``directory`` (``*.json``), sorted by id.

    Anything that is not an object with an ``id`` is skipped: a directory may also hold
    reference tables (a top-level list) or indexes, and one of those must not take the
    whole validation down with an ``AttributeError``.
    """
    entries = []
    for path in sorted(pathlib.Path(directory).glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            continue            # e.g. the mitigation table, which is a top-level list
        if "id" not in document:
            continue            # an index or a mapping, not a family
        document.setdefault("_file", path.name)
        entries.append(document)
    return sorted(entries, key=lambda entry: entry["id"])


def _problems_in_root_cause(entry: dict, problems: List[str]) -> None:
    root_cause = entry.get("root_cause") or {}
    if not isinstance(root_cause, dict):
        problems.append(f"{entry['id']}: root_cause must be an object")
        return
    role = entry.get("role")
    missing = [field for field in DESCRIPTIVE if not str(root_cause.get(field, "")).strip()]
    if role == "held_back":
        present = [field for field in DESCRIPTIVE if str(root_cause.get(field, "")).strip()]
        if present:
            problems.append(
                f"{entry['id']}: held_back entries may not describe the bug "
                f"(root_cause.{', root_cause.'.join(present)} must stay empty)")
    elif missing:
        problems.append(f"{entry['id']}: root_cause missing {', '.join(missing)}")


def _problems_in_sources(entry: dict, problems: List[str]) -> None:
    sources = entry.get("sources")
    if not isinstance(sources, list):
        problems.append(f"{entry['id']}: sources must be a list")
        return
    if entry.get("role") != "held_back" and not sources:
        problems.append(f"{entry['id']}: no sources; a claim without a source is not evidence")
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            problems.append(f"{entry['id']}: sources[{index}] must be an object")
            continue
        url = str(source.get("url", ""))
        if not url.startswith(("http://", "https://")):
            problems.append(f"{entry['id']}: sources[{index}] has no fetchable url")
        if not str(source.get("supports", "")).strip():
            problems.append(f"{entry['id']}: sources[{index}] does not say what it supports")
        if source.get("kind") not in SOURCE_KINDS:
            problems.append(f"{entry['id']}: sources[{index}].kind must be one of "
                            f"{SOURCE_KINDS}")
    if entry.get("confidence") == "high" and not sources:
        problems.append(f"{entry['id']}: high confidence without a source")


#: A held-back case must not answer its own question, so the fields that would give the
#: bug class or the patch away are optional for it -- but they must not be *filled*.
HELD_BACK_OPTIONAL = ("bug_class", "patch_evidence")


def validate(entry: dict) -> List[str]:
    """All problems in one entry; empty means valid."""
    problems: List[str] = []
    required = REQUIRED
    if entry.get("role") == "held_back":
        required = tuple(field for field in REQUIRED if field not in HELD_BACK_OPTIONAL)
    missing = [field for field in required if field not in entry]
    if missing:
        problems.append(f"{entry.get('id', '?')}: missing {', '.join(missing)}")
        return problems
    if entry["role"] not in ROLES:
        problems.append(f"{entry['id']}: role must be one of {ROLES}")
    if entry["confidence"] not in CONFIDENCE:
        problems.append(f"{entry['id']}: confidence must be one of {CONFIDENCE}")
    if not entry.get("platform"):
        problems.append(f"{entry['id']}: platform must not be empty")
    for platform in entry.get("platform") or []:
        if platform not in PLATFORMS:
            problems.append(f"{entry['id']}: unknown platform {platform!r}")
    if entry["role"] == "burned" and not str(entry.get("burned_reason", "")).strip():
        problems.append(f"{entry['id']}: a burned entry must say why it is burned")
    approach = entry.get("discovery_approach") or {}
    if entry["role"] == "held_back" and approach.get("blind_usable"):
        problems.append(f"{entry['id']}: a held_back entry cannot claim blind_usable")
    if entry["role"] != "held_back" and approach.get("blind_usable"):
        # describing a root cause here is precisely what makes a case unusable blind
        problems.append(f"{entry['id']}: blind_usable must be false once the root cause "
                        f"is written down")
    firmware = entry.get("firmware") or {}
    if not isinstance(firmware, dict) or "affected" not in firmware:
        problems.append(f"{entry['id']}: firmware.affected is required")
    _problems_in_root_cause(entry, problems)
    _problems_in_sources(entry, problems)
    return problems


def check_separation(corpus: Iterable[dict], data_directory: pathlib.Path) -> List[str]:
    """Held-back cases must not be described anywhere else in the data directory.

    The sources of a leak are mundane: a family note that summarises the bug, a
    training reference that names the affected driver, a fixture comment.  Matching is
    deliberately crude — the entry's family name as a whole word plus, for a held-back
    entry, any distinctive phrase from its name.
    """
    problems: List[str] = []
    data_directory = pathlib.Path(data_directory)
    documents: Dict[pathlib.Path, str] = {}
    for path in sorted(data_directory.rglob("*")):
        if path.is_file() and path.suffix in (".json", ".md", ".txt"):
            try:
                documents[path] = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
    for entry in corpus:
        if entry.get("role") != "held_back":
            continue
        # Both the family name and its identifier are matched: a note that says
        # "the fam-x bug" leaks just as much as one that spells out the name, and the
        # identifier is the shorter, more likely string to appear.
        words = [word for word in re.split(r"[^a-z0-9]+", str(entry["name"]).lower())
                 if len(word) >= 5]
        words += [word for word in re.split(r"[^a-z0-9]+", str(entry["id"]).lower())
                  if len(word) >= 4 and word not in words]
        for path, text in documents.items():
            if path.name == entry.get("_file"):
                continue
            lowered = text.lower()
            hits = [word for word in words if re.search(rf"\b{re.escape(word)}\b", lowered)]
            if hits:
                problems.append(
                    f"{entry['id']}: held_back family is described in {path.name} "
                    f"({', '.join(sorted(hits)[:3])})")
    return problems


def validate_all(directory: pathlib.Path,
                 data_directory: Optional[pathlib.Path] = None) -> List[str]:
    """Validate every entry plus the separation property for the whole directory."""
    corpus = load_corpus(directory)
    problems: List[str] = []
    for entry in corpus:
        problems.extend(validate(entry))
    identifiers = [entry["id"] for entry in corpus]
    duplicates = {i for i in identifiers if identifiers.count(i) > 1}
    if duplicates:
        problems.append(f"duplicate corpus ids: {', '.join(sorted(duplicates))}")
    problems.extend(check_separation(corpus, data_directory or pathlib.Path(directory).parent))
    return problems


MITIGATION_REQUIRED = ("id", "feature", "first_firmware_seen", "evidence", "confidence",
                       "notes")


def validate_mitigation(row: dict) -> List[str]:
    """Problems in one firmware-mitigation row; empty means usable.

    ``first_firmware_seen`` is allowed to be ``None``: "no public source shows this
    feature" is a finding, not a missing field.  What is not allowed is a null without an
    explanation, or evidence-free confidence.
    """
    problems: List[str] = []
    missing = [field for field in MITIGATION_REQUIRED if field not in row]
    if missing:
        problems.append(f"{row.get('id', '?')}: missing {', '.join(missing)}")
        return problems
    if not str(row.get("feature", "")).strip():
        problems.append(f"{row['id']}: feature must not be empty")
    if not str(row.get("evidence", "")).strip():
        problems.append(f"{row['id']}: no evidence; an unsourced mitigation claim is a guess")
    if row.get("confidence") not in CONFIDENCE:
        problems.append(f"{row['id']}: confidence must be one of {CONFIDENCE}")
    if row.get("first_firmware_seen") is None and not str(row.get("notes", "")).strip():
        problems.append(f"{row['id']}: a null first_firmware_seen needs a note saying why")
    return problems


def validate_mitigations(rows: Iterable[dict]) -> List[str]:
    """Validate a whole mitigation table, including duplicate identifiers."""
    rows = list(rows)
    problems: List[str] = []
    for row in rows:
        if not isinstance(row, dict):
            problems.append("mitigation rows must be objects")
            continue
        problems.extend(validate_mitigation(row))
    identifiers = [row.get("id") for row in rows if isinstance(row, dict)]
    duplicates = {i for i in identifiers if identifiers.count(i) > 1}
    if duplicates:
        problems.append(f"duplicate mitigation ids: {', '.join(sorted(duplicates))}")
    return problems
