"""Deterministic indexer for an operator-provided GTFOBins corpus.

The corpus is an EXTERNAL input (path configurable, never vendored into this
repository). One entry file per binary, in the upstream GTFOBins on-disk
format confirmed against the public project (provenance with URLs and
sha256s in ``tests/fixtures/gtfobins/README.md``):

* the file is a single YAML document starting with the ``---`` front matter
  delimiter (a trailing ``...`` closes it and is tolerated either way);
* ``functions`` maps a function name to a non-empty list of examples;
* every example carries a non-empty ``contexts`` mapping with keys from
  ``unprivileged``, ``sudo``, ``suid``, ``capabilities``;
* examples may carry an optional ``version`` constraint (string, int or
  float), surfaced in the index without ever being evaluated;
* a ``capabilities`` context may declare ``list: [CAP_*, ...]`` -- the Linux
  capabilities required for that route;
* an alias entry is ``alias: <entry-name>`` and resolves within the corpus.

What lands in the index (deterministic: sorted keys, no timestamps, no
absolute paths, trailing newline):

* ``functions`` -- sorted union of normalized function names (upstream names
  with hyphens mapped to underscores) and privilege-route markers
  (``sudo``, ``suid``, ``capabilities``) declared anywhere in the entry;
* ``contexts`` -- per-function declared routes (precise gating data);
* ``capability_requirements`` -- per-function list of requirement sets
  (empty inner list = "any declared capability");
* ``version_constraints`` -- sorted union of example-level versions;
* ``sha256`` per file plus one aggregate ``corpus_sha256``.

Fail closed: unparsable entries, unknown function names, unknown context
names, broken aliases and duplicate entry names are refusals; nothing is
guessed. Recipe fields (``code``, ``comment`` and similar) are ignored and
never stored, so no recipe text can reach the index.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import ValidationError

from .models import (CONTEXT_NAMES, FUNCTION_NAMES, GtfobinsConfigError,
                     GtfobinsCorpusDrift, GtfobinsCorpusError, GtfobinsIndex,
                     GtfobinsIndexEntry, GtfobinsIndexError,
                     GtfobinsUnknownFunction, INDEX_SCHEMA_ID, MARKER_NAMES,
                     REFERENCE_TEMPLATE)

Generated = tuple[list[str], dict[str, list[str]], dict[str, list[list[str]]], list[str]]
"""Resolved entry routes: (functions, contexts, capability_requirements, versions)."""


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _iter_entry_files(corpus: Path) -> list[Path]:
    """All non-hidden regular files under ``corpus`` (sorted, deterministic)."""
    if not corpus.is_dir():
        raise GtfobinsConfigError(f"corpus directory not found: {corpus}")
    files = []
    for path in corpus.rglob("*"):
        if not path.is_file():
            continue
        parts = path.relative_to(corpus).parts
        if any(part.startswith(".") for part in parts):
            continue
        files.append(path)
    return sorted(files)


def _read_document(path: Path) -> Any:
    """Parse one entry file into a YAML mapping; anything else is a refusal."""
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GtfobinsCorpusError(
            f"corpus entry {path.name!r} is not valid UTF-8: {exc}") from exc
    if not text.lstrip("\ufeff").startswith("---"):
        raise GtfobinsCorpusError(
            f"corpus entry {path.name!r} has no front matter delimiter '---'")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise GtfobinsCorpusError(
            f"corpus entry {path.name!r} is not parsable YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise GtfobinsCorpusError(
            f"corpus entry {path.name!r} must be a YAML mapping")
    return data


def _normalize_function_key(key: Any) -> Optional[str]:
    if not isinstance(key, str):
        return None
    return key.strip().lower().replace("-", "_")


def _normalize_capability(name: str, entry: str, function: str) -> str:
    if not isinstance(name, str) or not name.strip():
        raise GtfobinsCorpusError(
            f"corpus entry {entry!r}: capability list of function {function!r} "
            "must hold non-empty strings")
    return name.strip().upper()


def _version_text(version: Any, entry: str, function: str) -> str:
    if isinstance(version, bool) or not isinstance(version, (str, int, float)):
        raise GtfobinsCorpusError(
            f"corpus entry {entry!r}: version of function {function!r} must be "
            "a string, int or float")
    text = version.strip() if isinstance(version, str) else str(version)
    if not text:
        raise GtfobinsCorpusError(
            f"corpus entry {entry!r}: version of function {function!r} is empty")
    return text


def _extract_routes(path_name: str, data: dict[str, Any]) -> Generated:
    """Extract route data of a normal (non-alias) entry; fail closed."""
    functions = data.get("functions")
    if not isinstance(functions, dict) or not functions:
        raise GtfobinsCorpusError(
            f"corpus entry {path_name!r} must declare a non-empty 'functions' mapping")
    contexts: dict[str, set[str]] = {}
    capability_sets: dict[str, set[tuple[str, ...]]] = {}
    versions: set[str] = set()
    for raw_key, examples in functions.items():
        name = _normalize_function_key(raw_key)
        if name is None or name not in FUNCTION_NAMES:
            raise GtfobinsUnknownFunction(
                f"corpus entry {path_name!r}: unknown function {raw_key!r} "
                f"(known: {', '.join(sorted(FUNCTION_NAMES))})")
        if not isinstance(examples, list) or not examples:
            raise GtfobinsCorpusError(
                f"corpus entry {path_name!r}: function {raw_key!r} must carry a "
                "non-empty list of examples")
        routes = contexts.setdefault(name, set())
        caps = capability_sets.setdefault(name, set())
        for example in examples:
            if not isinstance(example, dict):
                raise GtfobinsCorpusError(
                    f"corpus entry {path_name!r}: function {raw_key!r} example "
                    "must be a mapping")
            version = example.get("version")
            if version is not None:
                versions.add(_version_text(version, path_name, str(raw_key)))
            declared = example.get("contexts")
            if not isinstance(declared, dict) or not declared:
                raise GtfobinsCorpusError(
                    f"corpus entry {path_name!r}: function {raw_key!r} example "
                    "needs a non-empty 'contexts' mapping")
            for raw_context, detail in declared.items():
                context = (raw_context.strip().lower()
                           if isinstance(raw_context, str) else None)
                if context not in CONTEXT_NAMES:
                    raise GtfobinsCorpusError(
                        f"corpus entry {path_name!r}: unknown context {raw_context!r} "
                        f"in function {raw_key!r}")
                if detail is not None and not isinstance(detail, dict):
                    raise GtfobinsCorpusError(
                        f"corpus entry {path_name!r}: context {raw_context!r} must "
                        "be null or a mapping")
                routes.add(context)
                if context == "capabilities":
                    required: list[str] = []
                    declared_list = detail.get("list") if isinstance(detail, dict) else None
                    if declared_list is not None:
                        if not isinstance(declared_list, list) or not declared_list:
                            raise GtfobinsCorpusError(
                                f"corpus entry {path_name!r}: capability list of "
                                f"function {raw_key!r} must be a non-empty list")
                        required = sorted({_normalize_capability(item, path_name,
                                                                 str(raw_key))
                                           for item in declared_list})
                    caps.add(tuple(required))
    flat_functions = sorted(set(contexts)
                            | {route for routes in contexts.values() for route in routes
                               if route in MARKER_NAMES})
    return (flat_functions,
            {name: sorted(routes) for name, routes in contexts.items()},
            {name: [list(items) for items in sorted(sets)]
             for name, sets in capability_sets.items() if sets},
            sorted(versions))


def _resolve_entry(entry: str, documents: dict[str, Any], stack: list[str]) -> tuple[Optional[str], Generated]:
    """Resolve one entry (following aliases); returns (direct alias or None, routes)."""
    if entry in stack:
        raise GtfobinsCorpusError(
            f"corpus entry {entry!r}: alias cycle {' -> '.join([*stack, entry])}")
    data = documents[entry]
    if "alias" in data:
        target = data.get("alias")
        if not isinstance(target, str) or not target.strip():
            raise GtfobinsCorpusError(
                f"corpus entry {entry!r}: 'alias' must be a non-empty string")
        if list(data.keys()) != ["alias"]:
            raise GtfobinsCorpusError(
                f"corpus entry {entry!r}: an alias entry carries only the 'alias' key")
        target = target.strip()
        if target not in documents:
            raise GtfobinsCorpusError(
                f"corpus entry {entry!r}: alias target {target!r} is not in the corpus")
        _, resolved = _resolve_entry(target, documents, [*stack, entry])
        return target, resolved
    return None, _extract_routes(entry, data)


def build_index(corpus_dir: str | Path) -> GtfobinsIndex:
    """Build the deterministic index for one corpus snapshot (fail closed)."""
    corpus = Path(corpus_dir)
    files = _iter_entry_files(corpus)
    if not files:
        raise GtfobinsCorpusError(f"no corpus entries under {corpus}")
    documents: dict[str, Any] = {}
    positions: dict[str, tuple[str, str]] = {}
    for path in files:
        name = path.name
        if name in documents:
            raise GtfobinsCorpusError(f"duplicate corpus entry name {name!r}")
        documents[name] = _read_document(path)
        positions[name] = (path.relative_to(corpus).as_posix(),
                           _sha256_bytes(path.read_bytes()))
    entries: dict[str, GtfobinsIndexEntry] = {}
    for name in documents:
        alias, (functions, contexts, capability_requirements,
                versions) = _resolve_entry(name, documents, [])
        relative_path, digest = positions[name]
        entries[name] = GtfobinsIndexEntry.model_validate({
            "relative_path": relative_path, "sha256": digest,
            "functions": functions, "contexts": contexts,
            "capability_requirements": capability_requirements,
            "version_constraints": versions,
            "reference": REFERENCE_TEMPLATE.format(binary=name), "alias": alias})
    relative_paths = sorted(
        (positions[name][0], positions[name][1]) for name in positions)
    corpus_hash = _sha256_bytes("".join(
        f"{relative_path}\t{digest}\n"
        for relative_path, digest in relative_paths).encode("utf-8"))
    return GtfobinsIndex(schema=INDEX_SCHEMA_ID, corpus_sha256=corpus_hash,
                         entries=dict(sorted(entries.items())))


def index_sha256(index: GtfobinsIndex) -> str:
    """sha256 of the canonical index serialization (pin this value)."""
    return _sha256_bytes(index.to_json().encode("utf-8"))


def write_index(index: GtfobinsIndex, path: str | Path) -> str:
    """Write the index deterministically; returns the sha256 of the bytes."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    text = index.to_json()
    target.write_text(text, encoding="utf-8")
    return _sha256_bytes(text.encode("utf-8"))


def load_index(path: str | Path) -> GtfobinsIndex:
    """Load and validate a pinned index document (fail closed)."""
    source = Path(path)
    if not source.is_file():
        raise GtfobinsConfigError(f"index file not found: {source}")
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GtfobinsIndexError(f"index is not valid JSON: {exc}") from exc
    try:
        return GtfobinsIndex.model_validate(document)
    except ValidationError as exc:
        raise GtfobinsIndexError(f"index does not satisfy {INDEX_SCHEMA_ID}: {exc}") from exc


def verify_corpus(index: GtfobinsIndex, corpus_dir: str | Path) -> bool:
    """Re-hash the corpus and compare it with the pinned index (drift = refusal)."""
    corpus = Path(corpus_dir)
    files = _iter_entry_files(corpus)
    if not files:
        raise GtfobinsCorpusDrift(f"corpus under {corpus} holds no entries")
    found: dict[str, str] = {}
    for path in files:
        relative_path = path.relative_to(corpus).as_posix()
        found[relative_path] = _sha256_bytes(path.read_bytes())
    expected: dict[str, str] = {}
    for entry in index.entries.values():
        if entry.relative_path in expected:
            raise GtfobinsCorpusDrift(
                "index tracks the same relative path more than once")
        expected[entry.relative_path] = entry.sha256
    problems: list[str] = []
    for relative_path in sorted(set(expected) - set(found)):
        problems.append(f"missing on disk: {relative_path}")
    for relative_path in sorted(set(found) - set(expected)):
        problems.append(f"untracked on disk: {relative_path}")
    for relative_path in sorted(set(found) & set(expected)):
        if found[relative_path] != expected[relative_path]:
            problems.append(f"content drifted: {relative_path}")
    recomputed = _sha256_bytes("".join(
        f"{relative_path}\t{found[relative_path]}\n"
        for relative_path in sorted(found)).encode("utf-8"))
    if recomputed != index.corpus_sha256:
        problems.append("aggregate corpus hash does not match the index")
    if problems:
        raise GtfobinsCorpusDrift("; ".join(problems))
    return True


__all__ = ["build_index", "index_sha256", "write_index", "load_index", "verify_corpus"]
