"""GTFOBins knowledge adapter tests (pure data, offline, nothing executed).

Everything runs offline against the synthetic fixture corpus in
``tests/fixtures/gtfobins/``. The pinned values come from
``tests/fixtures/gtfobins/README.md``: the aggregate corpus hash and the
index sha256 are pinned separately, so drift between corpus, indexer and
fixtures is detected. The static guard verifies that no module under
``tools/knowledge/`` grows process/network/exec capabilities.

Run from the repo root:

    .venv/bin/python -m pytest -q tests/test_gtfobins_adapter.py
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from tools.knowledge.gtfobins import (EnumeratedBinary, GtfobinsAdapter,
                                      GtfobinsCandidate, GtfobinsConfig,
                                      GtfobinsConfigError, GtfobinsCorpusDrift,
                                      GtfobinsCorpusError, GtfobinsIndex,
                                      GtfobinsIndexError, GtfobinsStateError,
                                      GtfobinsUnknownFunction, build_index,
                                      index_sha256, load_index, match_binary,
                                      verify_corpus, write_index)

REPO = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "gtfobins"
CORPUS = FIXTURES / "corpus"
INDEX_FIXTURE = FIXTURES / "index-v1.json"

CORPUS_SHA = "0d4f9c0d361760e6f5517ce49e80df6c43aa0784943cf21299a0f02587025ee2"
INDEX_SHA = "ea380ae47a3606e6202ea8251ce5f624ca4f41820889c16a577c3709d7396b6f"

CANDIDATE_FIELDS = {"source", "technique", "classification",
                    "requires_verification", "binary", "functions",
                    "preconditions", "reference"}
FORBIDDEN_CANDIDATE_SUBSTRINGS = ("`", "sh -c", "/bin/sh")

ENTRY_FILES = {
    "tools/knowledge/__init__.py",
    "tools/knowledge/gtfobins/__init__.py",
    "tools/knowledge/gtfobins/models.py",
    "tools/knowledge/gtfobins/indexer.py",
    "tools/knowledge/gtfobins/matcher.py",
    "tools/knowledge/gtfobins/adapter.py",
}


def _record(name: str, *, version: str | None = None, owner: str = "root",
            mode: str = "0755", suid: bool = False, sgid: bool = False,
            capabilities: tuple[str, ...] = (),
            execution_context: str = "session") -> EnumeratedBinary:
    return EnumeratedBinary(
        binary_path=f"/usr/bin/{name}", name=name, version=version, owner=owner,
        mode=mode, suid=suid, sgid=sgid, capabilities=list(capabilities),
        execution_context=execution_context)  # type: ignore[arg-type]  # under-test validation


def _functions(candidate: GtfobinsCandidate) -> list[str]:
    return [technique.value for technique in candidate.functions]


def _write_corpus(root: Path, files: dict[str, str]) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


@pytest.fixture()
def index() -> GtfobinsIndex:
    return load_index(INDEX_FIXTURE)


# --------------------------------------------------------------- static guards
def test_knowledge_package_stays_inert() -> None:
    sources = {path.relative_to(REPO).as_posix(): path.read_text(encoding="utf-8")
               for path in (REPO / "tools" / "knowledge").rglob("*.py")}
    assert ENTRY_FILES <= set(sources)
    for relative_path, source in sources.items():
        for token in ("subprocess", "socket", "urllib", "os.system", "eval(",
                      "exec(", "importlib", "shell=True"):
            assert token not in source, \
                f"forbidden execution/network token {token!r} in {relative_path}"
        for pattern in (r"\bpty\b", r"\bshlex\b", r"\bhttp\b", r"\bexec\b", r"\beval\b"):
            # ``\bhttp\b`` bans the bare http token (module/usage); the https
            # reference URL used as inert data does not match the boundary.
            assert re.search(pattern, source) is None, \
                f"forbidden token pattern {pattern!r} in {relative_path}"


def test_candidate_model_has_no_recipe_or_command_field() -> None:
    assert set(GtfobinsCandidate.model_fields) == CANDIDATE_FIELDS
    for forbidden in ("command", "code", "recipe", "script", "argv", "cmd",
                      "payload", "shell"):
        assert forbidden not in GtfobinsCandidate.model_fields
    with pytest.raises(ValidationError):
        GtfobinsCandidate(binary="x", functions=["shell"], preconditions=["p"],
                          reference="https://example.test/x",
                          command="./x")  # type: ignore[call-arg]  # under-test refusal


def test_no_recipe_text_can_leak_into_candidates(index: GtfobinsIndex) -> None:
    records = [
        _record("synthetic-alpha"), _record("synthetic-beta"),
        _record("synthetic-gamma", execution_context="sudo"),
        _record("synthetic-delta", mode="4755", suid=True),
        _record("synthetic-epsilon", capabilities=("cap_setuid",),
                execution_context="capabilities"),
        _record("synthetic-zeta", execution_context="sudo"),
    ]
    emitted = 0
    for record in records:
        for candidate in match_binary(index, record):
            emitted += 1
            dumped = json.dumps(candidate.model_dump(mode="json"), sort_keys=True)
            for forbidden in FORBIDDEN_CANDIDATE_SUBSTRINGS:
                assert forbidden not in dumped, \
                    f"recipe-looking text {forbidden!r} leaked: {dumped}"
    assert emitted == len(records)


# ----------------------------------------------------------- index determinism
def test_index_build_matches_pinned_fixture_bytes(tmp_path: Path) -> None:
    built = build_index(CORPUS)
    text = built.to_json()
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == INDEX_SHA
    assert text.encode("utf-8") == INDEX_FIXTURE.read_bytes()
    assert built.corpus_sha256 == CORPUS_SHA
    rebuilt = build_index(CORPUS)
    assert rebuilt.to_json() == text
    relocated = tmp_path / "elsewhere" / "corpus"
    shutil.copytree(CORPUS, relocated)
    from_copy = build_index(relocated)
    assert from_copy.to_json() == text
    assert str(relocated) not in text          # no absolute paths in the index


def test_index_write_and_load_roundtrip(tmp_path: Path) -> None:
    built = build_index(CORPUS)
    target = tmp_path / "index.json"
    assert write_index(built, target) == INDEX_SHA
    assert index_sha256(built) == INDEX_SHA
    loaded = load_index(target)
    assert loaded.to_json() == built.to_json()
    assert loaded.model_dump() == built.model_dump()


def test_index_holds_expected_routes_and_no_recipe_data(index: GtfobinsIndex) -> None:
    alpha = index.entries["synthetic-alpha"]
    assert [f.value for f in alpha.functions] == \
        ["capabilities", "file_read", "shell", "sudo", "suid"]
    assert {k.value: [c.value for c in v] for k, v in alpha.contexts.items()} == {
        "shell": ["capabilities", "sudo", "suid", "unprivileged"],
        "file_read": ["capabilities", "sudo", "suid", "unprivileged"],
    }
    assert alpha.version_constraints == [">= 1.0"]
    assert alpha.reference == "https://gtfobins.github.io/gtfobins/synthetic-alpha/"
    beta = index.entries["synthetic-beta"]
    assert "restricted_shell" in [f.value for f in beta.functions]
    assert index.entries["synthetic-zeta"].alias == "synthetic-gamma"
    assert index.entries["synthetic-gamma"].alias is None
    dumped = index.to_json()
    for fragment in ("./synthetic", "code", "comment"):
        assert fragment not in dumped


# ------------------------------------------------------------- corpus drift
def test_corpus_drift_is_detected(index: GtfobinsIndex, tmp_path: Path) -> None:
    assert verify_corpus(index, CORPUS) is True
    tampered = tmp_path / "tampered"
    shutil.copytree(CORPUS, tampered)
    entry = tampered / "synthetic-alpha"
    entry.write_bytes(entry.read_bytes() + b"\n")
    with pytest.raises(GtfobinsCorpusDrift, match="content drifted"):
        verify_corpus(index, tampered)
    extra = tmp_path / "extra"
    shutil.copytree(CORPUS, extra)
    _write_corpus(extra, {"synthetic-omega": "---\nfunctions: {}\n...\n"})
    with pytest.raises(GtfobinsCorpusDrift, match="untracked"):
        verify_corpus(index, extra)
    missing = tmp_path / "missing"
    shutil.copytree(CORPUS, missing)
    (missing / "synthetic-zeta").unlink()
    with pytest.raises(GtfobinsCorpusDrift, match="missing"):
        verify_corpus(index, missing)
    # a hand-edited aggregate hash alone is drift too (index vs corpus hash)
    aggregate = index.model_copy(update={"corpus_sha256": "0" * 64})
    with pytest.raises(GtfobinsCorpusDrift, match="aggregate"):
        verify_corpus(aggregate, CORPUS)


# ---------------------------------------------------------------- suid route
def test_suid_route_requires_suid_binary(index: GtfobinsIndex) -> None:
    matched = match_binary(index, _record("synthetic-delta", mode="4755", suid=True))
    assert len(matched) == 1
    assert _functions(matched[0]) == ["file_read", "shell", "suid"]
    assert match_binary(index, _record("synthetic-delta")) == []
    assert match_binary(index, _record("synthetic-delta", mode="2755", sgid=True)) == []


def test_suid_forces_no_sgid_shortcut(index: GtfobinsIndex) -> None:
    # alpha declares suid routes: they stay closed without the setuid bit.
    session = match_binary(index, _record("synthetic-alpha", mode="2755", sgid=True))
    assert _functions(session[0]) == ["file_read", "shell"]


# ---------------------------------------------------------------- sudo route
def test_sudo_route_requires_sudo_context(index: GtfobinsIndex) -> None:
    matched = match_binary(index, _record("synthetic-gamma", execution_context="sudo"))
    assert _functions(matched[0]) == ["command", "library_load", "shell", "sudo"]
    assert match_binary(index, _record("synthetic-gamma")) == []
    # a setuid binary is not a sudo invocation context
    assert match_binary(index, _record("synthetic-gamma", mode="4755", suid=True)) == []


# -------------------------------------------------------- capabilities route
def test_capabilities_route_requires_relevant_capabilities(index: GtfobinsIndex) -> None:
    def epsilon(caps: tuple[str, ...]) -> list[str]:
        matched = match_binary(index, _record("synthetic-epsilon", capabilities=caps,
                                              execution_context="capabilities"))
        return _functions(matched[0]) if matched else []

    assert epsilon(("cap_setuid",)) == ["capabilities", "command", "shell"]
    assert epsilon(()) == []
    # file_read needs BOTH declared capabilities; 'command' declares no list ("any")
    assert epsilon(("cap_dac_read_search",)) == ["capabilities", "command"]
    assert epsilon(("cap_dac_read_search", "cap_dac_override")) == \
        ["capabilities", "command", "file_read"]
    assert epsilon(("cap_net_raw",)) == ["capabilities", "command"]


def test_capability_precondition_names_only_gate_passing_functions(
        index: GtfobinsIndex) -> None:
    matched = match_binary(index, _record("synthetic-alpha", capabilities=("cap_setuid",),
                                          execution_context="capabilities"))
    assert _functions(matched[0]) == ["capabilities", "file_read", "shell"]
    notes = [p for p in matched[0].preconditions if "capabilities route" in p]
    assert len(notes) == 1
    assert "shell: CAP_SETUID" in notes[0]
    assert "file_read" not in notes[0]   # matched via unprivileged, not via capabilities


# ------------------------------------------------------------ version policy
def test_version_constraint_is_surfaced_unverified(index: GtfobinsIndex) -> None:
    without_version = match_binary(index, _record("synthetic-alpha"))
    assert len(without_version) == 1
    note = " | ".join(without_version[0].preconditions)
    assert ">= 1.0" in note and "unverified" in note and "declares no version" in note
    with_version = match_binary(index, _record("synthetic-alpha", version="0.9"))
    assert len(with_version) == 1
    note = " | ".join(with_version[0].preconditions)
    assert ">= 1.0" in note and "not evaluated" in note and "0.9" in note
    # no constraint declared -> no version talk at all
    beta = match_binary(index, _record("synthetic-beta"))
    assert "version constraint" not in " | ".join(beta[0].preconditions)


# ----------------------------------------------------- candidate classification
def test_candidates_are_always_candidate_with_verification(index: GtfobinsIndex) -> None:
    for record in (
            _record("synthetic-alpha"), _record("synthetic-beta"),
            _record("synthetic-gamma", execution_context="sudo"),
            _record("synthetic-delta", mode="4755", suid=True),
            _record("synthetic-epsilon", capabilities=("cap_setuid",),
                    execution_context="capabilities")):
        for candidate in match_binary(index, record):
            assert candidate.source == "external_knowledge"
            assert candidate.technique == "gtfobins"
            assert candidate.classification == "CANDIDATE"
            assert candidate.requires_verification is True
            assert _functions(candidate) == sorted(_functions(candidate))
            assert candidate.reference.startswith("https://")
            assert candidate.preconditions


def test_no_match_yields_empty_results(index: GtfobinsIndex) -> None:
    assert match_binary(index, _record("not-in-the-corpus")) == []
    assert match_binary(index, _record("synthetic-gamma")) == []      # sudo-only
    assert match_binary(index, _record("synthetic-delta")) == []      # suid-only
    assert match_binary(index, _record("synthetic-epsilon",
                                       execution_context="capabilities")) == []


# ------------------------------------------------------------------ refusals
def test_unknown_function_name_is_refused(tmp_path: Path) -> None:
    corpus = _write_corpus(tmp_path / "corpus", {
        "broken": "---\nfunctions:\n  teleport:\n    - code: x\n      contexts:\n"
                  "        unprivileged:\n...\n"})
    with pytest.raises(GtfobinsUnknownFunction, match="teleport"):
        build_index(corpus)


@pytest.mark.parametrize("case,content,expected,match", [
    ("no-front-matter", "functions:\n  shell:\n    - contexts:\n        unprivileged:\n",
     GtfobinsCorpusError, "front matter"),
    ("bad-yaml", "---\nfunctions: [\n...\n", GtfobinsCorpusError, "YAML"),
    ("root-not-mapping", "---\n- alpha\n...\n", GtfobinsCorpusError, "mapping"),
    ("functions-missing", "---\ncomment: synthetic\n...\n",
     GtfobinsCorpusError, "functions"),
    ("functions-empty", "---\nfunctions: {}\n...\n", GtfobinsCorpusError, "functions"),
    ("function-empty-list", "---\nfunctions:\n  shell: []\n...\n",
     GtfobinsCorpusError, "examples"),
    ("example-not-mapping",
     "---\nfunctions:\n  shell:\n    - not-a-mapping\n...\n",
     GtfobinsCorpusError, "mapping"),
    ("example-without-contexts", "---\nfunctions:\n  shell:\n    - code: x\n...\n",
     GtfobinsCorpusError, "contexts"),
    ("unknown-context",
     "---\nfunctions:\n  shell:\n    - code: x\n      contexts:\n        warp:\n...\n",
     GtfobinsCorpusError, "context"),
    ("empty-capability-list",
     "---\nfunctions:\n  shell:\n    - code: x\n      contexts:\n"
     "        capabilities:\n          list: []\n...\n",
     GtfobinsCorpusError, "capability list"),
    ("bad-version-type",
     "---\nfunctions:\n  shell:\n    - code: x\n      version: true\n"
     "      contexts:\n        unprivileged:\n...\n",
     GtfobinsCorpusError, "version"),
])
def test_unparsable_entries_are_refused(tmp_path: Path, case: str, content: str,
                                        expected: type, match: str) -> None:
    corpus = _write_corpus(tmp_path / case, {"broken": content})
    with pytest.raises(expected, match=match):
        build_index(corpus)


def test_empty_and_hidden_only_corpora_are_refused(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(GtfobinsCorpusError, match="no corpus entries"):
        build_index(empty)
    hidden = tmp_path / "hidden"
    _write_corpus(hidden, {".hidden": "---\nfunctions: {}\n...\n"})
    with pytest.raises(GtfobinsCorpusError, match="no corpus entries"):
        build_index(hidden)
    with pytest.raises(GtfobinsConfigError, match="corpus directory"):
        build_index(tmp_path / "missing")


def test_duplicate_entry_names_are_refused(tmp_path: Path) -> None:
    entry = "---\nfunctions:\n  shell:\n    - code: x\n      contexts:\n" \
            "        unprivileged:\n...\n"
    corpus = _write_corpus(tmp_path / "corpus", {"a/dup": entry, "b/dup": entry})
    with pytest.raises(GtfobinsCorpusError, match="duplicate"):
        build_index(corpus)


def test_hidden_files_are_ignored(tmp_path: Path) -> None:
    corpus = _write_corpus(tmp_path / "corpus", {
        ".gitignore": "junk\n",
        ".state/notes": "junk\n",
        "visible": "---\nfunctions:\n  shell:\n    - code: x\n      contexts:\n"
                   "        unprivileged:\n...\n"})
    built = build_index(corpus)
    assert sorted(built.entries) == ["visible"]


# -------------------------------------------------------------------- aliases
def test_aliases_resolve_and_fail_closed(index: GtfobinsIndex, tmp_path: Path) -> None:
    zeta = index.entries["synthetic-zeta"]
    gamma = index.entries["synthetic-gamma"]
    assert zeta.alias == "synthetic-gamma"
    assert [f.value for f in zeta.functions] == [f.value for f in gamma.functions]
    assert zeta.reference == "https://gtfobins.github.io/gtfobins/synthetic-zeta/"
    record = _record("synthetic-zeta", execution_context="sudo")
    assert _functions(match_binary(index, record)[0]) == \
        ["command", "library_load", "shell", "sudo"]

    missing = _write_corpus(tmp_path / "missing-target",
                            {"ghost": "---\nalias: nowhere\n...\n"})
    with pytest.raises(GtfobinsCorpusError, match="not in the corpus"):
        build_index(missing)
    cycle = _write_corpus(tmp_path / "cycle", {
        "ping": "---\nalias: pong\n...\n", "pong": "---\nalias: ping\n...\n"})
    with pytest.raises(GtfobinsCorpusError, match="alias cycle"):
        build_index(cycle)
    entry = "---\nfunctions:\n  shell:\n    - code: x\n      contexts:\n" \
            "        unprivileged:\n...\n"
    extra_keys = _write_corpus(tmp_path / "extra-keys", {
        "target": entry, "ghost": "---\nalias: target\ncomment: x\n...\n"})
    with pytest.raises(GtfobinsCorpusError, match="only the 'alias' key"):
        build_index(extra_keys)


# ------------------------------------------------------------- record guards
def test_enumerated_records_are_fail_closed() -> None:
    with pytest.raises(ValidationError, match="setuid"):
        _record("x", mode="0755", suid=True)
    with pytest.raises(ValidationError, match="setuid"):
        _record("x", mode="4755", suid=False)
    with pytest.raises(ValidationError, match="setgid"):
        _record("x", mode="2755", sgid=False)
    with pytest.raises(ValidationError):
        _record("x", mode="9999")
    with pytest.raises(ValidationError):
        _record("x", execution_context="cron")
    with pytest.raises(ValidationError):
        _record("")
    with pytest.raises(ValidationError):
        EnumeratedBinary(binary_path="/x", name="x", owner="root", mode="0755",
                         suid=False, sgid=False, execution_context="session",
                         surprise=1)  # type: ignore[call-arg]  # under-test refusal


# ---------------------------------------------------------------- index guards
def test_index_documents_are_fail_closed(tmp_path: Path) -> None:
    document = json.loads(INDEX_FIXTURE.read_text(encoding="utf-8"))
    bad_schema = dict(document, schema="ps4rf.knowledge.gtfobins.index/v2")
    mutated = tmp_path / "bad-schema.json"
    mutated.write_text(json.dumps(bad_schema), encoding="utf-8")
    with pytest.raises(GtfobinsIndexError, match="schema"):
        load_index(mutated)
    with_extra = json.loads(INDEX_FIXTURE.read_text(encoding="utf-8"))
    with_extra["entries"]["synthetic-beta"]["surprise"] = 1
    mutated.write_text(json.dumps(with_extra), encoding="utf-8")
    with pytest.raises(GtfobinsIndexError):
        load_index(mutated)
    unknown = json.loads(INDEX_FIXTURE.read_text(encoding="utf-8"))
    unknown["entries"]["synthetic-beta"]["functions"].append("warp")
    mutated.write_text(json.dumps(unknown), encoding="utf-8")
    with pytest.raises(GtfobinsIndexError):
        load_index(mutated)
    mutated.write_text("{not json", encoding="utf-8")
    with pytest.raises(GtfobinsIndexError, match="JSON"):
        load_index(mutated)
    with pytest.raises(GtfobinsConfigError, match="not found"):
        load_index(tmp_path / "absent.json")


# ------------------------------------------------------------ adapter facade
def test_adapter_facade_end_to_end() -> None:
    adapter = GtfobinsAdapter(GtfobinsConfig(
        corpus_dir=str(CORPUS), index_path=str(INDEX_FIXTURE)))
    with pytest.raises(GtfobinsStateError):
        adapter.match(_record("synthetic-beta"))
    with pytest.raises(GtfobinsStateError):
        adapter.verify_corpus()
    loaded = adapter.load_index()
    assert loaded.corpus_sha256 == CORPUS_SHA
    assert adapter.verify_corpus() is True
    matched = adapter.match(_record("synthetic-beta"))
    assert _functions(matched[0]) == \
        ["download", "file_read", "file_write", "restricted_shell", "upload"]
    built = adapter.build_index()
    assert built.to_json() == loaded.to_json()
    assert adapter.current_index().to_json() == built.to_json()


def test_adapter_and_config_guards(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        GtfobinsConfig()
    only_index = GtfobinsAdapter(GtfobinsConfig(index_path=str(INDEX_FIXTURE)))
    with pytest.raises(GtfobinsConfigError, match="corpus_dir"):
        only_index.build_index()
    with pytest.raises(GtfobinsConfigError, match="index_path"):
        GtfobinsAdapter(GtfobinsConfig(corpus_dir=str(CORPUS))).load_index()
    with pytest.raises(GtfobinsConfigError, match="corpus_dir"):
        only_index.verify_corpus()
    with pytest.raises(ValidationError):
        GtfobinsConfig(corpus_dir="", index_path="")
