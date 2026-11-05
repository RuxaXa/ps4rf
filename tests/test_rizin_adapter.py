"""Rizin adapter tests against the offline command-surface mock (P3).

Everything runs offline: no rizin, no network, no execution of the analyzed
artifact. Pinned fixture hashes come from ``tests/fixtures/rizin/README.md``
(artifact and the four raw stdout captures).

Run from the repo root:

    .venv/bin/python -m pytest -q tests/test_rizin_adapter.py
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from tools.rizin.adapter import (MARKER_TEMPLATE, RizinAdapter, RizinBasicBlock,
                                 RizinCfg, RizinConfig, RizinConfigError,
                                 RizinEdge, RizinEvidenceError, RizinFunction,
                                 RizinHashMismatch, RizinNotFound, RizinRunError,
                                 RizinSchemaError, RizinTimeout, check_boundaries,
                                 normalize_cfg, normalize_xrefs, split_sections,
                                 verify_run_record)

REPO = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "rizin"
ARTIFACT = FIXTURES / "artifact.bin"

ARTIFACT_SHA = "2e2a2432c1032d47fcf55327fbc9518ff4c1f822bfad7ec9f78b8c434a1468b5"
STDOUT_ANALYZE_SHA = "26456a7fab49c18da8001b59d4c769b7c0549b236a4fbb01a84873c742a6bdae"
STDOUT_XREFS_TO_SHA = "e127b685b5861f0fdfdecca1b5101de967af32ec3c6020b56d740fb67127e9cf"
STDOUT_CFG_SHA = "5fa2edf6ff794a5a9fbdd7440082502756170b861bce3d6dcfcda115ffd690ff"
STDOUT_BB_SHA = "3fb9382571abe7cbf22e739c09304196b048df4643606e9341c8d37ff2153949"

MOCK_CMD = [sys.executable, "-m", "tools.rizin.mock.rizin_mock"]
FUNCTION_ORDER = ["sym.mock_open", "sym.mock_read", "sym.mock_write",
                  "sym.mock_close", "sym.mock_helper"]
FUNCTION_OFFSETS = ["0x401000", "0x401048", "0x4010cc", "0x40112c", "0x401158"]
FUNCTION_SIZES = [72, 132, 96, 44, 28]


@pytest.fixture()
def config(tmp_path: Path) -> RizinConfig:
    return RizinConfig(rizin_cmd=MOCK_CMD, work_dir=str(tmp_path / "rz"), timeout_s=30)


@pytest.fixture()
def adapter(config: RizinConfig) -> RizinAdapter:
    return RizinAdapter(config)


@pytest.fixture()
def mock_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "mock.log"
    monkeypatch.setenv("PS4RF_RIZIN_MOCK_LOG", str(path))
    return path


def _lines(path: Path, prefix: str) -> list[str]:
    if not path.exists():
        return []
    return [line for line in path.read_text().splitlines() if line.startswith(prefix)]


# ------------------------------------------------------------------- health/hash
def test_health_reports_rizin_version(adapter: RizinAdapter):
    health = adapter.health()
    assert health["reachable"] is True
    assert health["version"] == "0.7.4-mock"


def test_hash_artifact_matches_pinned_fixture(adapter: RizinAdapter):
    assert adapter.hash_artifact(ARTIFACT) == ARTIFACT_SHA


# ----------------------------------------------------------------------- analyze
def test_analyze_returns_pinned_functions(adapter: RizinAdapter):
    analysis = adapter.analyze(ARTIFACT)
    assert [f.name for f in analysis.functions] == FUNCTION_ORDER
    assert [f.offset for f in analysis.functions] == FUNCTION_OFFSETS
    assert [f.size for f in analysis.functions] == FUNCTION_SIZES
    assert (analysis.info.arch, analysis.info.bits, analysis.info.endian,
            analysis.info.os) == ("x86", 64, "little", "linux")
    assert analysis.run.artifact_sha256 == ARTIFACT_SHA
    assert analysis.run.rizin_version == "0.7.4-mock"
    assert analysis.run.query_kind == "analyze"
    assert analysis.run.sections == ["info", "functions"]
    assert analysis.run.functions_count == 5


def test_analyze_normalizes_int_offsets_and_drops_extra_keys(adapter: RizinAdapter):
    analysis = adapter.analyze(ARTIFACT)
    close = next(f for f in analysis.functions if f.name == "sym.mock_close")
    assert close.offset == "0x40112c"           # mock delivered an int
    keys = set(analysis.functions[0].model_dump())
    assert keys == {"name", "offset", "size", "type"}          # nbbs/cc dropped
    assert "nbbs" not in json.dumps([f.model_dump() for f in analysis.functions])


def test_analyze_stdout_is_byte_identical_to_committed_fixture(adapter: RizinAdapter,
                                                               tmp_path: Path):
    out = tmp_path / "analyze.txt"
    adapter.analyze(ARTIFACT, stdout_path=out)
    produced = out.read_bytes()
    assert hashlib.sha256(produced).hexdigest() == STDOUT_ANALYZE_SHA
    assert produced == (FIXTURES / "stdout-analyze-v1.txt").read_bytes()


def test_query_stdouts_match_committed_fixtures(adapter: RizinAdapter, tmp_path: Path):
    xrefs_out, cfg_out, bb_out = (tmp_path / "x.txt", tmp_path / "c.txt",
                                  tmp_path / "b.txt")
    adapter.xrefs("0x401158", artifact_path=ARTIFACT, stdout_path=xrefs_out)
    adapter.cfg("0x4010cc", artifact_path=ARTIFACT, stdout_path=cfg_out)
    adapter.boundaries("0x401048", artifact_path=ARTIFACT, stdout_path=bb_out)
    assert hashlib.sha256(xrefs_out.read_bytes()).hexdigest() == STDOUT_XREFS_TO_SHA
    assert hashlib.sha256(cfg_out.read_bytes()).hexdigest() == STDOUT_CFG_SHA
    assert hashlib.sha256(bb_out.read_bytes()).hexdigest() == STDOUT_BB_SHA
    assert xrefs_out.read_bytes() == \
        (FIXTURES / "stdout-xrefs-to-0x401158-v1.txt").read_bytes()
    assert cfg_out.read_bytes() == \
        (FIXTURES / "stdout-cfg-0x4010cc-v1.txt").read_bytes()
    assert bb_out.read_bytes() == \
        (FIXTURES / "stdout-bb-0x401048-v1.txt").read_bytes()


def test_run_record_verifies_and_detects_tamper(adapter: RizinAdapter):
    analysis = adapter.analyze(ARTIFACT)
    assert verify_run_record(analysis.run) is True
    stdout_path = Path(analysis.run.stdout_path)
    original = stdout_path.read_text()
    stdout_path.write_text(original + "\n")           # byte-level drift
    with pytest.raises(RizinEvidenceError):            # plain byte tamper
        verify_run_record(analysis.run)
    stdout_path.write_text(original)


def test_run_record_detects_semantic_tamper_with_rehashed_stdout(adapter: RizinAdapter):
    analysis = adapter.analyze(ARTIFACT)
    stdout_path = Path(analysis.run.stdout_path)
    sections = split_sections(stdout_path.read_text(), ("info", "functions"))
    functions = json.loads(sections["functions"])
    sections["functions"] = json.dumps(functions[:-1], sort_keys=True)   # drop one
    rebuilt = (f"{MARKER_TEMPLATE.format('info')}\n{sections['info']}\n"
               f"{MARKER_TEMPLATE.format('functions')}\n{sections['functions']}\n")
    stdout_path.write_text(rebuilt)
    rehashed = hashlib.sha256(rebuilt.encode()).hexdigest()
    record = analysis.run.model_copy(update={"stdout_sha256": rehashed})
    with pytest.raises(RizinEvidenceError) as excinfo:  # hash is fine, counts are not
        verify_run_record(record)
    assert "counts" in str(excinfo.value)


def test_two_queries_keep_distinct_evidence_files(adapter: RizinAdapter):
    first = adapter.xrefs("0x401158", artifact_path=ARTIFACT)
    second = adapter.xrefs("0x401070", direction="from", artifact_path=ARTIFACT)
    assert first.run.stdout_path != second.run.stdout_path
    assert verify_run_record(first.run) is True       # not clobbered by the second
    assert verify_run_record(second.run) is True


# ------------------------------------------------------------------ markup guards
def test_marker_contract_is_enforced():
    good = f"{MARKER_TEMPLATE.format('info')}\n{{}}\n" \
           f"{MARKER_TEMPLATE.format('functions')}\n[]\n"
    assert set(split_sections(good, ("info", "functions"))) == {"info", "functions"}
    with pytest.raises(RizinSchemaError):              # missing second marker
        split_sections(f"{MARKER_TEMPLATE.format('info')}\n{{}}\n", ("info", "functions"))
    with pytest.raises(RizinSchemaError):              # duplicate marker
        split_sections(good.replace(MARKER_TEMPLATE.format("functions"),
                                    MARKER_TEMPLATE.format("info")),
                       ("info", "functions"))
    with pytest.raises(RizinSchemaError):              # stray output before markers
        split_sections("banner\n" + good, ("info", "functions"))
    with pytest.raises(RizinSchemaError):              # empty section
        split_sections(f"{MARKER_TEMPLATE.format('info')}\n\n"
                       f"{MARKER_TEMPLATE.format('functions')}\n[]\n",
                       ("info", "functions"))


# ------------------------------------------------------------ xrefs / cfg / blocks
def test_xrefs_to_and_from(adapter: RizinAdapter):
    incoming = adapter.xrefs("0x401158", artifact_path=ARTIFACT)
    assert [(x.from_addr, x.to_addr, x.type.value) for x in incoming.xrefs] == [
        ("0x401070", "0x401158", "CALL"), ("0x4010d0", "0x401158", "CALL")]
    outgoing = adapter.xrefs("0x401070", direction="from", artifact_path=ARTIFACT)
    assert [(x.from_addr, x.to_addr) for x in outgoing.xrefs] == [("0x401070", "0x401158")]
    assert incoming.run.query_direction == "to"
    assert outgoing.run.query_direction == "from"
    assert adapter.xrefs("0x999999", artifact_path=ARTIFACT).xrefs == []
    with pytest.raises(RizinConfigError):
        adapter.xrefs("401158", artifact_path=ARTIFACT)   # missing 0x prefix
    with pytest.raises(RizinConfigError):
        adapter.xrefs("0x401158", direction="sideways", artifact_path=ARTIFACT)


def test_xref_direction_contradiction_is_refused():
    raw = [{"from": "0x401070", "to": "0x4010cc", "type": "CALL"}]
    assert len(normalize_xrefs(raw, "0x4010cc", "to")) == 1
    with pytest.raises(RizinSchemaError):             # 'to' must equal the target
        normalize_xrefs(raw, "0x401158", "to")
    with pytest.raises(RizinSchemaError):             # unknown xref type
        normalize_xrefs([{"from": "0x401070", "to": "0x401070", "type": "PONY"}],
                        "0x401070", "from")


def test_cfg_blocks_and_edges(adapter: RizinAdapter):
    result = adapter.cfg("0x4010cc", artifact_path=ARTIFACT)
    cfg = result.cfg
    assert cfg.function == "sym.mock_write"
    assert [(b.offset, b.size, b.jump, b.fail) for b in cfg.blocks] == [
        ("0x4010cc", 48, "0x4010fc", "0x401118"), ("0x4010fc", 28, None, None),
        ("0x401118", 20, None, None)]
    assert [(e.from_addr, e.to_addr, e.type.value) for e in cfg.edges] == [
        ("0x4010cc", "0x4010fc", "jump"), ("0x4010cc", "0x401118", "fail")]
    assert (result.run.blocks_count, result.run.edges_count) == (3, 2)
    assert result.run.query_kind == "cfg"


def test_cfg_consistency_is_enforced():
    blocks = [RizinBasicBlock(offset="0x4010cc", size=48, jump="0x4010fc", fail=None,
                              ninstr=7),
              RizinBasicBlock(offset="0x4010fc", size=28, ninstr=4)]
    good = RizinCfg(function="f", offset="0x4010cc", blocks=blocks,
                    edges=[RizinEdge.model_validate(
                        {"src": "0x4010cc", "dst": "0x4010fc", "type": "jump"})])
    assert len(good.edges) == 1
    with pytest.raises(ValidationError):             # jump edge contradicts block
        RizinCfg(function="f", offset="0x4010cc", blocks=blocks,
                 edges=[RizinEdge.model_validate(
                     {"src": "0x4010cc", "dst": "0x401000", "type": "jump"})])
    with pytest.raises(ValidationError):             # declared jump has no edge
        RizinCfg(function="f", offset="0x4010cc", blocks=blocks, edges=[])
    with pytest.raises(ValidationError):             # edge source is not a block
        RizinCfg(function="f", offset="0x4010cc", blocks=blocks,
                 edges=[RizinEdge.model_validate(
                     {"src": "0x401108", "dst": "0x4010fc", "type": "jump"}),
                     RizinEdge.model_validate(
                         {"src": "0x4010cc", "dst": "0x4010fc", "type": "jump"})])


def test_cfg_offset_must_match_query_target():
    raw = {"name": "f", "offset": "0x401048", "blocks": [
        {"offset": "0x401048", "size": 64, "jump": None, "fail": None, "ninstr": 1}],
        "edges": []}
    with pytest.raises(RizinSchemaError):
        normalize_cfg(raw, "0x4010cc")


def test_boundaries_pinned_and_range_checked(adapter: RizinAdapter):
    adapter.analyze(ARTIFACT)
    result = adapter.boundaries("0x401048")
    assert result.function == "sym.mock_read"
    assert [(b.offset, b.size) for b in result.blocks] == [("0x401048", 64),
                                                           ("0x401088", 68)]
    assert result.run.blocks_count == 2
    function = RizinFunction(name="f", offset="0x401048", size=32, type="sym")
    with pytest.raises(RizinSchemaError):             # block spills past the function
        check_boundaries(result.blocks, function)
    check_boundaries(result.blocks, None)             # unknown function: no range check


def test_queries_work_without_prior_analysis(adapter: RizinAdapter):
    result = adapter.boundaries("0x401048", artifact_path=ARTIFACT)
    assert result.function == "unknown"               # no analysis to resolve the name
    assert len(result.blocks) == 2


def test_not_a_function_is_refused_single_attempt(adapter: RizinAdapter, mock_log: Path):
    with pytest.raises(RizinNotFound):
        adapter.cfg("0x999999", artifact_path=ARTIFACT)
    assert len(_lines(mock_log, "not-a-function:0x999999")) == 1
    assert len(_lines(mock_log, "load:")) == 1        # exactly one attempt


# ---------------------------------------------------------------------- failures
def test_analyze_refuses_expected_artifact_hash_mismatch(adapter: RizinAdapter,
                                                         mock_log: Path):
    with pytest.raises(RizinHashMismatch):
        adapter.analyze(ARTIFACT, expected_artifact_sha256="0" * 64)
    assert _lines(mock_log, "load:") == []            # refused before any run


def test_unknown_artifact_is_refused_single_attempt(adapter: RizinAdapter,
                                                    tmp_path: Path, mock_log: Path):
    fake = tmp_path / "unknown.bin"
    fake.write_bytes(ARTIFACT.read_bytes() + b"x")
    with pytest.raises(RizinRunError) as excinfo:
        adapter.analyze(fake)
    assert excinfo.value.exit_code == 3
    assert "mock catalog" in excinfo.value.detail
    assert len(_lines(mock_log, "load:")) == 1


def test_injected_failure_single_attempt(adapter: RizinAdapter, mock_log: Path,
                                         monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PS4RF_RIZIN_MOCK_INJECT", "error")
    with pytest.raises(RizinRunError) as excinfo:
        adapter.analyze(ARTIFACT)
    assert excinfo.value.exit_code == 8
    assert len(_lines(mock_log, "load:")) == 1


def test_timeout_kills_process_without_retry(tmp_path: Path, mock_log: Path,
                                             monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PS4RF_RIZIN_MOCK_INJECT", "hang")
    adapter = RizinAdapter(RizinConfig(rizin_cmd=MOCK_CMD,
                                       work_dir=str(tmp_path / "rz"), timeout_s=2.0))
    started = time.monotonic()
    with pytest.raises(RizinTimeout):
        adapter.analyze(ARTIFACT)
    assert time.monotonic() - started < 15
    assert _lines(mock_log, "inject:hang") == ["inject:hang"]
    assert len(_lines(mock_log, "load:")) == 1


# ------------------------------------------------------------------- config guard
def test_config_requires_argv_list_not_shell_string(tmp_path: Path):
    with pytest.raises(ValidationError):
        RizinConfig(rizin_cmd="bash -c true", work_dir=str(tmp_path))  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        RizinConfig(rizin_cmd=[], work_dir=str(tmp_path))
    with pytest.raises(ValidationError):
        RizinConfig(rizin_cmd=MOCK_CMD, work_dir="")


# --------------------------------------------------------------- static guards
def test_rizin_sources_stay_shell_free_and_firmware_free():
    sources = {path: path.read_text() for path in (REPO / "tools" / "rizin").rglob("*.py")}
    blob = "\n".join(sources.values())
    assert "shell=True" not in blob
    for forbidden in ("import socket", "import http", "urllib", "kbase", "rdmsr",
                      "/payload"):
        assert forbidden not in blob, f"forbidden token in tools/rizin: {forbidden}"
    assert re.search(r"0xc0[0-9a-f]{6,}", blob) is None, "firmware-looking address literal"


def test_mock_never_executes_the_artifact():
    source = (REPO / "tools" / "rizin" / "mock" / "rizin_mock.py").read_text()
    for forbidden in ("import subprocess", "subprocess.run", "subprocess.Popen",
                      "os.system", "eval(", "exec(", "importlib"):
        assert forbidden not in source, f"mock must stay inert: {forbidden}"
