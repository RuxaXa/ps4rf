"""angr adapter tests against the offline runner mock (P3).

Everything runs offline: no angr, no network, no execution of the analyzed
artifact. Pinned fixture hashes come from ``tests/fixtures/angr/README.md``
(artifact, runner placeholder and the three mode exports).

Run from the repo root:

    .venv/bin/python -m pytest -q tests/test_angr_adapter.py
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

from tools.angr.adapter import (REQUEST_SCHEMA_ID, SCHEMA_ID, AngrAdapter,
                                AngrAnalyzeExport, AngrCfg, AngrConfig,
                                AngrConfigError, AngrConstraint,
                                AngrDataflowExport, AngrEvidenceError,
                                AngrFunction, AngrHashMismatch, AngrNotFound,
                                AngrRunError, AngrSchemaError, AngrSymbolicExport,
                                AngrTimeout, verify_run_record)

REPO = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "angr"
ARTIFACT = FIXTURES / "artifact.bin"

ARTIFACT_SHA = "efd361839429619ba5d83586dc973688fd21c9e55ae9e5b580fcc63db82238dd"
RUNNER_SHA = "edf328c2a4bf64dabf1e6261094854f6dde9a84a6c069bf540306d18a7388527"
EXPORT_ANALYZE_SHA = "6da39512295789260153018aa9915c76f9428b79804ca3fdd2fd47f9acf7c13c"
EXPORT_DATAFLOW_SHA = "a3451fbfbd1eca8a93809ba8f3ea124d44d5b63f1049e09b61b8364144fc201d"
EXPORT_SYMBOLIC_SHA = "7a2c70980c4b98881549e1161f73bb8d260db5eb3037e674f438ed951a1f0a4c"

MOCK_CMD = [sys.executable, "-m", "tools.angr.mock.angr_mock"]
FUNCTION_ORDER = ["mock_main", "mock_parse", "mock_check", "mock_tail"]
FUNCTION_SIZES = [96, 128, 84, 24]
CFG_NODES = ["0x401000", "0x401030", "0x401060", "0x4010a0", "0x4010e0",
             "0x40110c", "0x401134"]
CFG_EDGE_TYPES = ["fallthrough", "call", "fallthrough", "call", "jump", "ret"]


@pytest.fixture()
def config(tmp_path: Path) -> AngrConfig:
    return AngrConfig(runner_cmd=MOCK_CMD, work_dir=str(tmp_path / "angr"),
                      timeout_s=30)


@pytest.fixture()
def adapter(config: AngrConfig) -> AngrAdapter:
    return AngrAdapter(config)


@pytest.fixture()
def mock_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "mock.log"
    monkeypatch.setenv("PS4RF_ANGR_MOCK_LOG", str(path))
    return path


def _lines(path: Path, prefix: str) -> list[str]:
    if not path.exists():
        return []
    return [line for line in path.read_text().splitlines() if line.startswith(prefix)]


# ------------------------------------------------------------------- health/hash
def test_health_reports_runner_version(adapter: AngrAdapter):
    health = adapter.health()
    assert health["reachable"] is True
    assert health["version"] == "9.2.4-mock"


def test_hashes_match_pinned_fixtures(adapter: AngrAdapter):
    assert adapter.hash_artifact(ARTIFACT) == ARTIFACT_SHA
    assert adapter.hash_runner() == RUNNER_SHA


# ----------------------------------------------------------------------- analyze
def test_analyze_returns_pinned_functions_and_cfg(adapter: AngrAdapter):
    analysis = adapter.analyze(ARTIFACT)
    assert [f.name for f in analysis.functions] == FUNCTION_ORDER
    assert [f.size for f in analysis.functions] == FUNCTION_SIZES
    assert analysis.entry == "0x401000"
    assert (analysis.info.arch, analysis.info.bits, analysis.info.os) == (
        "AMD64", 64, "linux")
    assert [node.offset for node in analysis.cfg.nodes] == CFG_NODES
    assert [edge.type.value for edge in analysis.cfg.edges] == CFG_EDGE_TYPES
    assert (analysis.run.mode, analysis.run.target) == ("analyze", None)
    assert (analysis.run.functions_count, analysis.run.nodes_count,
            analysis.run.edges_count) == (4, 7, 6)
    assert analysis.run.runner_sha256 == RUNNER_SHA


def test_analyze_export_is_byte_identical_to_committed_fixture(adapter: AngrAdapter,
                                                               tmp_path: Path):
    out = tmp_path / "export.json"
    adapter.analyze(ARTIFACT, export_path=out)
    produced = out.read_bytes()
    assert hashlib.sha256(produced).hexdigest() == EXPORT_ANALYZE_SHA
    assert produced == (FIXTURES / "export-analyze-v1.json").read_bytes()
    assert str(REPO) not in produced.decode()          # no paths in evidence


def test_request_document_matches_contract(adapter: AngrAdapter, tmp_path: Path):
    request_out = tmp_path / "req.json"
    adapter.analyze(ARTIFACT, entry="0x401000", request_path=request_out)
    request = json.loads(request_out.read_text())
    assert request["schema"] == REQUEST_SCHEMA_ID
    assert request["mode"] == "analyze"
    assert request["entry"] == "0x401000"
    assert request["artifact_sha256"] == ARTIFACT_SHA
    assert Path(request["artifact"]).is_absolute()
    assert request["artifact"].endswith("artifact.bin")


def test_analyze_accepts_expected_entry_and_refuses_mismatch(adapter: AngrAdapter):
    analysis = adapter.analyze(ARTIFACT, entry="0x401000")
    assert analysis.entry == "0x401000"
    with pytest.raises(AngrNotFound):                  # not a function start
        adapter.analyze(ARTIFACT, entry="0x401048")
    with pytest.raises(AngrConfigError):               # malformed address
        adapter.analyze(ARTIFACT, entry="401000")


# ---------------------------------------------------------------------- dataflow
def test_dataflow_returns_pinned_edges(adapter: AngrAdapter, tmp_path: Path):
    out = tmp_path / "df.json"
    result = adapter.dataflow(ARTIFACT, "0x401060", export_path=out)
    assert result.function.name == "mock_parse"
    assert [(e.from_addr, e.to_addr, e.kind.value, e.value) for e in result.edges] == [
        ("0x401068", "0x4010b4", "reg", "rax"),
        ("0x401070", "0x4010bc", "mem", "0x404020"),
        ("0x401060", "0x4010a0", "stack", "0x8"),
        ("0x401078", "0x4010c0", "reg", "rdi")]
    assert result.run.dataflow_count == 4
    assert hashlib.sha256(out.read_bytes()).hexdigest() == EXPORT_DATAFLOW_SHA
    assert out.read_bytes() == \
        (FIXTURES / "export-dataflow-0x401060-v1.json").read_bytes()


def test_dataflow_unknown_function_is_refused_single_attempt(adapter: AngrAdapter,
                                                             mock_log: Path):
    with pytest.raises(AngrNotFound):
        adapter.dataflow(ARTIFACT, "0x999999")
    assert len(_lines(mock_log, "not-found:0x999999")) == 1
    assert len(_lines(mock_log, "load:")) == 1


# ---------------------------------------------------------------------- symbolic
def test_symbolic_returns_pinned_paths_and_constraints(adapter: AngrAdapter,
                                                       tmp_path: Path):
    out = tmp_path / "sym.json"
    result = adapter.symbolic(ARTIFACT, "0x40110c", export_path=out)
    assert [p.path_id for p in result.paths] == ["p0", "p1"]
    assert all(p.reached == "0x40110c" for p in result.paths)
    assert [(c.expr, c.satisfiable, c.solution)
            for c in result.paths[0].constraints] == [
        ("rsp != 0", True, "0x1"), ("mem[0x404020] == 0x41", True, "0x41")]
    assert result.paths[1].constraints[0].satisfiable is False
    assert result.paths[1].constraints[0].solution is None
    assert (result.run.paths_count, result.run.constraints_count) == (2, 3)
    assert hashlib.sha256(out.read_bytes()).hexdigest() == EXPORT_SYMBOLIC_SHA
    assert out.read_bytes() == \
        (FIXTURES / "export-symbolic-0x40110c-v1.json").read_bytes()


def test_symbolic_unreachable_target_is_refused(adapter: AngrAdapter, mock_log: Path):
    with pytest.raises(AngrNotFound):
        adapter.symbolic(ARTIFACT, "0x999999")
    assert len(_lines(mock_log, "not-found:0x999999")) == 1
    assert len(_lines(mock_log, "load:")) == 1


# ----------------------------------------------------------------------- evidence
def test_run_records_verify_and_detect_tamper(adapter: AngrAdapter):
    for result in (adapter.analyze(ARTIFACT), adapter.dataflow(ARTIFACT, "0x401060"),
                   adapter.symbolic(ARTIFACT, "0x40110c")):
        assert verify_run_record(result.run) is True
    analysis = adapter.analyze(ARTIFACT)
    export_path = Path(analysis.run.export_path)
    original = export_path.read_text()
    export_path.write_text(original + "\n")
    with pytest.raises(AngrEvidenceError):
        verify_run_record(analysis.run)
    export_path.write_text(original)


def test_verify_detects_count_and_request_drift(adapter: AngrAdapter):
    analysis = adapter.analyze(ARTIFACT)
    drifted = analysis.run.model_copy(update={"nodes_count": 5})
    with pytest.raises(AngrEvidenceError) as excinfo:
        verify_run_record(drifted)
    assert "counts" in str(excinfo.value)
    request_path = Path(analysis.run.request_path)
    original = request_path.read_text()
    request_path.write_text(original.replace(ARTIFACT_SHA, "0" * 64))
    with pytest.raises(AngrEvidenceError):
        verify_run_record(analysis.run)
    request_path.write_text(original)


def test_runs_keep_distinct_evidence_files(adapter: AngrAdapter):
    first = adapter.dataflow(ARTIFACT, "0x401060")
    second = adapter.symbolic(ARTIFACT, "0x40110c")
    assert first.run.export_path != second.run.export_path
    assert verify_run_record(first.run) and verify_run_record(second.run)


# ---------------------------------------------------------------------- failures
def test_analyze_refuses_expected_artifact_hash_mismatch(adapter: AngrAdapter,
                                                         mock_log: Path):
    with pytest.raises(AngrHashMismatch):
        adapter.analyze(ARTIFACT, expected_artifact_sha256="0" * 64)
    assert _lines(mock_log, "load:") == []


def test_analyze_refuses_runner_hash_drift(adapter: AngrAdapter, mock_log: Path):
    with pytest.raises(AngrHashMismatch):
        adapter.analyze(ARTIFACT, expected_runner_sha256="0" * 64)
    assert _lines(mock_log, "load:") == []


def test_unknown_artifact_is_refused_single_attempt(adapter: AngrAdapter,
                                                    tmp_path: Path, mock_log: Path):
    fake = tmp_path / "unknown.bin"
    fake.write_bytes(ARTIFACT.read_bytes() + b"x")
    with pytest.raises(AngrRunError) as excinfo:
        adapter.analyze(fake)
    assert excinfo.value.exit_code == 3
    assert "mock catalog" in excinfo.value.detail
    assert len(_lines(mock_log, "load:")) == 1


def test_injected_failure_single_attempt(adapter: AngrAdapter, mock_log: Path,
                                         monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PS4RF_ANGR_MOCK_INJECT", "error")
    with pytest.raises(AngrRunError) as excinfo:
        adapter.analyze(ARTIFACT)
    assert excinfo.value.exit_code == 8
    assert len(_lines(mock_log, "load:")) == 1


def test_timeout_kills_process_without_retry(tmp_path: Path, mock_log: Path,
                                             monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PS4RF_ANGR_MOCK_INJECT", "hang")
    adapter = AngrAdapter(AngrConfig(runner_cmd=MOCK_CMD,
                                     work_dir=str(tmp_path / "angr"), timeout_s=2.0))
    started = time.monotonic()
    with pytest.raises(AngrTimeout):
        adapter.analyze(ARTIFACT)
    assert time.monotonic() - started < 15
    assert _lines(mock_log, "inject:hang") == ["inject:hang"]
    assert len(_lines(mock_log, "load:")) == 1


# ------------------------------------------------------------------ model guards
def test_constraint_requires_consistent_satisfiability():
    assert AngrConstraint(expr="rax == 0", satisfiable=True, solution="0x0").solution
    with pytest.raises(ValidationError):               # satisfiable without solution
        AngrConstraint(expr="rax == 0", satisfiable=True, solution=None)
    with pytest.raises(ValidationError):               # unsatisfiable with solution
        AngrConstraint(expr="rax != rax", satisfiable=False, solution="0x0")


def test_cfg_edges_must_reference_nodes():
    document = json.loads((FIXTURES / "export-analyze-v1.json").read_text())
    broken = json.loads(json.dumps(document))
    broken["cfg"]["edges"][0]["dst"] = "0x401999"
    with pytest.raises(ValidationError):
        AngrAnalyzeExport.model_validate(broken)
    extra = {**document, "surprise": 1}
    with pytest.raises(ValidationError):               # strict: no extra keys
        AngrAnalyzeExport.model_validate(extra)
    wrong_schema = {**document, "schema": "ps4rf.angr.export/v2"}
    with pytest.raises(ValidationError):
        AngrAnalyzeExport.model_validate(wrong_schema)


def test_analyze_export_rejects_inconsistent_functions_and_nodes():
    document = json.loads((FIXTURES / "export-analyze-v1.json").read_text())
    not_a_function = json.loads(json.dumps(document))
    not_a_function["entry"] = "0x401048"
    with pytest.raises(ValidationError):               # entry not a function start
        AngrAnalyzeExport.model_validate(not_a_function)
    missing_node = json.loads(json.dumps(document))
    missing_node["cfg"]["nodes"] = missing_node["cfg"]["nodes"][:-1]
    with pytest.raises(ValidationError):               # nodes != union of blocks
        AngrAnalyzeExport.model_validate(missing_node)
    with pytest.raises(ValidationError):               # block outside its function
        AngrFunction(name="f", offset="0x401000", size=16, blocks=["0x401020"])


def test_dataflow_and_symbolic_exports_enforce_range_and_target():
    dataflow = json.loads((FIXTURES / "export-dataflow-0x401060-v1.json").read_text())
    outside = json.loads(json.dumps(dataflow))
    outside["edges"][0]["from"] = "0x401999"
    with pytest.raises(ValidationError):
        AngrDataflowExport.model_validate(outside)
    symbolic = json.loads((FIXTURES / "export-symbolic-0x40110c-v1.json").read_text())
    wrong_target = json.loads(json.dumps(symbolic))
    wrong_target["paths"][0]["reached"] = "0x401134"
    with pytest.raises(ValidationError):
        AngrSymbolicExport.model_validate(wrong_target)


# ------------------------------------------------------------------- config guard
def test_config_requires_argv_list_not_shell_string(tmp_path: Path):
    with pytest.raises(ValidationError):
        AngrConfig(runner_cmd="bash -c true", work_dir=str(tmp_path))  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        AngrConfig(runner_cmd=[], work_dir=str(tmp_path))
    with pytest.raises(ValidationError):
        AngrConfig(runner_cmd=MOCK_CMD, work_dir="")
    with pytest.raises(ValidationError):
        AngrConfig(runner_cmd=MOCK_CMD, work_dir=str(tmp_path), runner_path="")


# --------------------------------------------------------------- static guards
def test_angr_sources_stay_shell_free_and_firmware_free():
    sources = {path: path.read_text() for path in (REPO / "tools" / "angr").rglob("*.py")}
    blob = "\n".join(sources.values())
    assert "shell=True" not in blob
    for forbidden in ("import socket", "import http", "urllib", "kbase", "rdmsr",
                      "/payload"):
        assert forbidden not in blob, f"forbidden token in tools/angr: {forbidden}"
    assert re.search(r"0xc0[0-9a-f]{6,}", blob) is None, "firmware-looking address literal"
    assert SCHEMA_ID in blob


def test_mock_never_executes_the_artifact():
    source = (REPO / "tools" / "angr" / "mock" / "angr_mock.py").read_text()
    for forbidden in ("import subprocess", "subprocess.run", "subprocess.Popen",
                      "os.system", "eval(", "exec(", "importlib"):
        assert forbidden not in source, f"mock must stay inert: {forbidden}"
