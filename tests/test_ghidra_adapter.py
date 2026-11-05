"""Ghidra adapter tests against the offline headless mock (P3).

Everything runs offline: no Ghidra, no Java, no network, no execution of the
analyzed artifact. Pinned fixture hashes come from
``tests/fixtures/ghidra/README.md`` (artifact, export and postscript are pinned
separately so drift between mock, script and fixtures is detected).

Run from the repo root:

    .venv/bin/python -m pytest -q tests/test_ghidra_adapter.py
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from tools.ghidra.adapter import (EXPORT_SCRIPT, SCHEMA_ID, GhidraAdapter,
                                  GhidraConfig, GhidraConfigError, GhidraDecompilation,
                                  GhidraEvidenceError, GhidraExport, GhidraHashMismatch,
                                  GhidraNotFound, GhidraRunError, GhidraSchemaError,
                                  GhidraStateError, GhidraTimeout, verify_run_record)

REPO = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "ghidra"
ARTIFACT = FIXTURES / "artifact.bin"
EXPORT_FIXTURE = FIXTURES / "export-v1.json"

ARTIFACT_SHA = "bb249eaf3b7666d21e9149147d4c7a1ef04c4695cd5b539e251094d3795e7c95"
EXPORT_SHA = "82d5e0b82931e98ccfbabde8c9ac3f9fac56683154307da31644cf86321c35b7"
SCRIPT_SHA = "a10264395399644b03b2981de1e18b4da4113f1ac1d5b2a252be23ea0fa9a9f0"

MOCK_CMD = [sys.executable, "-m", "tools.ghidra.mock.headless_mock"]
SCRIPT_DIR = REPO / "tools" / "ghidra" / "scripts"
FUNCTION_ORDER = ["mock_init", "mock_parse_header", "mock_dispatch", "mock_free",
                  "mock_helper"]
FUNCTION_SIZES = [64, 120, 288, 48, 36]


@pytest.fixture()
def config(tmp_path: Path) -> GhidraConfig:
    return GhidraConfig(headless_cmd=MOCK_CMD, project_dir=str(tmp_path / "proj"),
                        script_dir=str(SCRIPT_DIR), timeout_s=30)


@pytest.fixture()
def adapter(config: GhidraConfig) -> GhidraAdapter:
    return GhidraAdapter(config)


@pytest.fixture()
def mock_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "mock.log"
    monkeypatch.setenv("PS4RF_GHIDRA_MOCK_LOG", str(path))
    return path


def _lines(path: Path, prefix: str) -> list[str]:
    if not path.exists():
        return []
    return [line for line in path.read_text().splitlines() if line.startswith(prefix)]


# ------------------------------------------------------------------- health/hash
def test_health_reports_headless_version(adapter: GhidraAdapter):
    health = adapter.health()
    assert health["reachable"] is True
    assert health["version"] == "11.0-mock"


def test_hash_artifact_matches_pinned_fixture(adapter: GhidraAdapter):
    assert adapter.hash_artifact(ARTIFACT) == ARTIFACT_SHA


# ----------------------------------------------------------------------- analyze
def test_analyze_returns_pinned_functions(adapter: GhidraAdapter):
    analysis = adapter.analyze(ARTIFACT)
    assert [f.name for f in analysis.export.functions] == FUNCTION_ORDER
    assert [f.size for f in analysis.export.functions] == FUNCTION_SIZES
    assert all(f.entry.startswith("0x40") for f in analysis.export.functions)
    assert analysis.run.artifact_sha256 == ARTIFACT_SHA
    assert analysis.run.script_name == EXPORT_SCRIPT
    assert analysis.run.script_sha256 == SCRIPT_SHA
    assert analysis.run.headless_version == "11.0-mock"
    assert (analysis.run.functions_count, analysis.run.xrefs_count,
            analysis.run.decompilations_count) == (5, 4, 2)


def test_export_is_byte_identical_to_committed_fixture(adapter: GhidraAdapter,
                                                       tmp_path: Path):
    out = tmp_path / "export.json"
    adapter.analyze(ARTIFACT, output_path=out)
    produced = out.read_bytes()
    assert hashlib.sha256(produced).hexdigest() == EXPORT_SHA
    assert produced == EXPORT_FIXTURE.read_bytes()


def test_run_record_verifies_and_detects_tamper(adapter: GhidraAdapter):
    analysis = adapter.analyze(ARTIFACT)
    assert verify_run_record(analysis.run) is True
    export_path = Path(analysis.run.export_path)
    tampered = json.loads(export_path.read_text())
    tampered["functions"][0]["size"] += 1
    export_path.write_text(json.dumps(tampered, indent=2, sort_keys=True) + "\n")
    with pytest.raises(GhidraEvidenceError):
        verify_run_record(analysis.run)


def test_analyze_refuses_expected_artifact_hash_mismatch(adapter: GhidraAdapter,
                                                         mock_log: Path):
    with pytest.raises(GhidraHashMismatch):
        adapter.analyze(ARTIFACT, expected_artifact_sha256="0" * 64)
    assert _lines(mock_log, "import:") == []      # refused before any run


def test_analyze_refuses_script_hash_drift(adapter: GhidraAdapter, mock_log: Path):
    with pytest.raises(GhidraHashMismatch):
        adapter.analyze(ARTIFACT, expected_script_sha256="0" * 64)
    assert _lines(mock_log, "import:") == []


def test_unknown_artifact_is_refused_single_attempt(adapter: GhidraAdapter,
                                                    tmp_path: Path, mock_log: Path):
    fake = tmp_path / "unknown.bin"
    fake.write_bytes(ARTIFACT.read_bytes() + b"x")
    with pytest.raises(GhidraRunError) as excinfo:
        adapter.analyze(fake)
    assert excinfo.value.exit_code == 3
    assert "mock catalog" in excinfo.value.detail
    assert len(_lines(mock_log, "import:")) == 1  # exactly one attempt


# ---------------------------------------------------------------------- failures
def test_injected_failure_single_attempt(adapter: GhidraAdapter, mock_log: Path,
                                         monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PS4RF_GHIDRA_MOCK_INJECT", "error")
    with pytest.raises(GhidraRunError) as excinfo:
        adapter.analyze(ARTIFACT)
    assert excinfo.value.exit_code == 5
    assert len(_lines(mock_log, "import:")) == 1


def test_timeout_kills_process_without_retry(tmp_path: Path, mock_log: Path,
                                             monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PS4RF_GHIDRA_MOCK_INJECT", "hang")
    cfg = GhidraConfig(headless_cmd=MOCK_CMD, project_dir=str(tmp_path / "proj"),
                       script_dir=str(SCRIPT_DIR), timeout_s=2.0)
    adapter = GhidraAdapter(cfg)
    started = time.monotonic()
    with pytest.raises(GhidraTimeout):
        adapter.analyze(ARTIFACT)
    assert time.monotonic() - started < 15
    assert len(_lines(mock_log, "import:")) == 1
    assert _lines(mock_log, "inject:hang") == ["inject:hang"]


# ------------------------------------------------------------ decompile / xrefs
def test_decompile_by_name_and_entry(adapter: GhidraAdapter):
    adapter.analyze(ARTIFACT)
    by_name = adapter.decompile("mock_init")
    by_entry = adapter.decompile("0x401000")
    assert "mock_table" in by_name.text
    assert by_name == by_entry
    with pytest.raises(GhidraNotFound):
        adapter.decompile("does_not_exist")
    with pytest.raises(GhidraNotFound):
        adapter.decompile("mock_free")               # no decompilation in export


def test_xrefs_directions(adapter: GhidraAdapter):
    adapter.analyze(ARTIFACT)
    incoming_helper = adapter.xrefs("0x401208")
    assert len(incoming_helper) == 2
    assert {x.from_addr for x in incoming_helper} == {"0x4010e0", "0x401060"}
    outgoing_callsite = adapter.xrefs("0x4010c4", direction="from")
    assert [x.to_addr for x in outgoing_callsite] == ["0x401000"]
    assert outgoing_callsite[0].type.value == "CALL"
    data_ref = adapter.xrefs("0x404020")
    assert len(data_ref) == 1 and data_ref[0].type.value == "DATA"
    assert adapter.xrefs("0x4010b8") == []          # entries carry no incoming xrefs
    with pytest.raises(GhidraConfigError):
        adapter.xrefs("401208")                     # missing 0x prefix
    with pytest.raises(GhidraConfigError):
        adapter.xrefs("0x401208", direction="sideways")


def test_result_accessors_require_analysis(adapter: GhidraAdapter):
    for call in (adapter.list_functions, lambda: adapter.decompile("mock_init"),
                 lambda: adapter.xrefs("0x401000")):
        with pytest.raises(GhidraStateError):
            call()


# ------------------------------------------------------------------ schema guards
def test_export_schema_rejects_unknown_fields_and_bad_addresses():
    document = json.loads(EXPORT_FIXTURE.read_text())
    with_extra = {**document, "surprise": 1}
    with pytest.raises(ValidationError):
        GhidraExport.model_validate(with_extra)
    bad_address = json.loads(EXPORT_FIXTURE.read_text())
    bad_address["functions"][0]["entry"] = "0xZZZZ"
    with pytest.raises(ValidationError):
        GhidraExport.model_validate(bad_address)


def test_decompilation_text_binding_is_enforced():
    with pytest.raises(ValidationError):
        GhidraDecompilation(function="x", entry="0x401000", text="int x(void){}",
                            text_sha256="0" * 64)


def test_schema_id_is_checked(tmp_path: Path, adapter: GhidraAdapter):
    analysis = adapter.analyze(ARTIFACT)
    assert analysis.export.schema_id == SCHEMA_ID
    document = json.loads(Path(analysis.run.export_path).read_text())
    document["schema"] = "ps4rf.ghidra.export/v2"
    with pytest.raises(ValidationError):
        GhidraExport.model_validate(document)


# ------------------------------------------------------------------- config guard
def test_config_requires_argv_list_not_shell_string(tmp_path: Path):
    with pytest.raises(ValidationError):
        GhidraConfig(headless_cmd="bash -c true", project_dir=str(tmp_path))  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        GhidraConfig(headless_cmd=[], project_dir=str(tmp_path))


# --------------------------------------------------------------- static guards
def test_ghidra_sources_stay_shell_free_and_firmware_free():
    sources = {path: path.read_text() for path in (REPO / "tools" / "ghidra").rglob("*.py")}
    blob = "\n".join(sources.values())
    assert "shell=True" not in blob
    for forbidden in ("import socket", "import http", "urllib", "kbase", "rdmsr",
                      "/payload"):
        assert forbidden not in blob, f"forbidden token in tools/ghidra: {forbidden}"
    import re
    assert re.search(r"0xc0[0-9a-f]{6,}", blob) is None, "firmware-looking address literal"


def test_mock_never_executes_the_artifact():
    source = (REPO / "tools" / "ghidra" / "mock" / "headless_mock.py").read_text()
    for forbidden in ("import subprocess", "subprocess.run", "subprocess.Popen",
                      "os.system", "eval(", "exec(", "importlib"):
        assert forbidden not in source, f"mock must stay inert: {forbidden}"
