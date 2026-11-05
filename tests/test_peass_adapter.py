"""PEASS/linPEAS adapter tests against the offline scan mock (P4 recon).

Everything runs offline: no target is contacted, no PEASS-ng installation is
required -- the scanner driven by the tests is the synthetic mock
(``tools/recon/peass/mock/linpeas_mock.py``). Pinned fixture hashes come from
``tests/fixtures/peass/README.md`` (scan outputs, canonical analysis documents
and the mock module itself are pinned separately so drift is detected).

Run from the repo root:

    .venv/bin/python -m pytest -q tests/test_peass_adapter.py
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from tools.recon.peass import adapter as peass_adapter
from tools.recon.peass.adapter import PeassAdapter, verify_run_record
from tools.recon.peass.models import (LINUX_REASON, MOCK_MODULE, OBSERVATION,
                                      SCANNER_CMD_NOT_RECORDED, UNKNOWN_REASON,
                                      UNSUPPORTED_REASON, FindingCategory,
                                      PeassConfig, PeassConfigError, PeassEvidenceError,
                                      PeassFinding, PeassHashMismatch, PeassReport,
                                      PeassRunError, PeassScanTarget, PeassSchemaError,
                                      PeassTargetOS, PeassTimeout)
from tools.recon.peass.parser import detect_target_os

REPO = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "peass"
SCAN_LINUX = FIXTURES / "scan-linux.txt"
SCAN_ORBISOS = FIXTURES / "scan-orbisos.txt"
ANALYSIS_LINUX = FIXTURES / "analysis-linux.json"
ANALYSIS_ORBISOS = FIXTURES / "analysis-orbisos.json"

SCAN_LINUX_SHA = "5ecef87f3bc15e937d862d29a639a38fcbf6cf98fd31e93139525a57d987c61d"
SCAN_ORBISOS_SHA = "b9ded18bdc3757718a0b71f0cbe038cdb071dc52c57734dcc9a2f8737d4d84d5"
ANALYSIS_LINUX_SHA = "c9cb57ad9a584709e00c1cc52693a1ff33576e15aa156e726d79e9bea792442e"
ANALYSIS_ORBISOS_SHA = "cd8c19e88e86aeff2f35fc9d2a369ef9d3d005d8f795db910e34bab2271c6922"
MOCK_SHA = "dfa6fa833e83c066f3154a1ad865fc05f083257fd2e8a85fb814198b5695628e"

MOCK_CMD = [sys.executable, "-m", MOCK_MODULE]
MOCK_PATH = REPO / "tools" / "recon" / "peass" / "mock" / "linpeas_mock.py"

REQUIRED_CATEGORIES = {
    FindingCategory.FILESYSTEM, FindingCategory.PERMISSIONS,
    FindingCategory.SUID_SGID, FindingCategory.CAPABILITIES,
    FindingCategory.SERVICES, FindingCategory.CRON, FindingCategory.SOCKETS,
    FindingCategory.CREDENTIALS, FindingCategory.MOUNTS, FindingCategory.KERNEL_OS,
    FindingCategory.INTERESTING_BINARIES,
}


@pytest.fixture()
def config(tmp_path: Path) -> PeassConfig:
    return PeassConfig(scanner_cmd=MOCK_CMD, work_dir=str(tmp_path / "work"),
                       timeout_s=30)


@pytest.fixture()
def adapter(config: PeassConfig) -> PeassAdapter:
    return PeassAdapter(config)


@pytest.fixture()
def mock_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "mock.log"
    monkeypatch.setenv("PS4RF_PEASS_MOCK_LOG", str(path))
    return path


def _lines(path: Path, prefix: str) -> list[str]:
    if not path.exists():
        return []
    return [line for line in path.read_text().splitlines() if line.startswith(prefix)]


def assert_observations_only(node: object) -> int:
    """Walk a whole output object tree; fail on any non-OBSERVATION finding node.

    Returns the number of finding-shaped nodes checked, so callers can prove
    the walk actually visited the findings.
    """
    checked = 0
    if isinstance(node, dict):
        if "classification" in node or "requires_verification" in node:
            assert node.get("classification") == OBSERVATION, node
            assert node.get("requires_verification") is True, node
            checked += 1
        for value in node.values():
            checked += assert_observations_only(value)
    elif isinstance(node, list):
        for value in node:
            checked += assert_observations_only(value)
    return checked


# ------------------------------------------------------------------- health/hash
def test_health_reports_mock_version(adapter: PeassAdapter, mock_log: Path):
    health = adapter.health()
    assert health["reachable"] is True
    assert health["version"] == "20231115-mock"
    assert _lines(mock_log, "version") == ["version"]


def test_hash_file_matches_pinned_fixtures(adapter: PeassAdapter):
    assert adapter.hash_file(SCAN_LINUX) == SCAN_LINUX_SHA
    assert adapter.hash_file(SCAN_ORBISOS) == SCAN_ORBISOS_SHA
    assert adapter.hash_file(MOCK_PATH) == MOCK_SHA


# ----------------------------------------------------------------------- scanning
def test_scan_is_deterministic_and_matches_pinned_fixture(adapter: PeassAdapter,
                                                          tmp_path: Path):
    first = adapter.scan("linux", scan_path=tmp_path / "a.txt",
                         analysis_path=tmp_path / "a.json")
    second = adapter.scan(PeassScanTarget.LINUX, scan_path=tmp_path / "b.txt",
                          analysis_path=tmp_path / "b.json")
    assert (tmp_path / "a.txt").read_bytes() == SCAN_LINUX.read_bytes()
    assert (tmp_path / "b.txt").read_bytes() == SCAN_LINUX.read_bytes()
    assert first.run.scan_sha256 == second.run.scan_sha256 == SCAN_LINUX_SHA
    assert (tmp_path / "a.json").read_bytes() == ANALYSIS_LINUX.read_bytes()
    assert first.run.report_sha256 == ANALYSIS_LINUX_SHA
    assert first.run.mode == "scan"
    assert first.run.scanner_version == "20231115-mock"


def test_scan_accepts_pinned_scanner_hash(adapter: PeassAdapter):
    analysis = adapter.scan("linux", expected_scanner_sha256=MOCK_SHA)
    assert analysis.run.scan_sha256 == SCAN_LINUX_SHA


def test_ingest_writes_byte_identical_canonical_documents(adapter: PeassAdapter,
                                                          tmp_path: Path):
    linux = adapter.ingest(SCAN_LINUX, analysis_path=tmp_path / "l.json")
    orbis = adapter.ingest(SCAN_ORBISOS, analysis_path=tmp_path / "o.json")
    assert (tmp_path / "l.json").read_bytes() == ANALYSIS_LINUX.read_bytes()
    assert (tmp_path / "o.json").read_bytes() == ANALYSIS_ORBISOS.read_bytes()
    assert hashlib.sha256((tmp_path / "l.json").read_bytes()).hexdigest() == ANALYSIS_LINUX_SHA
    assert hashlib.sha256((tmp_path / "o.json").read_bytes()).hexdigest() == ANALYSIS_ORBISOS_SHA
    assert linux.run.mode == "ingest" and orbis.run.mode == "ingest"
    assert linux.run.scan_sha256 == SCAN_LINUX_SHA
    assert orbis.run.scan_sha256 == SCAN_ORBISOS_SHA


# ------------------------------------------------------------------- parsed target
def test_linux_analysis_covers_all_required_categories(adapter: PeassAdapter):
    report = adapter.ingest(SCAN_LINUX).report
    categories = {finding.category for finding in report.findings}
    assert REQUIRED_CATEGORIES <= categories
    assert report.target.hostname == "ac-lab-host"
    assert "6.8.0" in (report.target.kernel or "")
    assert report.scanner.synthetic is True


def test_linux_target_is_compatible_with_canonical_reason(adapter: PeassAdapter):
    report = adapter.ingest(SCAN_LINUX).report
    assert report.target.os is PeassTargetOS.LINUX
    assert report.compatibility.compatible is True
    assert report.compatibility.reason == LINUX_REASON


def test_orbisos_target_is_not_compatible_with_native_ps4_reason(adapter: PeassAdapter):
    report = adapter.ingest(SCAN_ORBISOS).report
    assert report.target.os is PeassTargetOS.FREEBSD_ORBISOS
    assert report.compatibility.compatible is False
    reason = report.compatibility.reason
    assert "linPEAS assumptions do not apply" in reason
    assert "PS4/OrbisOS" in reason
    assert "PS4RF surface/experiment modules" in reason
    assert len(report.findings) >= 1     # best-effort observations, still not claims


def test_unknown_target_fails_closed(tmp_path: Path, adapter: PeassAdapter):
    scan = tmp_path / "unknown.txt"
    scan.write_text(
        "# synthetic fixture with no identifiable OS markers\n"
        "╔══════════╣ Filesystem ╚ offline fixture ╝\n"
        "╚ /srv (fixture entry)\n", encoding="utf-8")
    report = adapter.ingest(scan).report
    assert report.target.os is PeassTargetOS.UNKNOWN
    assert report.compatibility.compatible is False
    assert report.compatibility.reason == UNKNOWN_REASON


def test_mixed_os_markers_fail_closed_to_unknown():
    text = ("# synthetic mixed-marker fixture\n"
            "╔══════════╣ System Information ╚ offline fixture ╝\n"
            "╚ uname -a: Linux host claiming FreeBSD heritage\n")
    assert detect_target_os(text) is PeassTargetOS.UNKNOWN


def test_compatibility_verdict_cannot_be_hand_rolled():
    linux_doc = json.loads(ANALYSIS_LINUX.read_text())
    linux_doc["compatibility"] = {"compatible": True, "reason": UNKNOWN_REASON}
    with pytest.raises(ValidationError):
        PeassReport.model_validate(linux_doc)
    orbisos_doc = json.loads(ANALYSIS_ORBISOS.read_text())
    orbisos_doc["compatibility"] = {"compatible": True, "reason": LINUX_REASON}
    with pytest.raises(ValidationError):
        PeassReport.model_validate(orbisos_doc)
    unsupported_but_linux_reason = json.loads(ANALYSIS_ORBISOS.read_text())
    unsupported_but_linux_reason["compatibility"] = {
        "compatible": False, "reason": LINUX_REASON}
    with pytest.raises(ValidationError):
        PeassReport.model_validate(unsupported_but_linux_reason)


# ------------------------------------------------------------- observation policy
def test_whole_output_tree_is_observation_only(adapter: PeassAdapter):
    analysis = adapter.ingest(SCAN_LINUX)
    dump = analysis.model_dump(mode="json")
    checked = assert_observations_only(dump)
    assert checked == len(analysis.report.findings) > 0
    blob = json.dumps(dump).upper()
    assert "VULNERAB" not in blob
    assert OBSERVATION in blob
    # the canonical document on disk obeys the same rule
    document = json.loads(Path(analysis.run.report_path).read_text())
    assert assert_observations_only(document) == len(analysis.report.findings)


def test_observation_walker_detects_a_violation(adapter: PeassAdapter):
    dump = adapter.ingest(SCAN_LINUX).model_dump(mode="json")
    tampered = copy.deepcopy(dump)
    tampered["report"]["findings"][0]["classification"] = "VULNERABILITY"
    with pytest.raises(AssertionError):
        assert_observations_only(tampered)
    tampered = copy.deepcopy(dump)
    tampered["report"]["findings"][0]["requires_verification"] = False
    with pytest.raises(AssertionError):
        assert_observations_only(tampered)


def test_finding_model_rejects_any_other_classification():
    with pytest.raises(ValidationError):
        PeassFinding(category=FindingCategory.SOCKETS, line=1, text="x",
                     classification="VULNERABILITY")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        PeassFinding(category=FindingCategory.SOCKETS, line=1, text="x",
                     requires_verification=False)  # type: ignore[arg-type]


# --------------------------------------------------------------------- credentials
def test_credentials_are_reported_without_copying_values(tmp_path: Path,
                                                         adapter: PeassAdapter):
    placeholder = "PLACEHOLDER-VALUE-" + "9" * 12
    scan = tmp_path / "with-marker.txt"
    scan.write_text(
        "# synthetic fixture for credential handling\n"
        "╔══════════╣ Credentials Search ╚ offline fixture ╝\n"
        f"╚ /srv/app/.pgpass: password: {placeholder}\n"
        "╚ /srv/app/.netrc: credential-like directives observed (values never copied)\n",
        encoding="utf-8")
    analysis = adapter.ingest(scan, analysis_path=tmp_path / "doc.json")
    blob = json.dumps(analysis.model_dump(mode="json"))
    assert placeholder not in blob
    assert "[value withheld]" in blob
    assert placeholder not in (tmp_path / "doc.json").read_text(encoding="utf-8")
    credentials = [finding for finding in analysis.report.findings
                   if finding.category is FindingCategory.CREDENTIALS]
    assert len(credentials) == 2
    assert "password: [value withheld]" in credentials[0].text
    assert "values never copied" in credentials[1].text


# -------------------------------------------------------------------- run records
def test_run_record_carries_cmd_hash_counts_and_timestamps(adapter: PeassAdapter,
                                                           tmp_path: Path):
    analysis = adapter.scan("linux", scan_path=tmp_path / "s.txt",
                            analysis_path=tmp_path / "a.json")
    run = analysis.run
    assert run.mode == "scan"
    assert run.scanner_cmd[:len(MOCK_CMD)] == MOCK_CMD
    assert run.scanner_cmd[-4:] == ["--target", "linux", "--output",
                                    str(tmp_path / "s.txt")]
    assert run.scanner_tool == "linPEAS"
    assert run.scanner_version == "20231115-mock"
    assert run.scan_sha256 == SCAN_LINUX_SHA
    assert run.findings_count == len(analysis.report.findings)
    assert run.categories_count == len(run.category_counts)
    assert sum(run.category_counts.values()) == run.findings_count
    assert run.started_at <= run.ended_at
    ingested = adapter.ingest(SCAN_LINUX, analysis_path=tmp_path / "i.json")
    assert ingested.run.mode == "ingest"
    assert ingested.run.scanner_cmd == [SCANNER_CMD_NOT_RECORDED]
    provided = adapter.ingest(SCAN_LINUX, analysis_path=tmp_path / "p.json",
                              scanner_cmd=["linpeas.sh", "-a"])
    assert provided.run.scanner_cmd == ["linpeas.sh", "-a"]


def test_verify_run_record_and_detects_document_tamper(adapter: PeassAdapter,
                                                       tmp_path: Path):
    scan_copy = tmp_path / "scan.txt"
    scan_copy.write_bytes(SCAN_LINUX.read_bytes())
    analysis = adapter.ingest(scan_copy, analysis_path=tmp_path / "doc.json")
    assert verify_run_record(analysis.run) is True
    document = Path(analysis.run.report_path)
    payload = json.loads(document.read_text())
    payload["findings"][0]["text"] = "tampered text"
    document.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    with pytest.raises(PeassEvidenceError):
        verify_run_record(analysis.run)


def test_verify_run_record_detects_scan_tamper(adapter: PeassAdapter, tmp_path: Path):
    scan_copy = tmp_path / "scan.txt"
    scan_copy.write_bytes(SCAN_LINUX.read_bytes())
    analysis = adapter.ingest(scan_copy, analysis_path=tmp_path / "doc.json")
    scan_copy.write_bytes(scan_copy.read_bytes() + b"extra\n")
    with pytest.raises(PeassEvidenceError):
        verify_run_record(analysis.run)
    scan_copy.unlink()
    with pytest.raises(PeassEvidenceError):
        verify_run_record(analysis.run)


# ---------------------------------------------------------------------- refusals
def test_ingest_refuses_expected_hash_mismatch_before_any_parse(
        adapter: PeassAdapter, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    called: list[str] = []
    monkeypatch.setattr(peass_adapter, "parse_scan", lambda *a, **k: called.append("parse"))
    target_doc = tmp_path / "never.json"
    with pytest.raises(PeassHashMismatch) as excinfo:
        adapter.ingest(SCAN_LINUX, analysis_path=target_doc,
                       expected_scan_sha256="0" * 64)
    assert "refused before any parse" in str(excinfo.value)
    assert called == []
    assert not target_doc.exists()


def test_scan_refuses_expected_scanner_hash_mismatch_before_any_run(
        adapter: PeassAdapter, mock_log: Path):
    with pytest.raises(PeassHashMismatch) as excinfo:
        adapter.scan("linux", expected_scanner_sha256="0" * 64)
    assert "refused before any run" in str(excinfo.value)
    assert _lines(mock_log, "version") == []
    assert _lines(mock_log, "target:") == []


def test_scan_refuses_expected_scan_output_drift_single_attempt(
        adapter: PeassAdapter, tmp_path: Path, mock_log: Path):
    with pytest.raises(PeassHashMismatch) as excinfo:
        adapter.scan("linux", scan_path=tmp_path / "s.txt",
                     analysis_path=tmp_path / "a.json",
                     expected_scan_sha256="0" * 64)
    assert "after run" in str(excinfo.value)
    assert len(_lines(mock_log, "target:")) == 1
    assert not (tmp_path / "a.json").exists()


def test_scan_injected_failure_single_attempt(adapter: PeassAdapter, mock_log: Path,
                                              monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PS4RF_PEASS_MOCK_INJECT", "error")
    with pytest.raises(PeassRunError) as excinfo:
        adapter.scan("linux")
    assert excinfo.value.exit_code == 5
    assert len(_lines(mock_log, "target:")) == 1


def test_scan_timeout_kills_process_without_retry(tmp_path: Path, mock_log: Path,
                                                  monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PS4RF_PEASS_MOCK_INJECT", "hang")
    cfg = PeassConfig(scanner_cmd=MOCK_CMD, work_dir=str(tmp_path / "work"),
                      timeout_s=2.0)
    adapter = PeassAdapter(cfg)
    started = time.monotonic()
    with pytest.raises(PeassTimeout):
        adapter.scan("linux")
    assert time.monotonic() - started < 15
    assert len(_lines(mock_log, "target:")) == 1
    assert _lines(mock_log, "inject:hang") == ["inject:hang"]


def test_unparseable_scan_is_refused(tmp_path: Path, adapter: PeassAdapter):
    garbage = tmp_path / "garbage.txt"
    garbage.write_text("this is not a linPEAS report\n", encoding="utf-8")
    with pytest.raises(PeassSchemaError):
        adapter.ingest(garbage)
    empty = tmp_path / "empty.txt"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(PeassSchemaError):
        adapter.ingest(empty)
    header_only = tmp_path / "header-only.txt"
    header_only.write_text("╔══════════╣ Filesystem ╚ offline fixture ╝\n",
                           encoding="utf-8")
    with pytest.raises(PeassSchemaError):
        adapter.ingest(header_only)     # a section without findings is not a report


def test_missing_scan_file_is_refused(tmp_path: Path, adapter: PeassAdapter):
    with pytest.raises(PeassConfigError):
        adapter.ingest(tmp_path / "nope.txt")


def test_scan_refuses_unknown_target(adapter: PeassAdapter):
    with pytest.raises(PeassConfigError):
        adapter.scan("netbsd")  # type: ignore[arg-type]


# -------------------------------------------------------------------- config/mock
def test_config_requires_argv_list_not_shell_string(tmp_path: Path):
    with pytest.raises(ValidationError):
        PeassConfig(scanner_cmd="bash -c true", work_dir=str(tmp_path))  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        PeassConfig(scanner_cmd=[], work_dir=str(tmp_path))
    with pytest.raises(ValidationError):
        PeassConfig(scanner_cmd=MOCK_CMD, work_dir="")


def test_mock_cli_version_and_unknown_target(tmp_path: Path, mock_log: Path):
    version = subprocess.run([*MOCK_CMD, "--version"], capture_output=True,
                             text=True, cwd=REPO, check=False)
    assert version.returncode == 0
    assert "20231115-mock" in version.stdout
    target = tmp_path / "x.txt"
    unknown = subprocess.run([*MOCK_CMD, "--target", "netbsd", "--output", str(target)],
                             capture_output=True, text=True, cwd=REPO, check=False)
    assert unknown.returncode == 3
    assert not target.exists()
    assert _lines(mock_log, "unknown-target") == ["unknown-target"]


# ------------------------------------------------------------------ static guards
def test_fixtures_stay_synthetic_deterministic_and_clean():
    for path in (SCAN_LINUX, SCAN_ORBISOS, ANALYSIS_LINUX, ANALYSIS_ORBISOS):
        data = path.read_bytes()
        assert data.endswith(b"\n") and not data.endswith(b"\n\n"), path
        text = data.decode("utf-8")
        assert "/home/hermes" not in text, path
        assert "/tmp/" not in text, path
        assert "2026-" not in text, path
    assert "SYNTHETIC" in SCAN_LINUX.read_text()
    assert "SYNTHETIC" in SCAN_ORBISOS.read_text()


def test_peass_sources_stay_shell_free_and_offline():
    sources = {path: path.read_text() for path in (REPO / "tools" / "recon").rglob("*.py")}
    blob = "\n".join(sources.values())
    assert "shell=True" not in blob
    for forbidden in ("import socket", "import http", "urllib", "paramiko", "requests."):
        assert forbidden not in blob, f"forbidden token in tools/recon: {forbidden}"


def test_mock_never_runs_anything():
    source = MOCK_PATH.read_text()
    for forbidden in ("import subprocess", "subprocess.", "os.system", "import socket",
                      "urllib", "eval(", "exec(", "importlib", "Popen"):
        assert forbidden not in source, f"mock must stay inert: {forbidden}"
