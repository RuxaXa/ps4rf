"""AFL++ adapter tests against the offline tool-surface mock (P3).

Everything runs offline: no afl binaries, no fuzzing, no target execution, no
gdb. Pinned fixture hashes come from ``tests/fixtures/aflplusplus/README.md``.

Run from the repo root:

    .venv/bin/python -m pytest -q tests/test_aflplusplus_adapter.py
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

from tools.aflplusplus.adapter import (AflAdapter, AflCminResult, AflCollectResult,
                                       AflConfig, AflConfigError, AflCorpusOutcome,
                                       AflEvidenceError, AflHashMismatch, AflRunError,
                                       AflSchemaError, AflShowmapResult, AflTimeout,
                                       AflTminResult, verify_run_record)

REPO = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "aflplusplus"
TARGET = FIXTURES / "target.bin"
CORPUS = FIXTURES / "corpus"
CRASHES = FIXTURES / "crashes"
SEED0 = CORPUS / "seed0.bin"
CRASH_A = CRASHES / "crash_a.bin"

TARGET_SHA = "7c3408ffce2d37de47dfb79fbf64c91ea94031d185130912b5dd4e1af9ae0a1e"
RESULT_SHOWMAP_SEED0_SHA = "dd1c6684d93da8adef8b278f442fcc0e0d87db9509a09fc4414be180517a2262"
RESULT_SHOWMAP_CRASH_SHA = "f5e0746a9feeba486913c7fe1eeff632153b56c52f3c028b26445a42ce7db310"
RESULT_CMIN_SHA = "aca6533192443d96eaced184e6c2500d55adc8acb046b26c57cb40619d4fc26b"
RESULT_COLLECT_SHA = "1b533a4193cb2a6247bb8d5b191c4f59af73c4a9a444e9ea5397b8cb9be1c124"
RESULT_TMIN_SHA = "6e7f6f6f3c519163114dfdf1e58730a8afa0977bf8e87e1c540e648ba03c949e"
MINIMIZED_SHA = "c4986c5d7f9e0497ca09e07bd99975d4172d4484268c3bf7bec83b3e5e04e5ef"

MOCK_CMD = [sys.executable, "-m", "tools.aflplusplus.mock.afl_mock"]


def _mock(tool: str) -> list[str]:
    return [*MOCK_CMD, tool]


@pytest.fixture()
def config(tmp_path: Path) -> AflConfig:
    return AflConfig(fuzz_cmd=_mock("afl-fuzz"), showmap_cmd=_mock("afl-showmap"),
                     cmin_cmd=_mock("afl-cmin"), tmin_cmd=_mock("afl-tmin"),
                     collect_cmd=_mock("afl-collect"), work_dir=str(tmp_path / "afl"),
                     timeout_s=30)


@pytest.fixture()
def adapter(config: AflConfig) -> AflAdapter:
    return AflAdapter(config)


@pytest.fixture()
def mock_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "mock.log"
    monkeypatch.setenv("PS4RF_AFL_MOCK_LOG", str(path))
    return path


def _lines(path: Path, prefix: str) -> list[str]:
    if not path.exists():
        return []
    return [line for line in path.read_text().splitlines() if line.startswith(prefix)]


# ------------------------------------------------------------------- health/hash
def test_health_reports_afl_version(adapter: AflAdapter):
    health = adapter.health()
    assert health["reachable"] is True
    assert health["version"] == "4.21c-mock"


def test_hash_file_matches_pinned_target(adapter: AflAdapter):
    assert adapter.hash_file(TARGET) == TARGET_SHA


# ---------------------------------------------------------------- showmap/coverage
def test_showmap_returns_pinned_coverage(adapter: AflAdapter, tmp_path: Path):
    out = tmp_path / "cov.json"
    outcome = adapter.showmap(TARGET, SEED0, result_path=out)
    assert outcome.tuples == ["0x0001", "0x0002", "0x0003", "0x0004"]
    assert outcome.crashes is False
    assert outcome.signature is None
    assert outcome.target.sha256 == TARGET_SHA
    assert outcome.run.coverage_count == 4
    assert outcome.run.input_hashes["target"] == TARGET_SHA
    assert hashlib.sha256(out.read_bytes()).hexdigest() == RESULT_SHOWMAP_SEED0_SHA
    assert out.read_bytes() == (FIXTURES / "result-showmap-seed0-v1.json").read_bytes()


def test_showmap_flags_crash_inputs(adapter: AflAdapter, tmp_path: Path):
    out = tmp_path / "cov.json"
    outcome = adapter.showmap(TARGET, CRASH_A, result_path=out)
    assert outcome.crashes is True
    assert outcome.signature == "0x41414141"
    assert outcome.run.crashes_count == 1
    assert hashlib.sha256(out.read_bytes()).hexdigest() == RESULT_SHOWMAP_CRASH_SHA


def test_showmap_refuses_hash_mismatch_before_invocation(adapter: AflAdapter,
                                                         mock_log: Path):
    with pytest.raises(AflHashMismatch):
        adapter.showmap(TARGET, SEED0, expected_target_sha256="0" * 64)
    assert _lines(mock_log, "tool:") == []
    with pytest.raises(AflHashMismatch):
        adapter.showmap(TARGET, SEED0, expected_input_sha256="0" * 64)
    assert _lines(mock_log, "tool:") == []


# ------------------------------------------------------------------- corpus workflow
def test_cmin_keeps_and_drops_as_pinned(adapter: AflAdapter, tmp_path: Path):
    out = tmp_path / "cmin.json"
    outcome = adapter.cmin(CORPUS, result_path=out)
    assert outcome.kept == ["seed0.bin", "seed2.bin"]
    assert [(entry.name, entry.reason) for entry in outcome.dropped] == [
        ("seed1.bin", "duplicate coverage"), ("seed3.bin", "no new coverage")]
    assert outcome.coverage_total == 8
    assert outcome.corpus.total == 4
    assert (outcome.run.kept_count, outcome.run.dropped_count) == (2, 2)
    assert hashlib.sha256(out.read_bytes()).hexdigest() == RESULT_CMIN_SHA
    assert out.read_bytes() == (FIXTURES / "result-cmin-v1.json").read_bytes()
    assert sorted(outcome.run.input_hashes) == [
        "corpus/seed0.bin", "corpus/seed1.bin", "corpus/seed2.bin", "corpus/seed3.bin"]


def test_cmin_refuses_empty_directory(adapter: AflAdapter, tmp_path: Path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(AflConfigError):
        adapter.cmin(empty)


# --------------------------------------------------------------- reproducer workflow
def test_tmin_shrinks_and_preserves_signature(adapter: AflAdapter, tmp_path: Path):
    out, minimized = tmp_path / "tmin.json", tmp_path / "min.bin"
    outcome = adapter.tmin(CRASH_A, minimized_path=minimized, result_path=out)
    assert outcome.input.size == 32
    assert outcome.minimized.size == 23
    assert outcome.minimized.sha256 == MINIMIZED_SHA
    assert outcome.signature == "0x41414141"
    assert outcome.preserved_signature is True
    assert hashlib.sha256(minimized.read_bytes()).hexdigest() == MINIMIZED_SHA
    assert minimized.read_bytes() == \
        (FIXTURES / "minimized-crash_a-v1.bin").read_bytes()
    assert hashlib.sha256(out.read_bytes()).hexdigest() == RESULT_TMIN_SHA
    assert out.read_bytes() == (FIXTURES / "result-tmin-v1.json").read_bytes()
    assert outcome.run.minimized_sha256 == MINIMIZED_SHA


def test_tmin_refuses_non_crash_input(adapter: AflAdapter, mock_log: Path):
    with pytest.raises(AflRunError) as excinfo:
        adapter.tmin(SEED0)
    assert excinfo.value.exit_code == 4
    assert len(_lines(mock_log, "tool:afl-tmin")) == 1       # single attempt


# -------------------------------------------------------------------- crash triage
def test_triage_groups_crashes_by_signature(adapter: AflAdapter, tmp_path: Path):
    out = tmp_path / "collect.json"
    outcome = adapter.triage(CRASHES, result_path=out)
    assert [(group.signature, group.members) for group in outcome.groups] == [
        ("0x41414141", ["crash_a.bin", "crash_b.bin"]),
        ("0x42424242", ["crash_c.bin"])]
    assert outcome.total == 3
    assert (outcome.run.groups_count, outcome.run.crashes_count) == (2, 3)
    assert hashlib.sha256(out.read_bytes()).hexdigest() == RESULT_COLLECT_SHA
    assert out.read_bytes() == (FIXTURES / "result-collect-v1.json").read_bytes()


def test_triage_refuses_non_crash_directory(adapter: AflAdapter, mock_log: Path,
                                            tmp_path: Path):
    with pytest.raises(AflRunError) as excinfo:
        adapter.triage(CORPUS)
    assert excinfo.value.exit_code == 4
    assert len(_lines(mock_log, "tool:afl-collect")) == 1


# ----------------------------------------------------------------------- evidence
def test_run_records_verify_and_detect_tamper(adapter: AflAdapter):
    outcomes = [adapter.showmap(TARGET, CRASH_A), adapter.cmin(CORPUS),
                adapter.tmin(CRASH_A), adapter.triage(CRASHES)]
    assert all(verify_run_record(outcome.run) for outcome in outcomes)
    result_path = Path(outcomes[1].run.result_path)
    original = result_path.read_text()
    result_path.write_text(original + "\n")
    with pytest.raises(AflEvidenceError):
        verify_run_record(outcomes[1].run)
    result_path.write_text(original)
    assert verify_run_record(outcomes[1].run) is True


def test_verify_detects_count_input_and_minimized_drift(adapter: AflAdapter,
                                                        tmp_path: Path):
    outcome = adapter.tmin(CRASH_A)
    drifted = outcome.run.model_copy(update={"crashes_count": 7})
    with pytest.raises(AflEvidenceError) as excinfo:
        verify_run_record(drifted)
    assert "counts" in str(excinfo.value)

    corpus_outcome = adapter.cmin(CORPUS, result_path=tmp_path / "c.json")
    seed = CORPUS / "seed0.bin"
    original = seed.read_bytes()
    seed.write_bytes(original + b"\x00")                     # input drift
    try:
        with pytest.raises(AflEvidenceError):
            verify_run_record(corpus_outcome.run)
    finally:
        seed.write_bytes(original)
    assert verify_run_record(corpus_outcome.run) is True

    assert outcome.run.minimized_path is not None
    minimized = Path(outcome.run.minimized_path)             # minimized drift
    minimized_original = minimized.read_bytes()
    minimized.write_bytes(b"junk")
    try:
        with pytest.raises(AflEvidenceError):
            verify_run_record(outcome.run)
    finally:
        minimized.write_bytes(minimized_original)
    assert verify_run_record(outcome.run) is True


def test_runs_keep_distinct_result_files(adapter: AflAdapter):
    first = adapter.showmap(TARGET, SEED0)
    second = adapter.showmap(TARGET, CRASH_A)
    assert first.run.result_path != second.run.result_path
    assert verify_run_record(first.run) and verify_run_record(second.run)


# ---------------------------------------------------------------------- failures
def test_unknown_target_is_refused_single_attempt(adapter: AflAdapter, tmp_path: Path,
                                                  mock_log: Path):
    fake = tmp_path / "fake-target.bin"
    fake.write_bytes(b"not the committed target")
    with pytest.raises(AflRunError) as excinfo:
        adapter.showmap(fake, SEED0)
    assert excinfo.value.exit_code == 3
    assert "mock catalog" in excinfo.value.detail
    assert len(_lines(mock_log, "tool:afl-showmap")) == 1


def test_injected_failure_single_attempt(adapter: AflAdapter, mock_log: Path,
                                         monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PS4RF_AFL_MOCK_INJECT", "error")
    with pytest.raises(AflRunError) as excinfo:
        adapter.cmin(CORPUS)
    assert excinfo.value.exit_code == 8
    assert len(_lines(mock_log, "tool:afl-cmin")) == 1


def test_timeout_kills_process_without_retry(tmp_path: Path, mock_log: Path,
                                             monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PS4RF_AFL_MOCK_INJECT", "hang")
    adapter = AflAdapter(AflConfig(fuzz_cmd=_mock("afl-fuzz"),
                                   showmap_cmd=_mock("afl-showmap"),
                                   cmin_cmd=_mock("afl-cmin"),
                                   tmin_cmd=_mock("afl-tmin"),
                                   collect_cmd=_mock("afl-collect"),
                                   work_dir=str(tmp_path / "afl"), timeout_s=2.0))
    started = time.monotonic()
    with pytest.raises(AflTimeout):
        adapter.cmin(CORPUS)
    assert time.monotonic() - started < 15
    assert _lines(mock_log, "inject:hang") == ["inject:hang"]
    assert len(_lines(mock_log, "tool:afl-cmin")) == 1


# ------------------------------------------------------------------ model guards
def test_cmin_partition_and_showmap_consistency_are_enforced():
    document = json.loads((FIXTURES / "result-cmin-v1.json").read_text())
    overlapping = json.loads(json.dumps(document))
    overlapping["kept"].append("seed1.bin")                  # kept and dropped
    with pytest.raises(ValidationError):
        AflCminResult.model_validate(overlapping)
    incomplete = json.loads(json.dumps(document))
    incomplete["dropped"] = incomplete["dropped"][:-1]       # no longer partitions
    with pytest.raises(ValidationError):
        AflCminResult.model_validate(incomplete)
    showmap = json.loads((FIXTURES / "result-showmap-seed0-v1.json").read_text())
    crash_without_signature = json.loads(json.dumps(showmap))
    crash_without_signature["crashes"] = True
    with pytest.raises(ValidationError):
        AflShowmapResult.model_validate(crash_without_signature)
    unsorted = json.loads(json.dumps(showmap))
    unsorted["tuples"] = list(reversed(unsorted["tuples"]))
    with pytest.raises(ValidationError):
        AflShowmapResult.model_validate(unsorted)
    with pytest.raises(ValidationError):                     # strict: no extra keys
        AflShowmapResult.model_validate({**showmap, "surprise": 1})


def test_tmin_and_collect_invariants_are_enforced():
    document = json.loads((FIXTURES / "result-tmin-v1.json").read_text())
    lost = json.loads(json.dumps(document))
    lost["preserved_signature"] = False
    with pytest.raises(ValidationError):                     # signature must survive
        AflTminResult.model_validate(lost)
    grown = json.loads(json.dumps(document))
    grown["minimized"]["size"] = grown["input"]["size"] + 1
    with pytest.raises(ValidationError):                     # must shrink or stay
        AflTminResult.model_validate(grown)
    collect = json.loads((FIXTURES / "result-collect-v1.json").read_text())
    wrong_total = json.loads(json.dumps(collect))
    wrong_total["total"] = 5
    with pytest.raises(ValidationError):
        AflCollectResult.model_validate(wrong_total)
    duplicate_member = json.loads(json.dumps(collect))
    duplicate_member["groups"][1]["members"].append("crash_a.bin")
    with pytest.raises(ValidationError):
        AflCollectResult.model_validate(duplicate_member)


# ------------------------------------------------------------------- config guard
def test_config_requires_argv_lists_not_shell_strings(tmp_path: Path):
    with pytest.raises(ValidationError):
        AflConfig(showmap_cmd="bash -c true", work_dir=str(tmp_path))  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        AflConfig(cmin_cmd=[], work_dir=str(tmp_path))
    with pytest.raises(ValidationError):
        AflConfig(work_dir="")


# --------------------------------------------------------------- static guards
def test_afl_sources_stay_shell_free_and_firmware_free():
    sources = {path: path.read_text()
               for path in (REPO / "tools" / "aflplusplus").rglob("*.py")}
    blob = "\n".join(sources.values())
    assert "shell=True" not in blob
    for forbidden in ("import socket", "import http", "urllib", "kbase", "rdmsr",
                      "/payload"):
        assert forbidden not in blob, f"forbidden token in tools/aflplusplus: {forbidden}"
    assert re.search(r"0xc0[0-9a-f]{6,}", blob) is None, "firmware-looking address literal"


def test_mock_never_executes_or_fuzzes():
    source = (REPO / "tools" / "aflplusplus" / "mock" / "afl_mock.py").read_text()
    for forbidden in ("import subprocess", "subprocess.run", "subprocess.Popen",
                      "os.system", "eval(", "exec(", "importlib", "gdb"):
        assert forbidden not in source, f"mock must stay inert: {forbidden}"
