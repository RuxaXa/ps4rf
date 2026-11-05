"""Adapter tests against the offline msfrpcd mock (P2, DoD v0.3 §12.7 items 1-3, 5, 6, 8).

All tests run offline against :class:`MockMsfRpc` over real loopback HTTP +
MessagePack; there is no real Metasploit and no external network (DoD 8). The
auth token only ever exists in the environment (spec §12.1).

Run from the repo root:

    .venv/bin/python -m pytest -q tests/test_metasploit_adapter.py
"""

from __future__ import annotations

import hashlib

import pytest

from tools.metasploit.adapter import (CheckResult, ExploitResult, MetasploitAdapter,
                                      MetasploitRunRecord, MsfConfig, MsfEvidenceError,
                                      MsfRpcError, MsfSessionNotOwned, MsfTokenMissing,
                                      verify_run_record)
from tools.metasploit.mock.msfrpcd_mock import MockMsfRpc
from tools.metasploit.redact import options_sha256

TOKEN = "test-token-0123456789abcdef"
SECRET = "Sup3rS3cret!"
EXPLOIT_REF = "exploit/ps4/browser/example"
AUX_REF = "auxiliary/ps4/example_probe"
MOCK_TOKEN_ENV = "PS4RF_MSF_TOKEN_MOCK"


@pytest.fixture()
def mock_rpc(monkeypatch: pytest.MonkeyPatch):
    # The mock's expected token lives under its own variable so tests can hand
    # the adapter a different (wrong) one without changing the expectation.
    monkeypatch.setenv(MOCK_TOKEN_ENV, TOKEN)
    monkeypatch.setenv("PS4RF_MSF_TOKEN", TOKEN)
    mock = MockMsfRpc(token_env=MOCK_TOKEN_ENV)
    mock.start()
    yield mock
    mock.stop()


@pytest.fixture()
def adapter(mock_rpc: MockMsfRpc) -> MetasploitAdapter:
    return MetasploitAdapter(MsfConfig(host="127.0.0.1", port=mock_rpc.port))


def _secret_absent(blob: str) -> bool:
    return (SECRET not in blob
            and hashlib.sha256(SECRET.encode()).hexdigest() not in blob)


# ---------------------------------------------------------------- DoD 1: health
def test_dod1_health_reports_framework_revision(adapter: MetasploitAdapter):
    health = adapter.health()
    assert health["reachable"] is True
    assert health["version"] == "6.4.0-mock"
    assert health["endpoint"].endswith("/api/")


def test_missing_token_is_refused_without_contacting_endpoint(
        adapter: MetasploitAdapter, mock_rpc: MockMsfRpc,
        monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("PS4RF_MSF_TOKEN")
    with pytest.raises(MsfTokenMissing):
        adapter.health()
    assert mock_rpc.call_counts["core.version"] == 0


def test_wrong_token_is_rejected(adapter: MetasploitAdapter,
                                 monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PS4RF_MSF_TOKEN", "wrong-token")
    with pytest.raises(MsfRpcError) as excinfo:
        adapter.health()
    assert excinfo.value.message == "auth.invalid"


def test_non_local_endpoint_requires_tls():
    with pytest.raises(ValueError):
        MsfConfig(host="192.168.1.141", port=55553)
    cfg = MsfConfig(host="192.168.1.141", port=55553, tls=True)
    assert cfg.endpoint.startswith("https://")


# ------------------------------------------------------- DoD 2: modules and info
def test_dod2_list_modules_and_module_info(adapter: MetasploitAdapter):
    refs = adapter.list_modules()
    assert refs == sorted([EXPLOIT_REF, AUX_REF, "post/ps4/example_status"])
    assert adapter.list_modules("auxiliary") == [AUX_REF]
    info = adapter.module_info("exploit", EXPLOIT_REF)
    assert info["rank"] == "normal"
    assert info["name"] == EXPLOIT_REF


# --------------------------------------------------- DoD 3: auxiliary run -> job
def test_dod3_auxiliary_run_yields_job_and_evidence_record(
        adapter: MetasploitAdapter, mock_rpc: MockMsfRpc):
    record = adapter.module_run("auxiliary", AUX_REF, {"RHOSTS": "192.0.2.10"},
                                dry_run=False)
    assert isinstance(record, MetasploitRunRecord)
    assert record.job_id == 1
    assert record.exploit_result is ExploitResult.SUCCESS
    assert record.check_result is CheckResult.NOT_RUN
    assert record.framework_revision == "6.4.0-mock"
    assert mock_rpc.call_counts["module.execute"] == 1


def test_dry_run_checks_only_and_never_executes(adapter: MetasploitAdapter,
                                                mock_rpc: MockMsfRpc):
    record = adapter.module_run("exploit", EXPLOIT_REF)          # dry_run default
    assert record.check_result is CheckResult.VULNERABLE
    assert record.exploit_result is ExploitResult.NOT_RUN
    assert record.job_id is None
    assert mock_rpc.call_counts["module.check"] == 1
    assert mock_rpc.call_counts["module.execute"] == 0


@pytest.mark.parametrize(("code", "expected"), [
    ("vulnerable", CheckResult.VULNERABLE),
    ("safe", CheckResult.PATCHED),
    ("detected", CheckResult.UNKNOWN),
    ("unknown", CheckResult.UNKNOWN),
])
def test_check_code_mapping(adapter: MetasploitAdapter, mock_rpc: MockMsfRpc,
                            code: str, expected: CheckResult):
    mock_rpc.set_check_result(EXPLOIT_REF, code)
    record = adapter.module_run("exploit", EXPLOIT_REF)
    assert record.check_result is expected


def test_no_retry_on_rpc_error(adapter: MetasploitAdapter, mock_rpc: MockMsfRpc):
    """§12.5/§49: no automatic retry after an error -- exactly one attempt."""
    mock_rpc.fail_next("module.execute")
    with pytest.raises(MsfRpcError):
        adapter.module_run("auxiliary", AUX_REF, dry_run=False)
    assert mock_rpc.call_counts["module.execute"] == 1


# --------------------------------------- DoD 5: evidence record + hash binding
def test_dod5_run_record_redacts_secrets(adapter: MetasploitAdapter):
    options = {"RHOST": "192.0.2.10", "RPORT": 4444, "PASSWORD": SECRET}
    record = adapter.module_run("exploit", EXPLOIT_REF, options, dry_run=False)
    assert record.options["PASSWORD"] == "<redacted>"
    assert record.redacted_fields == ["PASSWORD"]
    assert _secret_absent(record.model_dump_json())
    assert record.options_sha256 == options_sha256(options)


def test_t_msf_02_run_records_hash_is_secret_independent(
        adapter: MetasploitAdapter):
    first = adapter.module_run("exploit", EXPLOIT_REF,
                               {"RPORT": 4444, "PASSWORD": "secret-one"})
    second = adapter.module_run("exploit", EXPLOIT_REF,
                                {"RPORT": 4444, "PASSWORD": "secret-two"})
    assert first.options_sha256 == second.options_sha256
    assert first.options == second.options


def test_output_hash_binding_and_verification(adapter: MetasploitAdapter, tmp_path):
    target = tmp_path / "msf_run.json"
    record = adapter.module_run("exploit", EXPLOIT_REF, dry_run=True,
                                output_path=str(target))
    assert target.exists()
    assert record.output_sha256 == hashlib.sha256(target.read_bytes()).hexdigest()
    assert verify_run_record(record) is True
    target.write_bytes(b"{}")                                    # tamper
    with pytest.raises(MsfEvidenceError):
        verify_run_record(record)


def test_verify_run_record_rejects_tampered_options_hash(
        adapter: MetasploitAdapter):
    record = adapter.module_run("exploit", EXPLOIT_REF)
    tampered = record.model_copy(update={"options_sha256": "0" * 64})
    with pytest.raises(MsfEvidenceError):
        verify_run_record(tampered)


# ------------------------------------------------ DoD 6: sessions + ownership
def test_dod6_session_lifecycle_and_ownership(adapter: MetasploitAdapter):
    record = adapter.module_run("exploit", EXPLOIT_REF, dry_run=False)
    session_id = record.session_id
    assert session_id == "1"
    assert session_id in adapter.list_sessions()
    assert adapter.session_info(session_id)["via_exploit"] == EXPLOIT_REF
    output = adapter.session_command(session_id, "id")
    assert "id" in output
    log_entry = adapter.session_log[-1]
    assert log_entry["session_id"] == session_id
    assert log_entry["response_sha256"] == hashlib.sha256(
        output.encode("utf-8")).hexdigest()
    adapter.session_close(session_id)
    assert session_id not in adapter.list_sessions()


def test_foreign_sessions_cannot_be_driven(adapter: MetasploitAdapter,
                                           mock_rpc: MockMsfRpc):
    adapter.module_run("exploit", EXPLOIT_REF, dry_run=False)
    other = MetasploitAdapter(MsfConfig(host="127.0.0.1", port=mock_rpc.port))
    assert "1" in other.list_sessions()                          # visible...
    with pytest.raises(MsfSessionNotOwned):                      # ...not owned
        other.session_command("1", "id")
    with pytest.raises(MsfSessionNotOwned):
        adapter.session_command("999", "id")
    with pytest.raises(MsfSessionNotOwned):
        adapter.session_close("999")


def test_jobs_list_and_stop(adapter: MetasploitAdapter):
    adapter.module_run("auxiliary", AUX_REF, dry_run=False)
    jobs = adapter.list_jobs()
    assert jobs == [{"job_id": 1, "module": AUX_REF}]
    assert adapter.stop_job(1)["result"] == "success"


# ----------------------------------------------------- logs never carry values
def test_logs_never_contain_option_values(adapter: MetasploitAdapter,
                                          mock_rpc: MockMsfRpc):
    adapter.module_run("exploit", EXPLOIT_REF, {"PASSWORD": SECRET}, dry_run=False)
    assert SECRET not in repr(adapter.call_log)
    assert SECRET not in repr(mock_rpc.call_log)
    assert "module.execute" in adapter.call_log
