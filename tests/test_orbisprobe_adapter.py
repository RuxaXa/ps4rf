"""Parity tests for the OrbisProbe adapter v0.1 (offline, mock core).

Run from the repo root, as the freeze runner does:

    .venv/bin/python -m pytest -q tests/test_orbisprobe_adapter.py

Evidence rules: every expected value below is either derived from the committed
fixture (generated with the real OrbisProbe code, see
`tests/fixtures/orbisprobe/README.md`) or mirrors the cited source lines of
OrbisProbe @ 3ee779f. No network, no subprocess (except the env-gated cross-check).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from core.models.candidate import CandidateSource, CandidateState
from core.models.verification import StoredEvidence, VerificationOutcome
from tools.orbisprobe import adapter as adapter_mod
from tools.orbisprobe.adapter import (
    AdapterRefusal,
    ArtifactHashMismatch,
    DiscoveryContext,
    EvidenceArtifact,
    EvidenceBundle,
    OrbisProbeAdapter,
    RunRecord,
    SessionContext,
)

FIXTURE = Path(__file__).parent / "fixtures" / "orbisprobe" / "leads_store.json"
FIXTURE_SHA256 = "a1c32b0d897fd702a56e842533b8e3e88e6e9f1b5c3539ef383bb686349bc479"

# Produced by the real orbisprobe.leads.scoring.rank_leads() on this fixture
# (run 2026-10-05, commit 3ee779f, see fixture README).
EXPECTED_RANK_ORDER = [
    "V5-P1-dddddddddddd",  # 52, EDGE-0
    "V5-P1-cccccccccccc",  # 49, EDGE-1
    "V5-P1-0123456789ab",  # 41, EDGE-2
    "V5-P1-eeeeeeeeeeee",  # 38, EDGE-1, id tiebreak
    "V5-P1-ffffffffffff",  # 38, EDGE-1, id tiebreak
]
EXPECTED_RANK_SCORES = [52, 49, 41, 38, 38]

EXPECTED_STATES = {
    "RC-001": CandidateState.ANOMALY,  # VULNERABILITY_CANDIDATE, no reproducer -> downgraded
    "V5-P1-0123456789ab": CandidateState.OBSERVATION,
    "V5-P1-cccccccccccc": CandidateState.OBSERVATION,
    "V5-P1-dddddddddddd": CandidateState.ANOMALY,  # PROOF_MODE
    "V5-P1-eeeeeeeeeeee": CandidateState.OBSERVATION,
    "V5-P1-ffffffffffff": CandidateState.OBSERVATION,
    "V5-P2-abcdef123456": CandidateState.OBSERVATION,
    "V5-P2-fedcba654321": CandidateState.PARKED,  # ARTIFACT_BLOCKED
}

READ_ONLY_CANDIDATE = "V5-P1-0123456789ab"


@pytest.fixture()
def adapter():
    store = OrbisProbeAdapter()
    records = store.discover(DiscoveryContext(store_paths=(FIXTURE,)))
    assert len(records) == 8
    return store


def _candidate(adapter: OrbisProbeAdapter, candidate_id: str):
    for record in adapter.discover(DiscoveryContext(store_paths=(FIXTURE,))):
        if record.id == candidate_id:
            return record
    raise AssertionError(candidate_id)


def _write_store(tmp_path: Path, leads: list[dict]) -> Path:
    target = tmp_path / "store.json"
    target.write_text(json.dumps({"schema": "orbisprobe-research-leads-v1", "count": len(leads), "leads": leads}))
    return target


def _lead_dict(**overrides) -> dict:
    base = json.loads(FIXTURE.read_text())["leads"][1]  # the READ_ONLY EDGE-2 lead
    base.update(overrides)
    return base


# --- fixture integrity ----------------------------------------------------------


def test_fixture_sha256_pinned():
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == FIXTURE_SHA256


# --- discover -------------------------------------------------------------------


def test_discover_maps_fixture_records(adapter):
    records = adapter.discover(DiscoveryContext(store_paths=(FIXTURE,)))
    assert {r.id for r in records} == set(EXPECTED_STATES)
    for record in records:
        assert record.source is CandidateSource.ORBISPROBE
        assert record.state is EXPECTED_STATES[record.id]
        assert record.surface_id.startswith("orbisprobe:0x")
        assert record.history, record.id
        assert record.history[-1].state is record.state
        assert record.history[-1].actor.startswith(f"orbisprobe:{record.id}")
    rc001 = next(r for r in records if r.id == "RC-001")
    assert "vulnerability_candidate_no_reproducer" in rc001.history[-1].actor
    blocked = next(r for r in records if r.id == "V5-P2-fedcba654321")
    assert blocked.history[-1].actor.endswith(":artifact_blocked")


def test_discover_refuses_unknown_status(tmp_path):
    store = _write_store(tmp_path, [_lead_dict(status="MADE_UP")])
    with pytest.raises(AdapterRefusal) as exc:
        OrbisProbeAdapter().discover(DiscoveryContext(store_paths=(store,)))
    assert exc.value.reason == "UNKNOWN_LEAD_STATUS"


def test_discover_refuses_unknown_schema(tmp_path):
    target = tmp_path / "store.json"
    target.write_text(json.dumps({"schema": "something-else-v9", "leads": []}))
    with pytest.raises(AdapterRefusal) as exc:
        OrbisProbeAdapter().discover(DiscoveryContext(store_paths=(target,)))
    assert exc.value.reason == "UNKNOWN_SCHEMA"


def test_discover_refuses_edge_count_mismatch(tmp_path):
    store = _write_store(tmp_path, [_lead_dict(edge_distance="EDGE-1")])  # fixture lead has 2 unknown edges
    with pytest.raises(AdapterRefusal) as exc:
        OrbisProbeAdapter().discover(DiscoveryContext(store_paths=(store,)))
    assert exc.value.reason == "EDGE_COUNT_MISMATCH"


def test_discover_records_artifact_provenance(adapter):
    assert adapter.artifacts[0].path == str(FIXTURE)
    assert adapter.artifacts[0].sha256 == FIXTURE_SHA256


# --- rank -----------------------------------------------------------------------


def test_rank_matches_real_orbisprobe_order(adapter):
    candidates = adapter.discover(DiscoveryContext(store_paths=(FIXTURE,)))
    ranked = adapter.rank(candidates)
    assert [e.candidate_id for e in ranked.entries] == EXPECTED_RANK_ORDER
    assert [e.score for e in ranked.entries] == EXPECTED_RANK_SCORES
    assert [e.rank for e in ranked.entries] == [1, 2, 3, 4, 5]
    # inactive leads (parked/blocked/terminal) are excluded
    assert "V5-P2-abcdef123456" not in {e.candidate_id for e in ranked.entries}
    assert "RC-001" not in {e.candidate_id for e in ranked.entries}


def test_rank_refuses_unknown_candidate(adapter):
    candidates = adapter.discover(DiscoveryContext(store_paths=(FIXTURE,)))
    stranger = candidates[0].model_copy(update={"id": "NOT-DISCOVERED"})
    with pytest.raises(AdapterRefusal) as exc:
        adapter.rank([stranger])
    assert exc.value.reason == "UNKNOWN_CANDIDATE"


@pytest.mark.skipif(
    not (os.environ.get("ORBISPROBE_PYTHON") and os.environ.get("ORBISPROBE_SRC")),
    reason="ORBISPROBE_PYTHON / ORBISPROBE_SRC not set (cross-check against real code)",
)
def test_rank_cross_check_with_real_orbisprobe(adapter):
    script = (
        "import sys, json; sys.path.insert(0, sys.argv[1]); "
        "from orbisprobe.leads.store import LeadStore; "
        "from orbisprobe.leads.scoring import rank_leads; "
        "store = LeadStore.load(sys.argv[2]); "
        "print(json.dumps([l.lead_id for l in rank_leads(list(store.leads))]))"
    )
    out = subprocess.run(
        [os.environ["ORBISPROBE_PYTHON"], "-c", script, os.environ["ORBISPROBE_SRC"], str(FIXTURE)],
        capture_output=True, text=True, check=True,
    )
    real_order = json.loads(out.stdout)
    candidates = adapter.discover(DiscoveryContext(store_paths=(FIXTURE,)))
    ranked = adapter.rank(candidates)
    assert [e.candidate_id for e in ranked.entries] == real_order


# --- status mapping -------------------------------------------------------------


def test_status_mapping_tables_exhaustive():
    lead_table = adapter_mod.LEAD_STATUS_TO_STATE
    assert len(lead_table) == 12
    assert set(lead_table) == {
        "DISCOVERED", "SCORED", "EDGE_ANALYZED", "CLOSURE_PENDING", "EVIDENCE_PROBE_READY",
        "PROOF_MODE", "VULNERABILITY_CANDIDATE", "SAFE_INVARIANT", "DOWNGRADED", "PARKED",
        "ARTIFACT_BLOCKED", "DISPROVED",
    }
    disposition_table = adapter_mod.DISPOSITION_TO_STATE
    assert len(disposition_table) == 8
    assert disposition_table["EVIDENCE_CONFLICT"] is None
    for value in lead_table.values():
        assert value in {state.name for state in CandidateState}
    # PS4RF-only states must never be assigned from OrbisProbe statuses
    mapped_values = set(lead_table.values()) | {v for v in disposition_table.values() if v}
    assert mapped_values.isdisjoint(adapter_mod.PS4RF_ONLY_STATES)


# --- reclassify -----------------------------------------------------------------


def test_reclassify_vulnerability_candidate_requires_reproducer(adapter):
    candidate = _candidate(adapter, "V5-P1-0123456789ab")
    bundle = EvidenceBundle(source="orbisprobe-leads", lead_id=candidate.id, status="VULNERABILITY_CANDIDATE")
    with pytest.raises(AdapterRefusal) as exc:
        adapter.reclassify(candidate, bundle)
    assert exc.value.reason == "REPRODUCER_REQUIRED"
    bundle_ok = EvidenceBundle(
        source="orbisprobe-leads", lead_id=candidate.id, status="VULNERABILITY_CANDIDATE",
        reproducer=EvidenceArtifact(path="/fake/repro.bin", sha256="a" * 64),
    )
    updated = adapter.reclassify(candidate, bundle_ok)
    assert updated.state is CandidateState.EXPLOIT_CANDIDATE
    assert len(updated.history) == len(candidate.history) + 1
    assert updated.history[-1].actor == f"orbisprobe:{candidate.id}:orbisprobe-leads"


def test_reclassify_safe_closed_and_disproved_to_closed(adapter):
    candidate = _candidate(adapter, "V5-P1-cccccccccccc")
    for status in ("SAFE_CLOSED", "DISPROVED"):
        updated = adapter.reclassify(candidate, EvidenceBundle(source="orbisprobe-leads", lead_id=candidate.id, status=status))
        assert updated.state is CandidateState.CLOSED


def test_reclassify_evidence_conflict_refused(adapter):
    candidate = _candidate(adapter, "V5-P1-cccccccccccc")
    with pytest.raises(AdapterRefusal) as exc:
        adapter.reclassify(candidate, EvidenceBundle(source="orbisprobe-evidence-pass", lead_id=candidate.id, status="EVIDENCE_CONFLICT"))
    assert exc.value.reason == "REVIEW_REQUIRED"


def test_reclassify_unknown_status_refused(adapter):
    candidate = _candidate(adapter, "V5-P1-cccccccccccc")
    with pytest.raises(AdapterRefusal) as exc:
        adapter.reclassify(candidate, EvidenceBundle(source="orbisprobe-leads", lead_id=candidate.id, status="WAT"))
    assert exc.value.reason == "UNKNOWN_STATUS"


# --- propose_experiment ---------------------------------------------------------


def test_propose_experiment_offline_is_deterministic(adapter):
    candidate = _candidate(adapter, READ_ONLY_CANDIDATE)
    first = adapter.propose_experiment(candidate, SessionContext(boot_id="BOOT-FIXTURE-01"))
    second = adapter.propose_experiment(candidate, SessionContext(boot_id="BOOT-FIXTURE-01"))
    assert first.canonical_sha256 == second.canonical_sha256
    assert first.ir["_canonical_sha256"] == first.canonical_sha256
    assert first.ir["steps"] == [{"op": "CALL", "call": {"operation": "session.ping", "arguments": {}}}]
    assert first.ir["metadata"]["lead_id"] == READ_ONLY_CANDIDATE


def test_propose_experiment_refuses_non_offline(adapter):
    candidate = _candidate(adapter, "RC-001")  # reversible_kernel_ram
    with pytest.raises(AdapterRefusal) as exc:
        adapter.propose_experiment(candidate, SessionContext(boot_id="BOOT-FIXTURE-01"))
    assert exc.value.reason == "NON_OFFLINE_PROPOSAL_REFUSED"


def test_propose_experiment_requires_boot_id(adapter):
    candidate = _candidate(adapter, READ_ONLY_CANDIDATE)
    with pytest.raises(AdapterRefusal) as exc:
        adapter.propose_experiment(candidate, SessionContext(boot_id=""))
    assert exc.value.reason == "SESSION_CONTEXT_INCOMPLETE"


# --- consume_evidence -----------------------------------------------------------


def _run_record(tmp_path: Path, artifact_sha: str) -> RunRecord:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"orbisprobe-fixture-evidence")
    return RunRecord(
        run_id="RUN-20261005T120000Z-AB12CD34",
        operation="orbisprobe.lead_evidence",
        outcome="PASS",
        capability="research.orbisprobe",
        profile_sha256="a" * 64,
        boot_id="BOOT-FIXTURE-01",
        expected="lead evidence pack present",
        observed="evidence pack hashed",
        evidence=(EvidenceArtifact(path=str(artifact), sha256=artifact_sha),),
    )


def test_consume_evidence_hash_binding(adapter, tmp_path):
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"orbisprobe-fixture-evidence")
    real_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    run = _run_record(tmp_path, real_sha)
    adapter.consume_evidence(run)
    assert len(adapter.consumed_hashes) == 1
    stored = adapter.evidence_store.get_verified_evidence(adapter.consumed_hashes[0])
    assert isinstance(stored, StoredEvidence)
    assert stored.run_id == run.run_id
    assert stored.outcome is VerificationOutcome.PASS
    assert stored.evidence_ref.sha256 == real_sha


def test_consume_evidence_rejects_tampered_artifact(adapter, tmp_path):
    run = _run_record(tmp_path, "b" * 64)  # declared hash != on-disk content
    with pytest.raises(ArtifactHashMismatch):
        adapter.consume_evidence(run)


def test_consume_evidence_rejects_bad_run_id(adapter, tmp_path):
    missing = tmp_path / "not-present.bin"  # not on disk -> only format checks apply
    run = RunRecord(
        run_id="RUN-20261005T120000Z-AB12CD34",
        operation="orbisprobe.lead_evidence",
        outcome="PASS",
        capability="research.orbisprobe",
        profile_sha256="a" * 64,
        boot_id="BOOT-FIXTURE-01",
        expected="e",
        observed="o",
        evidence=(EvidenceArtifact(path=str(missing), sha256="b" * 64),),
    )
    bad = RunRecord(**{**run.__dict__, "run_id": "RUN-not-a-run"})
    with pytest.raises(AdapterRefusal) as exc:
        adapter.consume_evidence(bad)
    assert exc.value.reason == "EVIDENCE_MODEL_INVALID"


# --- minimize -------------------------------------------------------------------


def test_minimize_returns_hash_bound_reproducer(adapter):
    candidate = _candidate(adapter, READ_ONLY_CANDIDATE)
    bundle = EvidenceBundle(
        source="orbisprobe-evidence-pass", lead_id=candidate.id, status="VULNERABILITY_CANDIDATE",
        reproducer=EvidenceArtifact(path="/fake/repro.bin", sha256="c" * 64),
        run_id="RUN-20261005T120000Z-AB12CD34", plan_sha256="d" * 64,
    )
    repro = adapter.minimize(candidate, bundle)
    assert repro.candidate_id == candidate.id
    assert repro.plan_sha256 == "d" * 64
    assert repro.created_by == "orbisprobe-adapter/v0.1"


def test_minimize_refuses_incomplete_bundle(adapter):
    candidate = _candidate(adapter, READ_ONLY_CANDIDATE)
    with pytest.raises(AdapterRefusal) as exc:
        adapter.minimize(candidate, EvidenceBundle(source="s", lead_id=candidate.id, status="PARKED"))
    assert exc.value.reason == "REPRODUCER_INCOMPLETE"


# --- static guard rails ---------------------------------------------------------


def test_adapter_has_no_execution_surfaces():
    import re

    source = Path(adapter_mod.__file__).read_text(encoding="utf-8")
    import_lines = [ln for ln in source.splitlines() if re.match(r"^\s*(import|from)\s", ln)]
    banned_modules = (
        "subprocess", "socket", "http", "urllib", "paramiko", "telnetlib", "ftplib", "requests",
        "orbisprobe.live", "orbisprobe.live import",
    )
    for line in import_lines:
        for banned in banned_modules:
            assert banned not in line, line
    for token in ("shell=True", "Popen", "connect("):
        assert token not in source, token


def test_adapter_contains_no_firmware_addresses():
    source = Path(adapter_mod.__file__).read_text(encoding="utf-8")
    for forbidden in ("0xffffffff", "0xFFFFFF", "TRACE_FW", "HOOK_RVA", "prison0", "kbase"):
        assert forbidden not in source, forbidden
