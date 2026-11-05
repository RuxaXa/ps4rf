"""OrbisProbe adapter v0.1 — offline data translator between OrbisProbe artifacts
and PS4RF models.

Binding rules (spec §10.3, hard rules):

1. Profiles/Candidates/Evidence only via PS4RF APIs (this module defines the v0.1
   conversion and uses PS4RF models; it owns no truth of its own).
2. Proposals always pass the PS4RF safety gate (here: ``compile_experiment`` +
   budget check; the proposal vocabulary is restricted to offline session steps).
3. The adapter executes nothing itself — no subprocess, no sockets, no SSH.
4. No new RVAs — no firmware addresses/constants in this module (test-enforced).
5. No payload delivery — the ``orbisprobe.live`` subsystem is never imported.

Evidence: ``ORBISPROBE-INVENTORY.md`` (source facts) and
``ORBISPROBE-PS4RF-MAPPING.md`` (mapping + status table, §3.2) in the repo root.
Status mapping constants mirror ``orbisprobe/leads/scoring.py`` (commit 3ee779f);
see mapping doc for the authoritative table.

Draft types (``RunRecord``, ``EvidenceBundle``, ``Reproducer``, ``DiscoveryContext``,
``SessionContext``) are provisional v0.1 envelopes pending their PS4RF schemas.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from pydantic import TypeAdapter, ValidationError

from core.evidence.store import InMemoryEvidenceStore
from core.experiment.compiler import compile_experiment
from core.models.candidate import (
    CandidateRecord,
    CandidateSource,
    CandidateState,
    Transition,
)
from core.models.capability import Scope
from core.models.common import EvidenceRef, ProviderType, RunId, Sha256, TargetExecutionContext
from core.models.verification import StoredEvidence, VerificationOutcome

STORE_SCHEMA = "orbisprobe-research-leads-v1"

# --- status mapping (v0.1, conservative; mapping doc §3.2) --------------------

LEAD_STATUS_TO_STATE: dict[str, str] = {
    "DISCOVERED": "OBSERVATION",
    "SCORED": "OBSERVATION",
    "EDGE_ANALYZED": "OBSERVATION",
    "CLOSURE_PENDING": "ANOMALY",
    "EVIDENCE_PROBE_READY": "ANOMALY",
    "PROOF_MODE": "ANOMALY",
    "VULNERABILITY_CANDIDATE": "EXPLOIT_CANDIDATE",
    "SAFE_INVARIANT": "CLOSED",
    "DOWNGRADED": "PARKED",
    "PARKED": "PARKED",
    "ARTIFACT_BLOCKED": "PARKED",
    "DISPROVED": "CLOSED",
}

DISPOSITION_TO_STATE: dict[str, str | None] = {
    "PROOF_MODE_READY": "ANOMALY",
    "CLOSURE_PENDING": "ANOMALY",
    "VULNERABILITY_CANDIDATE": "EXPLOIT_CANDIDATE",
    "SAFE_CLOSED": "CLOSED",
    "DOWNGRADED": "PARKED",
    "PARKED": "PARKED",
    "ARTIFACT_BLOCKED": "PARKED",
    "EVIDENCE_CONFLICT": None,  # never auto-transition (mapping doc §3.2)
}

# PS4RF states that must never be assigned from OrbisProbe status alone.
PS4RF_ONLY_STATES = frozenset({"BUG", "LOGIC_BUG", "CRASH", "PRIMITIVE", "EXPLOITABLE", "CHAINABLE"})

# Active-status set + ordering constants mirrored from orbisprobe/leads/scoring.py
# (ACTIVE_STATUSES :32, EDGE_ORDER :15, COST_PENALTY :23, EDGE_PENALTY :7).
ACTIVE_LEAD_STATUSES = frozenset(
    {"DISCOVERED", "SCORED", "EDGE_ANALYZED", "CLOSURE_PENDING", "EVIDENCE_PROBE_READY", "PROOF_MODE"}
)
EDGE_ORDER = {"EDGE-0": 0, "EDGE-1": 1, "EDGE-2": 2, "EDGE-3PLUS": 3, "ARTIFACT_BLOCKED": 4}
EDGE_PENALTY = {"EDGE-0": 0, "EDGE-1": 2, "EDGE-2": 6, "EDGE-3PLUS": 12, "ARTIFACT_BLOCKED": 20}
COST_PENALTY = {"COST-1": 1, "COST-2": 3, "COST-3": 6, "COST-4": 10, "COST-5": 15, "COST-BLOCKED": 20}

_LEAD_REQUIRED = (
    "lead_id", "origin", "root", "source", "sink", "hardware_class", "user_influence",
    "candidate_invariant", "known_edges", "unknown_edges", "evidence", "observable",
    "persistence_risk", "runtime_requirements", "risk_class", "status", "control_score",
    "sink_score", "gap_score", "edge_distance", "closure_cost", "evidence_value", "lead_score",
)

_SHA_ADAPTER = TypeAdapter(Sha256)
_RUN_ID_ADAPTER = TypeAdapter(RunId)

PROPOSAL_RISK_ALLOWLIST = frozenset({"offline", "read_only"})


class OrbisProbeAdapterError(Exception):
    """Base error for adapter refusals and integrity failures."""


class AdapterRefusal(OrbisProbeAdapterError):
    """Fail-closed refusal: the adapter will not guess or escalate."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


class ArtifactHashMismatch(OrbisProbeAdapterError):
    """A verified-on-disk artifact does not match its declared hash."""


# --- draft boundary types (provisional v0.1) ----------------------------------


@dataclass(frozen=True)
class DiscoveryContext:
    """Where to read OrbisProbe artifacts from (read-only)."""

    store_paths: tuple[Path, ...] = ()


@dataclass(frozen=True)
class SessionContext:
    """PS4RF session facts a proposal must be bound to (draft)."""

    boot_id: str
    session_id: str | None = None


@dataclass(frozen=True)
class RankedEntry:
    candidate_id: str
    rank: int
    score: int
    state: str
    edge_distance: str
    closure_cost: str


@dataclass(frozen=True)
class RankedCandidates:
    entries: tuple[RankedEntry, ...]


@dataclass(frozen=True)
class ProofReport:
    candidate_id: str
    lead_status: str
    evidence: tuple[str, ...]
    unknown_edges: tuple[str, ...]
    persistence_risk: str
    verdict: str = "UNKNOWN_UNVERIFIED"


@dataclass(frozen=True)
class ExperimentIR:
    ir: dict[str, Any]
    canonical_sha256: str


@dataclass(frozen=True)
class EvidenceArtifact:
    path: str
    sha256: str


@dataclass(frozen=True)
class RunRecord:
    """Draft run record (produced by PS4RF runs; provisional shape)."""

    run_id: str
    operation: str
    outcome: str
    capability: str
    profile_sha256: str
    boot_id: str
    expected: str
    observed: str
    evidence: tuple[EvidenceArtifact, ...] = ()
    context: str = "UNKNOWN"
    scope: str = "BOOT"
    session_id: str | None = None
    provider: str = "orbisprobe:adapter-v0.1"
    provider_type: str = "FIRMWARE_PROFILE"  # fail-closed: cannot grant availability/assurance


@dataclass(frozen=True)
class EvidenceBundle:
    """Draft evidence bundle handed to reclassify/minimize (provisional shape)."""

    source: str
    lead_id: str
    status: str
    reproducer: EvidenceArtifact | None = None
    run_id: str | None = None
    plan_sha256: str | None = None


@dataclass(frozen=True)
class Reproducer:
    candidate_id: str
    run_id: str
    plan_sha256: str
    artifact_path: str
    artifact_sha256: str
    created_by: str = "orbisprobe-adapter/v0.1"


class OrbisProbeAdapterProtocol(Protocol):
    """Spec interface v0.1 (ps4rf spec §10.3)."""

    def discover(self, context: DiscoveryContext) -> list[CandidateRecord]: ...
    def rank(self, candidates: Sequence[CandidateRecord]) -> RankedCandidates: ...
    def prove(self, candidate: CandidateRecord) -> ProofReport: ...
    def propose_experiment(self, candidate: CandidateRecord, context: SessionContext) -> ExperimentIR: ...
    def consume_evidence(self, run: RunRecord) -> None: ...
    def reclassify(self, candidate: CandidateRecord, evidence: EvidenceBundle) -> CandidateRecord: ...
    def minimize(self, candidate: CandidateRecord, evidence: EvidenceBundle) -> Reproducer: ...


# --- helpers ------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _state_for_lead_status(status: str) -> CandidateState | None:
    name = LEAD_STATUS_TO_STATE.get(status)
    return CandidateState[name] if name else None


def _state_for_bundle_status(status: str) -> CandidateState | None:
    if status in LEAD_STATUS_TO_STATE:
        return _state_for_lead_status(status)
    name = DISPOSITION_TO_STATE.get(status)
    return CandidateState[name] if name else None


def _lead_score(lead: Mapping[str, Any]) -> int:
    """Mirror of orbisprobe/leads/scoring.py:compute_lead_score (verified equal
    against the real implementation on the committed fixture)."""
    return (
        lead["control_score"] * 3
        + lead["sink_score"] * 4
        + lead["gap_score"] * 4
        + lead["evidence_value"] * 2
        - EDGE_PENALTY[lead["edge_distance"]]
        - COST_PENALTY[lead["closure_cost"]]
    )


def _is_active(lead: Mapping[str, Any]) -> bool:
    """Mirror of orbisprobe/leads/scoring.py:is_active (recomputed score)."""
    return (
        _activation_status(lead) in ACTIVE_LEAD_STATUSES
        and lead["edge_distance"] != "ARTIFACT_BLOCKED"
        and lead["closure_cost"] != "COST-BLOCKED"
    )


def _activation_status(lead: Mapping[str, Any]) -> str:
    """Mirror of orbisprobe/leads/scoring.py:activation_status (same policy,
    computed score — not the possibly stale stored value)."""
    terminal = {"VULNERABILITY_CANDIDATE", "SAFE_INVARIANT", "DOWNGRADED", "ARTIFACT_BLOCKED", "DISPROVED"}
    status = lead["status"]
    if status in terminal:
        return status
    if lead["edge_distance"] == "ARTIFACT_BLOCKED" or lead["closure_cost"] == "COST-BLOCKED":
        return "ARTIFACT_BLOCKED"
    if lead["edge_distance"] == "EDGE-3PLUS":
        return "PARKED"
    if lead["edge_distance"] == "EDGE-2":
        if _lead_score(lead) >= 35 and lead["closure_cost"] in {"COST-1", "COST-2", "COST-3"}:
            return "CLOSURE_PENDING"
        return "PARKED"
    if lead["edge_distance"] == "EDGE-1":
        return "CLOSURE_PENDING"
    return "PROOF_MODE"


# --- adapter ------------------------------------------------------------------


class OrbisProbeAdapter:
    """Read-only translator: OrbisProbe artifacts <-> PS4RF models."""

    def __init__(self, *, evidence_store: InMemoryEvidenceStore | None = None) -> None:
        self._leads: dict[str, dict[str, Any]] = {}
        self._artifacts: list[EvidenceArtifact] = []
        self._evidence_store = evidence_store if evidence_store is not None else InMemoryEvidenceStore()
        self._consumed_hashes: tuple[str, ...] = ()

    # -- properties --------------------------------------------------------

    @property
    def evidence_store(self) -> InMemoryEvidenceStore:
        return self._evidence_store

    @property
    def artifacts(self) -> tuple[EvidenceArtifact, ...]:
        """Artifacts read/written so far (path + sha256 provenance)."""
        return tuple(self._artifacts)

    @property
    def consumed_hashes(self) -> tuple[str, ...]:
        """Canonical evidence hashes stored by the last consume_evidence() call."""
        return self._consumed_hashes

    # -- discover ----------------------------------------------------------

    def discover(self, context: DiscoveryContext) -> list[CandidateRecord]:
        records: list[CandidateRecord] = []
        for path in context.store_paths:
            raw_path = Path(path)
            try:
                text = raw_path.read_text(encoding="utf-8")
                raw = json.loads(text)
            except (OSError, json.JSONDecodeError) as exc:
                raise AdapterRefusal("STORE_UNREADABLE", f"{raw_path}: {exc}") from exc
            sha = _sha256_file(raw_path)
            self._artifacts.append(EvidenceArtifact(path=str(raw_path), sha256=sha))
            leads = self._leads_from_store(raw, raw_path)
            for item in leads:
                lead = self._parse_lead(item, raw_path)
                self._leads[lead["lead_id"]] = lead
                records.append(self._record_for(lead))
        return records

    def _leads_from_store(self, raw: Any, path: Path) -> list[Any]:
        if isinstance(raw, list):
            return raw
        if isinstance(raw, dict):
            schema = raw.get("schema")
            if schema is not None and schema != STORE_SCHEMA:
                raise AdapterRefusal("UNKNOWN_SCHEMA", f"{path}: {schema}")
            leads = raw.get("leads")
            if not isinstance(leads, list):
                raise AdapterRefusal("STORE_MALFORMED", f"{path}: 'leads' missing or not a list")
            return leads
        raise AdapterRefusal("STORE_MALFORMED", f"{path}: not an object or array")

    def _parse_lead(self, item: Any, path: Path) -> dict[str, Any]:
        if not isinstance(item, dict):
            raise AdapterRefusal("LEAD_MALFORMED", f"{path}: lead entry is not an object")
        missing = [key for key in _LEAD_REQUIRED if key not in item]
        if missing:
            raise AdapterRefusal("LEAD_MISSING_FIELDS", f"{path}: {', '.join(missing)}")
        status = item["status"]
        if status not in LEAD_STATUS_TO_STATE:
            raise AdapterRefusal("UNKNOWN_LEAD_STATUS", f"{path}: {status}")
        edge = item["edge_distance"]
        if edge not in EDGE_ORDER:
            raise AdapterRefusal("UNKNOWN_EDGE_DISTANCE", f"{path}: {edge}")
        cost = item["closure_cost"]
        if cost not in COST_PENALTY:
            raise AdapterRefusal("UNKNOWN_CLOSURE_COST", f"{path}: {cost}")
        unknown = item["unknown_edges"]
        if not isinstance(unknown, list) or any(not isinstance(x, str) for x in unknown):
            raise AdapterRefusal("LEAD_MALFORMED", f"{path}: unknown_edges")
        if edge != "ARTIFACT_BLOCKED":
            count = len(unknown)
            ok = {
                "EDGE-0": count == 0,
                "EDGE-1": count == 1,
                "EDGE-2": count == 2,
                "EDGE-3PLUS": count >= 3,
            }[edge]
            if not ok:
                raise AdapterRefusal("EDGE_COUNT_MISMATCH", f"{path}: {edge} vs {count} unknown edges")
        for key in ("control_score", "sink_score", "gap_score", "evidence_value"):
            value = item[key]
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 5:
                raise AdapterRefusal("LEAD_SCORE_RANGE", f"{path}: {key}={value!r}")
        if not isinstance(item["lead_score"], (int, float)) or isinstance(item["lead_score"], bool):
            raise AdapterRefusal("LEAD_MALFORMED", f"{path}: lead_score")
        lead = {key: item[key] for key in _LEAD_REQUIRED}
        # compact tuples for downstream use
        lead["unknown_edges"] = tuple(unknown)
        lead["evidence"] = tuple(item["evidence"]) if isinstance(item["evidence"], list) else ()
        return lead

    def _record_for(self, lead: Mapping[str, Any]) -> CandidateRecord:
        state = _state_for_lead_status(lead["status"])
        if state is None:  # unreachable: _parse_lead refused unknown statuses
            raise AdapterRefusal("UNKNOWN_LEAD_STATUS", str(lead["status"]))
        note = ""
        if state is CandidateState.EXPLOIT_CANDIDATE:
            # No reproducer artifact is available in discover(); downgrade per
            # mapping doc §3.2 (escalation requires a hash-bound reproducer).
            state = CandidateState.ANOMALY
            note = ":vulnerability_candidate_no_reproducer"
        else:
            note = {
                "SAFE_INVARIANT": ":safe_invariant",
                "DISPROVED": ":disproved",
                "DOWNGRADED": ":downgraded",
                "PARKED": ":parked",
                "ARTIFACT_BLOCKED": ":artifact_blocked",
            }.get(lead["status"], "")
        actor = f"orbisprobe:{lead['lead_id']}{note}"
        return CandidateRecord(
            id=lead["lead_id"],
            surface_id=f"orbisprobe:{lead['root']}",
            source=CandidateSource.ORBISPROBE,
            state=state,
            history=[Transition(state=state, at=_now(), actor=actor)],
        )

    # -- rank --------------------------------------------------------------

    def rank(self, candidates: Sequence[CandidateRecord]) -> RankedCandidates:
        scored: list[tuple[int, int, int, str, CandidateRecord]] = []
        for candidate in candidates:
            lead = self._leads.get(candidate.id)
            if lead is None:
                raise AdapterRefusal("UNKNOWN_CANDIDATE", candidate.id)
            if not _is_active(lead):
                continue
            scored.append(
                (-_lead_score(lead), EDGE_ORDER[lead["edge_distance"]], COST_PENALTY[lead["closure_cost"]], candidate.id, candidate)
            )
        scored.sort(key=lambda row: row[:4])
        entries: list[RankedEntry] = []
        for rank, (neg_score, _, _, candidate_id, record) in enumerate(scored, start=1):
            lead = self._leads[candidate_id]
            entries.append(
                RankedEntry(
                    candidate_id=candidate_id,
                    rank=rank,
                    score=-neg_score,
                    state=record.state.value,
                    edge_distance=lead["edge_distance"],
                    closure_cost=lead["closure_cost"],
                )
            )
        return RankedCandidates(entries=tuple(entries))

    # -- prove -------------------------------------------------------------

    def prove(self, candidate: CandidateRecord) -> ProofReport:
        lead = self._leads.get(candidate.id)
        if lead is None:
            raise AdapterRefusal("UNKNOWN_CANDIDATE", candidate.id)
        return ProofReport(
            candidate_id=candidate.id,
            lead_status=lead["status"],
            evidence=lead["evidence"],
            unknown_edges=lead["unknown_edges"],
            persistence_risk=lead["persistence_risk"],
        )

    # -- propose_experiment --------------------------------------------------

    def propose_experiment(self, candidate: CandidateRecord, context: SessionContext) -> ExperimentIR:
        lead = self._leads.get(candidate.id)
        if lead is None:
            raise AdapterRefusal("UNKNOWN_CANDIDATE", candidate.id)
        if not context.boot_id:
            raise AdapterRefusal("SESSION_CONTEXT_INCOMPLETE", "boot_id required")
        if lead["risk_class"] not in PROPOSAL_RISK_ALLOWLIST:
            raise AdapterRefusal(
                "NON_OFFLINE_PROPOSAL_REFUSED",
                f"risk_class={lead['risk_class']} (v0.1 allows {'/'.join(sorted(PROPOSAL_RISK_ALLOWLIST))})",
            )
        doc: dict[str, Any] = {
            "schema_version": 1,
            "name": f"orbisprobe-{lead['lead_id'].lower()}",
            "ir_encoding": "jcs-rfc8785",
            "timeouts": {"default_step_ms": 100, "global_ms": 5000},
            "budget": {
                "max_expanded_steps": 100,
                "max_parallel_tasks": 4,
                "max_runtime_budget_ms": 5000,
                "max_snapshot_bytes": 1048576,
                "max_rpc_bytes": 1048576,
            },
            "steps": [{"op": "CALL", "call": {"operation": "session.ping", "arguments": {}}}],
            "metadata": {
                "origin": "orbisprobe",
                "proposal": "v0.1-connectivity",
                "lead_id": lead["lead_id"],
                "candidate_id": candidate.id,
                "surface_id": candidate.surface_id,
            },
        }
        compiled = compile_experiment(doc)  # PS4RF gate: canonical bytes + budget check
        return ExperimentIR(ir=compiled, canonical_sha256=compiled["_canonical_sha256"])

    # -- consume_evidence ----------------------------------------------------

    def consume_evidence(self, run: RunRecord) -> None:
        hashes: list[str] = []
        for artifact in run.evidence:
            self._check_artifact(artifact)
            try:
                row = StoredEvidence(
                    evidence_ref=EvidenceRef(run_id=run.run_id, path=artifact.path, sha256=artifact.sha256),
                    run_id=run.run_id,
                    operation=run.operation,
                    outcome=VerificationOutcome(run.outcome),
                    capability=run.capability,
                    provider=run.provider,
                    provider_type=ProviderType(run.provider_type),
                    profile_sha256=run.profile_sha256,
                    context=TargetExecutionContext(run.context),
                    scope=Scope(run.scope),
                    session_id=run.session_id,
                    boot_id=run.boot_id,
                    expected=run.expected,
                    observed=run.observed,
                    canonical_sha256="0" * 64,
                )
            except (ValidationError, ValueError) as exc:
                raise AdapterRefusal("EVIDENCE_MODEL_INVALID", str(exc)) from exc
            stored = self._evidence_store.put(row)
            hashes.append(stored.canonical_sha256)
        self._consumed_hashes = tuple(hashes)

    def _check_artifact(self, artifact: EvidenceArtifact) -> None:
        try:
            _SHA_ADAPTER.validate_python(artifact.sha256)
        except ValidationError as exc:
            raise AdapterRefusal("ARTIFACT_HASH_FORMAT", artifact.path) from exc
        path = Path(artifact.path)
        if path.is_file():
            actual = _sha256_file(path)
            if actual != artifact.sha256:
                raise ArtifactHashMismatch(f"{artifact.path}: declared {artifact.sha256}, actual {actual}")

    # -- reclassify ----------------------------------------------------------

    def reclassify(self, candidate: CandidateRecord, evidence: EvidenceBundle) -> CandidateRecord:
        lead = self._leads.get(candidate.id)
        if lead is None:
            raise AdapterRefusal("UNKNOWN_CANDIDATE", candidate.id)
        if evidence.status == "EVIDENCE_CONFLICT":
            raise AdapterRefusal("REVIEW_REQUIRED", "EVIDENCE_CONFLICT never auto-transitions (mapping doc §3.2)")
        target = _state_for_bundle_status(evidence.status)
        if target is None:
            raise AdapterRefusal("UNKNOWN_STATUS", evidence.status)
        if target is CandidateState.EXPLOIT_CANDIDATE and evidence.reproducer is None:
            raise AdapterRefusal("REPRODUCER_REQUIRED", f"{candidate.id}: EXPLOIT_CANDIDATE needs a reproducer artifact")
        transition = Transition(state=target, at=_now(), actor=f"orbisprobe:{candidate.id}:{evidence.source}")
        return CandidateRecord(
            id=candidate.id,
            surface_id=candidate.surface_id,
            source=candidate.source,
            state=target,
            history=[*candidate.history, transition],
        )

    # -- minimize ------------------------------------------------------------

    def minimize(self, candidate: CandidateRecord, evidence: EvidenceBundle) -> Reproducer:
        if evidence.reproducer is None or evidence.plan_sha256 is None or evidence.run_id is None:
            raise AdapterRefusal(
                "REPRODUCER_INCOMPLETE", f"{candidate.id}: needs run_id + plan_sha256 + reproducer artifact"
            )
        try:
            _SHA_ADAPTER.validate_python(evidence.plan_sha256)
            _SHA_ADAPTER.validate_python(evidence.reproducer.sha256)
            _RUN_ID_ADAPTER.validate_python(evidence.run_id)
        except ValidationError as exc:
            raise AdapterRefusal("REPRODUCER_FORMAT", str(exc)) from exc
        return Reproducer(
            candidate_id=candidate.id,
            run_id=evidence.run_id,
            plan_sha256=evidence.plan_sha256,
            artifact_path=evidence.reproducer.path,
            artifact_sha256=evidence.reproducer.sha256,
        )
