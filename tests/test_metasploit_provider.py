"""Provider bridge + authority tests (P2, DoD v0.3 §12.7 items 4, 7 + §12.6).

Offline only: manifests from ``tools/metasploit/modules``, authority and
capability machinery from core. The DoD-7 cases pin the capability rule down:

* a record attributed to the ``metasploit:`` provider namespace is capped at
  OBSERVED -- even a forged PROVEN record gets clamped by the resolution engine;
* PROVEN appears only through a separate ``verify.*`` run whose record is
  attributed to a PS4RF-native provider (outside the msf namespace);
* ``verified_by.operation`` must live in the ``verify.`` namespace (K2).

Run from the repo root:

    .venv/bin/python -m pytest -q tests/test_metasploit_provider.py
"""

from __future__ import annotations

import copy

import pytest
from pydantic import ValidationError

from core.evidence.store import InMemoryEvidenceStore
from core.models.capability import (Assurance, Availability, CapabilityIntake,
                                    CapabilityRecord, Requirement, Scope, VerifiedBy,
                                    effective_grant, resolve)
from core.models.common import (EvidenceRef, ProviderType,
                                TargetExecutionContext)
from core.models.exploit import CapabilityGrant, ExploitManifest
from core.models.verification import (StoredEvidence, VerificationEvidence,
                                      VerificationOutcome, VerificationRejection,
                                      grant_from_verification)
from core.rpc.registry import default_registry
from tools.metasploit.provider import (HOST_CORE_OPERATIONS, MSF_PROVIDER_PATTERN,
                                       MsfModuleManifest, ReliabilityStats,
                                       host_core_registry, load_module_manifests,
                                       metasploit_authority_table,
                                       msf_provider_rule, observed_capability_record)

PROFILE_FW1352 = "a281c6971f04088091900c59a8053a146b598f5007d2e292c330dc4680c7532c"
EXPLOIT_NAME = "metasploit:exploit/ps4/browser/example"
SESSION = "SES-0000000000000001"
BOOT = "BOOT-TEST-1"
TRIGGER_RUN = "RUN-20261005T120000Z-BBBB0002"
VERIFY_RUN = "RUN-20261005T120000Z-AAAA0001"

VALID_MANIFEST = {
    "status": "PROVIDER",
    "name": EXPLOIT_NAME,
    "msf_ref": "exploit/ps4/browser/example",
    "kind": "exploit",
    "execution": {"prepare": "HOST", "trigger": "WEB_CONTENT",
                  "verify": "USERLAND_AGENT"},
    "provides": [{"capability": "userland.exec",
                  "verify_operation": "verify.userland.exec"}],
    "reliability": {"attempts": 1, "successes": 1, "clean_failures": 0,
                    "hangs": 0, "panics": 0, "reboots": 0},
    "reproducers": ["ps4rf://repro/exploit-ps4-browser-example/1"],
    "profile_bindings": [PROFILE_FW1352],
}


def _manifest(**overrides) -> MsfModuleManifest:
    data = copy.deepcopy(VALID_MANIFEST)
    data.update(overrides)
    return MsfModuleManifest.model_validate(data)


@pytest.fixture(scope="module")
def providers():
    return load_module_manifests()


# ---------------------------------------------------- DoD 4: manifests + bridge
def test_dod4_manifests_load_and_validate(providers):
    assert set(providers) == {
        "metasploit:exploit/ps4/browser/example",
        "metasploit:auxiliary/ps4/example_probe",
        "metasploit:post/ps4/example_status"}
    for provider in providers.values():
        assert provider.name == f"metasploit:{provider.manifest.msf_ref}"
        assert provider.to_exploit_manifest().name == provider.name


def test_browser_exploit_context_mapping(providers):
    execution = providers[EXPLOIT_NAME].manifest.execution
    assert execution.prepare is not None
    assert execution.prepare.value == "HOST"
    assert execution.trigger is not None and execution.trigger.value == "WEB_CONTENT"
    assert execution.verify is not None and execution.verify.value == "USERLAND_AGENT"


def test_browser_exploit_requires_verify_context():
    with pytest.raises(ValidationError):
        _manifest(execution={"prepare": "HOST", "trigger": "WEB_CONTENT"})


def test_auxiliary_carries_no_trigger_or_verify_context():
    with pytest.raises(ValidationError):
        _manifest(kind="auxiliary", msf_ref="auxiliary/ps4/example_probe",
                  name="metasploit:auxiliary/ps4/example_probe",
                  execution={"prepare": "HOST", "trigger": "WEB_CONTENT"})


def test_post_context_must_be_a_session_context():
    with pytest.raises(ValidationError):
        _manifest(kind="post", msf_ref="post/ps4/example_status",
                  name="metasploit:post/ps4/example_status",
                  execution={"prepare": "HOST"})
    valid = _manifest(kind="post", msf_ref="post/ps4/example_status",
                      name="metasploit:post/ps4/example_status",
                      execution={"prepare": "SYSTEM_SERVICE"})
    assert valid.execution.prepare.value == "SYSTEM_SERVICE"


def test_name_and_kind_consistency():
    with pytest.raises(ValidationError):
        _manifest(name="metasploit:exploit/ps4/browser/other")
    with pytest.raises(ValidationError):
        _manifest(kind="post")


@pytest.mark.parametrize("removed", ["reliability", "reproducers", "profile_bindings"])
def test_status_provider_requires_reliability_reproducers_profiles(removed):
    with pytest.raises(ValidationError):
        _manifest(**{removed: None if removed == "reliability" else []})


def test_planned_status_needs_no_provider_fields():
    manifest = _manifest(status="PLANNED", reliability=None, reproducers=[],
                         profile_bindings=[])
    assert manifest.status.value == "PLANNED"


def test_reliability_sum_invariant():
    ReliabilityStats(attempts=3, successes=2, clean_failures=1, hangs=0,
                     panics=0, reboots=0)
    with pytest.raises(ValidationError):
        ReliabilityStats(attempts=2, successes=3, clean_failures=0, hangs=0,
                         panics=0, reboots=0)


def test_privileged_capability_requires_verify_operation():
    with pytest.raises(ValidationError):
        _manifest(provides=[{"capability": "kernel.exec"}])


def test_dod4_bridge_exploit_manifest(providers):
    manifest = providers[EXPLOIT_NAME].to_exploit_manifest()
    assert isinstance(manifest, ExploitManifest)
    assert manifest.name == EXPLOIT_NAME
    assert manifest.provides[0].capability == "userland.exec"
    assert manifest.provides[0].verify_operation == "verify.userland.exec"
    assert manifest.profile_bindings == [PROFILE_FW1352]


# ------------------------------------------------- DoD 7: capability authority
def test_dod7_authority_rule_precedence():
    table = metasploit_authority_table()
    rule = table.rule_for("userland.exec", ProviderType.EXPLOIT,
                          "metasploit:exploit/ps4/browser/example")
    assert rule is not None
    assert rule.max_assurance is Assurance.OBSERVED
    assert rule.provider_pattern == MSF_PROVIDER_PATTERN
    assert table.rules[0].provider_pattern == MSF_PROVIDER_PATTERN
    generic = table.rule_for("userland.exec", ProviderType.EXPLOIT,
                             "ps4rf.verify.agent")
    assert generic is not None and generic.max_assurance is Assurance.PROVEN
    assert msf_provider_rule().max_assurance is Assurance.OBSERVED


def test_observed_helper_yields_observed_record():
    record = observed_capability_record(EXPLOIT_NAME, "userland.exec",
                                        context=TargetExecutionContext.JAILBROKEN_PROCESS,
                                        session_id=SESSION, boot_id=BOOT)
    assert record.assurance is Assurance.OBSERVED
    assert record.provider_type is ProviderType.EXPLOIT


def test_dod7_msf_record_cannot_claim_proven():
    """Authority violation attempt: a PROVEN record in the msf namespace."""
    table = metasploit_authority_table()
    intake = CapabilityIntake(SESSION, BOOT)
    forged = CapabilityRecord(
        name="userland.exec", availability=Availability.AVAILABLE,
        assurance=Assurance.PROVEN, context=TargetExecutionContext.JAILBROKEN_PROCESS,
        provider=EXPLOIT_NAME, provider_type=ProviderType.EXPLOIT,
        session_id=SESSION, boot_id=BOOT,
        evidence=EvidenceRef(run_id=VERIFY_RUN),
        verified_by=VerifiedBy(operation="verify.userland.exec",
                               expected="agent up", observed="agent up",
                               verification_run=VERIFY_RUN))
    ingested = intake.ingest(forged)
    resolution = resolve("userland.exec", Scope.SESSION,
                         TargetExecutionContext.JAILBROKEN_PROCESS,
                         [ingested], table, session_id=SESSION, boot_id=BOOT)
    assert resolution.assurance is Assurance.OBSERVED
    assert resolution.assurance_resolution.value == "OBSERVED"
    decision = effective_grant(
        Requirement(name="userland.exec", min_assurance=Assurance.PROVEN),
        resolution, TargetExecutionContext.JAILBROKEN_PROCESS,
        TargetExecutionContext.JAILBROKEN_PROCESS, table)
    assert decision.granted is False
    assert decision.reason == "ASSURANCE_INSUFFICIENT"


def _stored_and_verification(store: InMemoryEvidenceStore, provider_name: str):
    stored = store.put(StoredEvidence(
        evidence_ref=EvidenceRef(run_id=VERIFY_RUN), run_id=VERIFY_RUN,
        operation="verify.userland.exec", outcome=VerificationOutcome.PASS,
        capability="userland.exec", provider=provider_name,
        provider_type=ProviderType.EXPLOIT, profile_sha256=PROFILE_FW1352,
        context=TargetExecutionContext.JAILBROKEN_PROCESS, scope=Scope.SESSION,
        session_id=SESSION, boot_id=BOOT, expected="agent up", observed="agent up",
        canonical_sha256="0" * 64))
    verification = VerificationEvidence(
        verification_run_id=VERIFY_RUN, operation="verify.userland.exec",
        outcome=VerificationOutcome.PASS, capability="userland.exec",
        provider=provider_name, provider_type=ProviderType.EXPLOIT,
        profile_sha256=PROFILE_FW1352,
        context=TargetExecutionContext.JAILBROKEN_PROCESS, scope=Scope.SESSION,
        session_id=SESSION, boot_id=BOOT, expected="agent up", observed="agent up",
        evidence_sha256=stored.canonical_sha256)
    return verification


def test_dod7_msf_provider_verification_still_capped_at_observed(providers):
    """Even a passing verify.* run stays OBSERVED inside the msf namespace."""
    table = metasploit_authority_table()
    store = InMemoryEvidenceStore()
    manifest = providers[EXPLOIT_NAME].to_exploit_manifest()
    verification = _stored_and_verification(store, manifest.name)
    result = grant_from_verification(verification, "userland.exec", manifest,
                                     TRIGGER_RUN, table, default_registry(),
                                     store, CapabilityIntake(SESSION, BOOT))
    assert result.assurance is Assurance.OBSERVED
    assert result.verified_by is None


def test_dod7_proven_via_separate_native_verify_run():
    """PROVEN appears only for a PS4RF-native verification record."""
    table = metasploit_authority_table()
    store = InMemoryEvidenceStore()
    native = ExploitManifest(
        name="ps4rf.verify.agent",
        provides=[CapabilityGrant(capability="userland.exec",
                                  verify_operation="verify.userland.exec")],
        profile_bindings=[PROFILE_FW1352])
    verification = _stored_and_verification(store, "ps4rf.verify.agent")
    result = grant_from_verification(verification, "userland.exec", native,
                                     TRIGGER_RUN, table, default_registry(),
                                     store, CapabilityIntake(SESSION, BOOT))
    assert result.assurance is Assurance.PROVEN
    assert result.verified_by is not None


def test_dod7_verified_by_requires_verify_namespace():
    with pytest.raises(ValidationError):
        VerifiedBy(operation="module.execute", expected="x", observed="y",
                   verification_run=VERIFY_RUN)


def test_dod7_operation_must_match_the_grant(providers):
    table = metasploit_authority_table()
    store = InMemoryEvidenceStore()
    manifest = providers[EXPLOIT_NAME].to_exploit_manifest()
    verification = _stored_and_verification(store, manifest.name)
    mismatched = verification.model_copy(update={"operation": "verify.kernel.read"})
    with pytest.raises(VerificationRejection) as excinfo:
        grant_from_verification(mismatched, "userland.exec", manifest, TRIGGER_RUN,
                                table, default_registry(), store,
                                CapabilityIntake(SESSION, BOOT))
    assert excinfo.value.reason == "OPERATION_MISMATCH"


# ------------------------------------------------- DoD §12.6: host-core namespace
def test_section12_6_host_core_operations_registered():
    registry = host_core_registry()
    assert len(HOST_CORE_OPERATIONS) == 18
    for name in ("msf.health", "msf.session.command", "exploit.run",
                 "exploit.verify", "chain.plan", "agent.deploy"):
        assert registry.has(name)
    assert registry.spec("exploit.run").mutating is True
    assert registry.spec("msf.health").mutating is False


def test_host_core_operations_never_reach_the_target_registry():
    target = default_registry()
    for name in HOST_CORE_OPERATIONS:
        assert not target.has(name)          # §12.6: never sent to ps4rfd
    merged = host_core_registry(target)
    assert merged.has("session.ping")        # existing target ops untouched
