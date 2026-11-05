#!/usr/bin/env python3
"""W12-A2 — NATIVE assurance consistency: the mandated regressions.

The owner's check: the persisted ``VerificationEvidence`` (provider ``ps4rfd-kread-privileged``,
provider_type ``NATIVE``) must not be able to *silently* produce ``PROVEN`` behind the F7 ceiling.
The reviewed mechanism is the documented exception (``tools/primitive_iface/schema.py`` F7:
"no kernel/gpuvm/keymgr/ccp/samu capability is grantable **from it alone**"): the runtime NATIVE
provider alone yields at most ``OBSERVED`` and defers; ``PROVEN`` exists only for the *separate*,
store-bound verification path, and the frozen W4 gate re-checks the minimum assurance per
namespace on its own.

These tests pin both halves, plus the four mandated refusals and the session boundary. Nothing
here talks to a console: the phases run through the synthetic session fixtures and a temporary
evidence store.
"""
from __future__ import annotations

import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.hostctl import kreadlive as KL                                # noqa: E402
from tools.hostctl import kreadstore as KS                               # noqa: E402
from tools.primitive_iface import gate as W4                             # noqa: E402
from tools.primitive_iface import schema as W3                           # noqa: E402
from tools.primitive_iface.gate import GateContext, gate_for             # noqa: E402
from tools.profiles import kread_capability as KC                        # noqa: E402
from tools.profiles import regions                                       # noqa: E402
from tools.profiles import w4_adapter                                    # noqa: E402
from tools.profiles.schema import profile_preconditions                  # noqa: E402

PROFILE, PROFILE_SHA = KL.synthetic_profile()
BINDING = KL.synthetic_boot_binding(PROFILE)
PINNED = KL.bootstrap_expectation(PROFILE)
APPROVAL = KL.SIM_APPROVAL
IDENTITY = KL.sim_provider()
OTHER_BOOT = 'BOOT-00000000000000ff'


# --- fixtures -------------------------------------------------------------------------------
def pinned_event(**over) -> dict:
    over.setdefault('runtime_kbase', KL.SIM_KBASE)
    return KL.synthetic_bounded_event(**over)


def do_phase_a(store, **over) -> dict:
    kwargs = dict(profile=PROFILE, boot_binding=BINDING, store=store,
                  provider=KL.sim_provider(live_approved=False),
                  verification_run_id=KL.SIM_VERIFICATION_RUN,
                  read_run_id=KL.SIM_BOOT_READ_RUN)
    kwargs.update(over)
    session = kwargs.pop('session', None) or KL.OfflineSession(session_id=KL.SIM_SESSION_A,
                                                              event=pinned_event())
    return KL.run_verification(session, **kwargs)


def do_phase_b(store, **over) -> dict:
    kwargs = dict(profile=PROFILE, boot_binding=BINDING, store=store,
                  verification_run_id=KL.SIM_VERIFICATION_RUN, provider=KL.sim_provider(),
                  approval=APPROVAL, generic_read_run_id=KL.SIM_GENERIC_RUN, expected=PINNED)
    kwargs.update(over)
    session = kwargs.pop('session', None) or KL.OfflineSession(session_id=KL.SIM_SESSION_B,
                                                              event=pinned_event())
    return KL.run_generic_read(session, **kwargs)


def seeded_store(tmp_path: pathlib.Path) -> KS.VerificationEvidenceStore:
    store = KS.VerificationEvidenceStore(tmp_path)
    result = do_phase_a(store)
    assert result['outcome'] == KL.OUTCOME_VERIFIED, result['problems']
    return store


def gate_binding() -> dict:
    verdict = profile_preconditions(PROFILE, boot_binding=BINDING,
                                    current_boot_id=BINDING.boot_id)
    return w4_adapter.profile_binding_for_gate('kernel.read', verdict)


def record_for(store, *, session_id: str, assurance: str = 'PROVEN',
               verification_over: dict | None = None, approval=APPROVAL,
               live_approved: bool = True) -> dict:
    """The record the driver derives, with a single field overridden for the regression."""
    evidence = store.load_verification(KL.SIM_VERIFICATION_RUN)
    record = KL.derive_capability_record(
        store, evidence_sha256=evidence['evidence_sha256'], read_run_id=KL.SIM_BOOT_READ_RUN,
        profile_sha256=PROFILE_SHA, boot_id=BINDING.boot_id,
        provider=KL.sim_provider(live_approved=live_approved), context=KL.CONTEXT,
        session_id=session_id, approval=approval, expected=PINNED)
    record['assurance'] = assurance
    if verification_over is not None:
        record['verification'].update(verification_over)
    return record


def chain(record: dict, *, session_id: str = KL.SIM_SESSION_B, live_approved: bool = True):
    """The W12 chain on one record, exactly as the driver walks it."""
    return KC.decide({'operation': 'kernel.read', 'region': 'image_elf', 'offset': 0,
                      'length': 16},
                     registry=regions, profile=PROFILE, boot_binding=BINDING,
                     context=KL.CONTEXT, capability=record, recovery=False,
                     provider=KL.sim_provider(live_approved=live_approved))


def w4(record: dict, *, session_id: str = KL.SIM_SESSION_B, approval=APPROVAL, boot_id=None):
    return gate_for('kernel.read', GateContext(
        capability_records=(record,), verification_records=(record['verification'],),
        evidence_refs=tuple(record['evidence_refs']), profile_binding=gate_binding(),
        session_id=session_id, boot_id=boot_id or BINDING.boot_id, session_state='ACTIVE',
        provider=KL.PROVIDER_NAME, provider_type='NATIVE', wired=True, approval=approval))


def refused(result: dict, reason: str) -> None:
    assert result['outcome'] == KL.OUTCOME_REFUSED, result['problems']
    assert result['ok'] is False
    assert result['provider_entries'] == 0 == result['generic_provider_entries']
    assert any(reason in str(problem) for problem in result['problems']), result['problems']


# ===========================================================================================
# 1. F7: the runtime provider alone can never produce PROVEN
# ===========================================================================================
def test_f7_native_alone_is_capped_at_observed_and_defers(tmp_path):
    """AVAILABLE + OBSERVED, no verification at all: kernel.read still refuses."""
    record = record_for(seeded_store(tmp_path), session_id=KL.SIM_SESSION_B, assurance='OBSERVED')
    del record['verification']
    decision = chain(record)
    assert decision.outcome == KC.DEFERRED, decision.reasons
    assert KC.KREAD_NATIVE_OBSERVED_ONLY in decision.reasons, decision.reasons
    assert decision.provider_entry is False
    assert decision.effective_grant['assurance'] == 'OBSERVED'


def test_f7_a_proven_claim_without_a_verification_is_not_honoured(tmp_path):
    """The claim alone never grants: the same record with assurance PROVEN and no evidence."""
    record = record_for(seeded_store(tmp_path), session_id=KL.SIM_SESSION_B, assurance='PROVEN')
    del record['verification']
    decision = chain(record)
    assert decision.outcome == KC.DEFERRED
    assert KC.KREAD_NATIVE_OBSERVED_ONLY in decision.reasons, decision.reasons
    assert decision.provider_entry is False


def test_f7_a_verification_without_the_separation_flag_is_refused(tmp_path):
    record = record_for(seeded_store(tmp_path), session_id=KL.SIM_SESSION_B,
                        verification_over={'separate_from_read': False})
    decision = chain(record)
    assert decision.outcome == KC.DEFERRED
    assert KC.KREAD_VERIFICATION_NOT_SEPARATE in decision.reasons, decision.reasons
    assert decision.provider_entry is False


def test_f7_a_verification_without_pass_is_refused(tmp_path):
    record = record_for(seeded_store(tmp_path), session_id=KL.SIM_SESSION_B,
                        verification_over={'outcome': 'FAIL'})
    decision = chain(record)
    assert decision.outcome == KC.DEFERRED
    assert KC.KREAD_VERIFICATION_MISSING in decision.reasons, decision.reasons
    assert decision.provider_entry is False


def test_f7_the_live_proposal_rule_caps_native_at_observed():
    """The F7 authority proposal in the frozen interface: NATIVE max_assurance OBSERVED."""
    assert W3.PROVIDER_RULE['provider_type'] == 'NATIVE'
    assert W3.PROVIDER_RULE['max_assurance'] == 'OBSERVED'
    assert W3.PROVIDER_RULE['min_assurance_for_grant']['privileged'] == 'PROVEN'
    assert 'from it alone' in W3.PROVIDER_RULE['min_assurance_for_grant']['consequence']


# ===========================================================================================
# 2. the W4 gate re-checks the assurance on its own (frozen minimum per namespace)
# ===========================================================================================
def test_w4_requires_proven_for_the_kernel_namespace():
    minimum = W4._frozen_authority().min_assurance_for_grant['kernel']
    assert getattr(minimum, 'value', minimum) == 'PROVEN'
    assert W4.REQ_BY_OP['kernel.read'].min_assurance == 'PROVEN'


def test_w4_rejects_an_observed_record_even_with_valid_evidence(tmp_path):
    record = record_for(seeded_store(tmp_path), session_id=KL.SIM_SESSION_B, assurance='OBSERVED')
    decision = w4(record)
    assert 'ASSURANCE_TOO_LOW' in decision.reasons, decision.reasons
    assert decision.decision == 'DEFERRED'


def test_w4_needs_the_hash_bound_evidence_reference_for_the_verification_run(tmp_path):
    """A PROVEN claim whose evidence reference does not match the verification run is refused."""
    record = record_for(seeded_store(tmp_path), session_id=KL.SIM_SESSION_B)
    record['evidence_refs'] = [{'run_id': 'VRUN-not-the-one', 'sha256': '00' * 32}]
    decision = w4(record)
    assert 'EVIDENCE_MISSING' in decision.reasons, decision.reasons


def test_w4_refuses_mock_derived_evidence(tmp_path):
    record = record_for(seeded_store(tmp_path), session_id=KL.SIM_SESSION_B,
                        verification_over={'provider_type': 'MOCK'})
    decision = w4(record)
    assert 'EVIDENCE_MISSING' in decision.reasons, decision.reasons


# ===========================================================================================
# 3. the four mandated refusals (forged evidence, profile, boot) -- zero provider entries
# ===========================================================================================
def test_forged_evidence_absent_from_the_store_is_refused(tmp_path):
    """NATIVE AVAILABLE + evidence that the store does not hold: nothing is granted."""
    store = seeded_store(tmp_path)
    forged = KS.VerificationEvidenceStore(tmp_path / 'forged')
    result = do_phase_b(forged, verification_run_id=KL.SIM_VERIFICATION_RUN)
    refused(result, KL.KREADLIVE_EVIDENCE_MISSING)
    assert store.verification_run_ids() == [KL.SIM_VERIFICATION_RUN]


def test_tampered_store_record_is_refused_on_the_rehash(tmp_path):
    """A post-hoc edit of the stored record: the load recomputes the hash and refuses."""
    store = seeded_store(tmp_path)
    path = next(store.root.rglob(f'{KL.SIM_VERIFICATION_RUN}.json'))
    body = json.loads(path.read_text())
    body['observed_sha256'] = 'de' * 32
    path.write_text(json.dumps(body, sort_keys=True))
    result = do_phase_b(store)
    refused(result, KL.KREADLIVE_EVIDENCE_REHASH_MISMATCH)


def test_wrong_profile_is_refused_before_any_provider_entry(tmp_path):
    """A foreign profile document: the chain refuses at W5, zero provider entries."""
    store = seeded_store(tmp_path)
    foreign = dict(PROFILE)
    foreign['target'] = dict(PROFILE['target'], firmware='13.00')
    result = do_phase_b(store, profile=foreign)
    refused(result, KL.KREADLIVE_WRONG_PROFILE)


def test_stale_boot_is_refused_before_any_provider_entry(tmp_path):
    """A boot binding from another boot: refused at W6, zero provider entries."""
    store = seeded_store(tmp_path)
    other = KL.synthetic_boot_binding(PROFILE)
    object.__setattr__(other, 'boot_id', OTHER_BOOT)
    result = do_phase_b(store, boot_binding=other)
    refused(result, KC.KREAD_STALE_BOOT_ID)


# ===========================================================================================
# 4. the intended transition, and the approval boundary after it
# ===========================================================================================
def test_valid_separate_evidence_reaches_the_intended_proven_transition(tmp_path):
    store = seeded_store(tmp_path)
    evidence = store.load_verification(KL.SIM_VERIFICATION_RUN)
    record = KL.derive_capability_record(
        store, evidence_sha256=evidence['evidence_sha256'], read_run_id=KL.SIM_BOOT_READ_RUN,
        profile_sha256=PROFILE_SHA, boot_id=BINDING.boot_id, provider=IDENTITY,
        context=KL.CONTEXT, session_id=KL.SIM_SESSION_B, approval=None, expected=PINNED)
    assert record['assurance'] == 'PROVEN'
    assert record['verification']['separate_from_read'] is True
    assert record['verification']['run_id'] == evidence['verification_run_id']
    assert record['evidence_refs'][0]['sha256'] == evidence['evidence_sha256']
    without = chain(record, live_approved=False)
    assert without.outcome == KC.DEFERRED
    assert without.reasons == ['APPROVAL_MISSING'], without.reasons
    assert without.provider_entry is False
    with_approval = chain(dict(record, approval=APPROVAL), live_approved=True)
    assert with_approval.outcome == KC.GRANTED, with_approval.reasons
    assert with_approval.provider_entry is True
    assert with_approval.stopped_at is None


def test_phase_b_without_the_live_approval_stops_before_the_provider(tmp_path):
    store = seeded_store(tmp_path)
    result = do_phase_b(store, approval=None)
    refused(result, KC.APPROVAL_MISSING)
    assert store.read_run_ids() == []


def test_phase_b_with_the_approval_reads_exactly_once(tmp_path):
    store = seeded_store(tmp_path)
    result = do_phase_b(store)
    assert result['outcome'] == KL.OUTCOME_READ, result['problems']
    assert result['provider_entries'] == 1 == result['generic_provider_entries']
    record = store.load_read_run(KL.SIM_GENERIC_RUN)
    assert record['provider_entries'] == 1


# ===========================================================================================
# 5. session B: a new session, nothing carried over from phase A
# ===========================================================================================
def test_session_b_record_is_new_and_nothing_is_carried_over(tmp_path):
    store = seeded_store(tmp_path)
    result = do_phase_b(store)
    capability = result['capability']
    evidence = store.load_verification(KL.SIM_VERIFICATION_RUN)
    read_run = store.load_read_run(KL.SIM_GENERIC_RUN)
    assert capability['session_id'] == KL.SIM_SESSION_B
    assert capability['session_id'] != evidence['verification_session_id']
    assert capability['boot_id'] == BINDING.boot_id == evidence['boot_id']
    assert capability['profile_sha256'] == PROFILE_SHA == evidence['profile_sha256']
    assert read_run['verification_run_id'] == KL.SIM_VERIFICATION_RUN
    assert read_run['read_run_id'] == KL.SIM_GENERIC_RUN
    assert read_run['verification_run_id'] != read_run['read_run_id']
    assert read_run['verification_session_id'] == KL.SIM_SESSION_A
    assert read_run['read_session_id'] == KL.SIM_SESSION_B
    # phase A's session id is refused in phase B, and the refused probe wrote nothing
    probe = do_phase_b(store, session=KL.OfflineSession(session_id=KL.SIM_SESSION_A,
                                                       event=pinned_event()),
                       generic_read_run_id='GENREAD-probe')
    refused(probe, KL.KREADLIVE_SESSION_REUSED)
    assert store.read_run_ids() == [KL.SIM_GENERIC_RUN]


def test_capability_record_carries_the_assurance_provenance(tmp_path):
    """The record the owner asked to see, field by field (W12 shape, hash-bound)."""
    store = seeded_store(tmp_path)
    evidence = store.load_verification(KL.SIM_VERIFICATION_RUN)
    record = KL.derive_capability_record(
        store, evidence_sha256=evidence['evidence_sha256'], read_run_id=KL.SIM_BOOT_READ_RUN,
        profile_sha256=PROFILE_SHA, boot_id=BINDING.boot_id, provider=IDENTITY,
        context=KL.CONTEXT, session_id=KL.SIM_SESSION_B, approval=APPROVAL, expected=PINNED)
    for field in ('name', 'availability', 'assurance', 'provider', 'provider_type', 'scope',
                  'session_id', 'boot_id', 'profile_sha256', 'verification', 'evidence_ref',
                  'evidence_refs', 'derived_from'):
        assert field in record, field
    assert record['name'] == 'kernel.read'
    assert record['availability'] == 'AVAILABLE'
    assert record['scope'] == 'SESSION'
    assert record['provider'] == KL.PROVIDER_NAME and record['provider_type'] == 'NATIVE'
    assert record['profile_sha256'] == PROFILE_SHA
    assert record['evidence_refs'][0] == {'run_id': evidence['verification_run_id'],
                                          'sha256': evidence['evidence_sha256']}
    assert record['derived_from']['verification_run_id'] == evidence['verification_run_id']
    assert record['derived_from']['evidence_sha256'] == evidence['evidence_sha256']
    assert record['verification']['run_id'] == evidence['verification_run_id']
    assert record['verification']['capability'] == 'kernel.read'
    assert record['verification']['outcome'] == 'PASS'
    assert record['verification']['boot_id'] == BINDING.boot_id
    assert record['verification']['separate_from_read'] is True
