#!/usr/bin/env python3
"""W12 two-phase live driver: offline tests (phase A, phase B, boundaries, store, CLI).

Everything here runs without a console, a socket or a payload upload: the phases are driven
through the synthetic session fixtures of :mod:`tools.hostctl.kreadlive` (see
``OfflineSession``), and the run record is the real ``RunRecord``.

The four boundaries the accepted flow must not silently rebind are each pinned by a test:

* **session** -- the record run A's session would carry is refused in run B
  (``BINDING_MISMATCH`` at the W4 gate) and reusing run A's session id is refused outright
  (``KREADLIVE_SESSION_REUSED``); the evidence itself is accepted and the *new* session derives
  its own valid record (``ELIGIBLE``);
* **boot** -- a binding from another boot refuses with ``KREAD_STALE_BOOT_ID``, zero provider
  entries, before anything is sent;
* **profile** -- stored evidence that names another profile is invalid (``KREAD_WRONG_PROFILE``,
  zero provider entries), and a current profile that is not the real one is refused as well;
* **run separation** -- ``verification_run_id != read_run_id`` and
  ``verification_session_id != read_session_id``, checked before the trigger and visible in the
  persisted read-run record.

The pinned RUN B window (``image_elf`` offset 0) is asserted as a *refusal* by the frozen W5
``addr`` field domain (``u64 > 0`` against the unslid target address 0): the driver reports that
refusal and never bypasses it. The phase-B grant path (one provider entry, the byte/hash
comparison, the read-run record) is exercised on a nonzero-RVA STRICT region in the rehearsal
tests, which is the same code path with a different window.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.hostctl import cli                                            # noqa: E402
from tools.hostctl import kreadlive as KL                                # noqa: E402
from tools.hostctl import kreadstore as KS                               # noqa: E402
from tools.hostctl import kreadverify                                    # noqa: E402
from tools.hostctl.evidence import RunRecord                             # noqa: E402
from tools.primitive_iface.gate import GateContext, gate_for             # noqa: E402
from tools.profiles import w4_adapter                                     # noqa: E402
from tools.profiles.schema import profile_preconditions                   # noqa: E402

PROFILE, PROFILE_SHA = KL.synthetic_profile()
BINDING = KL.synthetic_boot_binding(PROFILE)
KBASE = KL.SIM_KBASE
APPROVAL = KL.SIM_APPROVAL
PINNED = KL.bootstrap_expectation(PROFILE)
PINNED_BYTES = '7f454c46020101090000000000000000'
PINNED_SHA = '7ef1ae261e75094d5eb5f2291a465e479dd62cfd7ae628fdd3ecefb38f90a092'
REHEARSAL_BYTES = '11' * 16


# --- fixtures ------------------------------------------------------------------------------
def pinned_event(**over) -> dict:
    over.setdefault('runtime_kbase', KBASE)
    return KL.synthetic_bounded_event(**over)


def pinned_session(**over) -> KL.OfflineSession:
    over.setdefault('session_id', KL.SIM_SESSION_A)
    over.setdefault('event', pinned_event())
    return KL.OfflineSession(**over)


def rehearsal_window() -> dict:
    # a NON-bootstrap window only passes the release gate with a release id (W13): the offline
    # rehearsal carries an offline one, exactly like a real read carries the owner's release id.
    KL._CONSUMED_RELEASES.pop(KL.SIM_REHEARSAL_RELEASE_ID, None)   # isolated offline episode
    return KL.window_for(KL.SIM_REHEARSAL_REGION, bytes_hex=REHEARSAL_BYTES,
                         release_id=KL.SIM_REHEARSAL_RELEASE_ID,
                         release_sha256=hashlib.sha256(
                             f'{KL.SIM_REHEARSAL_RELEASE_ID}|{REHEARSAL_BYTES}'.encode()
                         ).hexdigest(),
                         approval_sha256=hashlib.sha256(b'SIM-REHEARSAL-APPROVAL').hexdigest(),
                          profile=PROFILE)


def rehearse_store(tmp_path: pathlib.Path) -> KS.VerificationEvidenceStore:
    """A store holding the rehearsal record (phase A shape, nonzero-RVA window)."""
    store = KS.VerificationEvidenceStore(tmp_path / 'rehearsal')
    store.store_verification(KL.rehearsal_evidence(
        rehearsal_window(), verification_run_id=KL.SIM_REHEARSAL_VERIFICATION_RUN,
        read_run_id=KL.SIM_REHEARSAL_BOOT_READ_RUN,
        verification_session_id=KL.SIM_REHEARSAL_SESSION_A, profile_sha256=PROFILE_SHA,
        boot_id=BINDING.boot_id, provider=KL.sim_provider(live_approved=False)))
    return store


def do_phase_a(store, **over) -> dict:
    kwargs = dict(profile=PROFILE, boot_binding=BINDING, store=store,
                  provider=KL.sim_provider(live_approved=False),
                  verification_run_id=KL.SIM_VERIFICATION_RUN,
                  read_run_id=KL.SIM_BOOT_READ_RUN)
    kwargs.update(over)
    session = kwargs.pop('session', None) or pinned_session()
    return KL.run_verification(session, **kwargs)


def do_phase_b(store, **over) -> dict:
    kwargs = dict(profile=PROFILE, boot_binding=BINDING, store=store,
                  verification_run_id=KL.SIM_VERIFICATION_RUN, provider=KL.sim_provider(),
                  approval=APPROVAL, generic_read_run_id=KL.SIM_GENERIC_RUN, expected=PINNED)
    kwargs.update(over)
    session = kwargs.pop('session', None) or KL.OfflineSession(session_id=KL.SIM_SESSION_B,
                                                               event=pinned_event())
    return KL.run_generic_read(session, **kwargs)


def do_rehearsal_read(store, **over) -> dict:
    kwargs = dict(profile=PROFILE, boot_binding=BINDING, store=store,
                  verification_run_id=KL.SIM_REHEARSAL_VERIFICATION_RUN,
                  provider=KL.sim_provider(), approval=APPROVAL,
                  generic_read_run_id=KL.SIM_REHEARSAL_GENERIC_RUN,
                  expected=rehearsal_window(), evidence_window=rehearsal_window())
    kwargs.update(over)
    session = kwargs.pop('session', None) or KL.OfflineSession(
        session_id=KL.SIM_REHEARSAL_SESSION_B,
        event=KL.synthetic_bounded_event(region=KL.SIM_REHEARSAL_REGION,
                                         bytes_hex=REHEARSAL_BYTES, runtime_kbase=KBASE))
    return KL.run_generic_read(session, **kwargs)


def refused(result: dict, reason: str, *, entries: int = 0) -> None:
    assert result['outcome'] == KL.OUTCOME_REFUSED, result['problems']
    assert result['ok'] is False
    assert result['provider_entries'] == entries == result['generic_provider_entries']
    assert any(reason in str(problem) for problem in result['problems']), \
        f'{reason} not in {result["problems"]}'


# --- the frozen identities -----------------------------------------------------------------
def test_region_semantics_are_unchanged(tmp_path):
    """STRICT only, aperture_global stays STRUCTURAL_ONLY, boottime stays DEFERRED."""
    image_elf = KL.regions.get_region('image_elf')
    assert image_elf.identity_status == KL.regions.IDENTITY_STRICT
    assert (image_elf.rva, image_elf.length) == (0, 16)
    aperture = KL.regions.get_region('aperture_global')
    assert aperture.identity_status != KL.regions.IDENTITY_STRICT
    assert KL.regions.MAX_READ_LEN == 4096
    # the ceiling is the registry's, and it refuses an over-long read outright
    with pytest.raises(KL.regions.KReadReject):
        KL.regions.resolve_read('image_elf', 0, KL.regions.MAX_READ_LEN + 1)
    # a STRUCTURAL_ONLY region is refused by the window builder and by the verifier
    structural = pinned_event(region='aperture_global', bytes_hex='ab' * 8)
    assert KL.verify_bounded_event(structural, profile=PROFILE, expected=PINNED)['verified'] is False
    window = KL.window_for('aperture_global', bytes_hex='ab' * 8, length=8, profile=PROFILE)
    assert any(KL.KREADLIVE_STRICT_IDENTITY_REQUIRED in problem
               for problem in window['problems']), window['problems']
    # boottime is STRICT in the registry but has no promoted locator in this profile: DEFERRED
    boottime = KL.regions.get_region('boottime')
    assert boottime.identity_status == KL.regions.IDENTITY_STRICT
    assert boottime.locator not in PROFILE['locators']
    deferred = KL.window_for('boottime', bytes_hex='11' * 16, profile=PROFILE)
    assert any(KL.KREADLIVE_LOCATOR_NOT_PROMOTED in problem
               for problem in deferred['problems']), deferred['problems']
    # ... and phase B refuses such a window instead of reading it
    refused(do_rehearsal_read(
        rehearse_store(tmp_path), expected=deferred,
        session=KL.OfflineSession(
            session_id=KL.SIM_REHEARSAL_SESSION_B,
            event=KL.synthetic_bounded_event(region='boottime', bytes_hex='11' * 16,
                                             runtime_kbase=KBASE))),
        KL.KREADLIVE_BOOTSTRAP_EXPECTATION)
    # an unknown region is never a window
    unknown = KL.window_for('no_such_region', bytes_hex='11')
    assert any(KL.KREADLIVE_UNKNOWN_REGION in problem for problem in unknown['problems'])
    # the rehearsal region that *is* promoted keeps a clean window
    assert rehearsal_window()['problems'] == []



def test_the_pinned_window_is_the_frozen_bootstrap_window():
    """The driver pins exactly the registry/bootstrap window, and the profile agrees."""
    assert (KL.PINNED_REGION, KL.PINNED_OFFSET, KL.PINNED_LENGTH, KL.PINNED_RVA) == (
        kreadverify.BOOTSTRAP_REGION, kreadverify.BOOTSTRAP_OFFSET,
        kreadverify.BOOTSTRAP_LENGTH, kreadverify.BOOTSTRAP_RVA)
    assert (KL.PINNED_REGION, KL.PINNED_OFFSET, KL.PINNED_LENGTH) == ('image_elf', 0, 16)
    assert KL.PINNED_BYTES_HEX == PINNED_BYTES
    assert KL.PINNED_SHA256 == PINNED_SHA
    assert hashlib.sha256(bytes.fromhex(PINNED_BYTES)).hexdigest() == PINNED_SHA
    locator = PROFILE['locators'][KL.PINNED_LOCATOR]
    assert locator['expected_bytes']['hex'] == PINNED_BYTES
    assert locator['expected_bytes']['offset'] == 0
    assert PROFILE_SHA == '51b59db31ee47a9e2c5450ddfad002a80a407bf727f9ac5ae19558b82c3a4819'
    assert PINNED['problems'] == []


# ===========================================================================================
# PHASE A
# ===========================================================================================
def test_phase_a_verifies_the_pinned_bytes_and_persists_the_evidence(tmp_path):
    store = KS.VerificationEvidenceStore(tmp_path)
    result = do_phase_a(store)
    assert result['outcome'] == KL.OUTCOME_VERIFIED and result['ok'] is True
    assert result['problems'] == []
    assert result['provider_entries'] == 0 and result['generic_provider_entries'] == 0
    evidence = result['evidence']
    assert evidence['region'] == 'image_elf' and evidence['offset'] == 0
    assert evidence['length'] == 16
    assert evidence['expected_bytes_hex'] == PINNED_BYTES
    assert evidence['observed_bytes_hex'] == PINNED_BYTES
    assert evidence['expected_sha256'] == PINNED_SHA == evidence['observed_sha256']
    assert evidence['outcome'] == 'PASS' and evidence['capability'] == 'kernel.read'
    assert evidence['operation'] == kreadverify.VERIFICATION_OPERATION
    assert evidence['provider_entries'] == 0
    # persisted, hashed, and rehashable on load
    path = pathlib.Path(result['evidence_path'])
    assert path.exists() and path.parent.name == 'verification'
    loaded = store.load_verification(KL.SIM_VERIFICATION_RUN)
    assert loaded == evidence
    assert evidence['evidence_sha256'] == KS.canonical_evidence_sha256(evidence)
    # the read run/session ids of the bootstrap read are part of the record
    assert evidence['verification_run_id'] == KL.SIM_VERIFICATION_RUN
    assert evidence['read_run_id'] == KL.SIM_BOOT_READ_RUN
    assert evidence['verification_session_id'] == evidence['read_session_id'] == KL.SIM_SESSION_A
    assert evidence['run_separation']['run_separated'] is True


def test_phase_a_host_verification_covers_the_event_and_the_addresses(tmp_path):
    """The phase-A report is the independent host verification of the captured event."""
    result = do_phase_a(KS.VerificationEvidenceStore(tmp_path))
    report = result['event_report']
    assert report['verified'] is True and report['checks_failed'] == []
    assert report['region'] == 'image_elf' and report['offset'] == 0 and report['length'] == 16
    assert report['returned_length'] == 16
    assert report['bytes_hex'] == PINNED_BYTES and report['output_sha256'] == PINNED_SHA
    assert report['region_rva'] == 0 and report['resolved_rva'] == 0
    assert report['kbase'] == KBASE
    assert report['resolved_runtime_va'] == KBASE
    assert report['callback_executed'] is True and report['kexec_rc'] == 0
    assert report['cb_status'] == 0 and report['cb_status_name'] == 'OK'
    assert report['max_read_len'] == KL.regions.MAX_READ_LEN
    # the payload reports the *compiled* table, never the policy registry total (W12-A-D1)
    assert report['region_count'] == len(KL.regions.compiled_regions())
    # ... and it was verified twice by the W12 verifier, before anything was persisted
    reports = result['verification_reports']
    assert reports['bootstrap']['verified'] is True
    assert reports['bootstrap']['verification_path'] == 'BOOTSTRAP'
    assert reports['generic']['verified'] is True
    assert reports['generic']['requirement_after'] == kreadverify.REQUIREMENT_ELIGIBLE


def test_phase_a_needs_no_already_proven_capability(tmp_path):
    """No capability circle: phase A never consults the chain and never enters the provider."""
    store = KS.VerificationEvidenceStore(tmp_path)
    assert store.verification_run_ids() == []
    result = do_phase_a(store)
    assert result['ok'] is True
    assert result['capability'] is None and result['decision'] is None
    assert result['provider_entries'] == 0
    assert any('no capability chain' in note and 'no generic provider entry' in note
               for note in result['notes']), result['notes']


def test_phase_a_refuses_bytes_that_are_not_the_pinned_bytes(tmp_path):
    store = KS.VerificationEvidenceStore(tmp_path)
    wrong = '00' * 16
    result = do_phase_a(store, session=pinned_session(event=pinned_event(bytes_hex=wrong)))
    refused(result, KL.KREADLIVE_BYTES_MISMATCH)
    assert store.verification_run_ids() == []      # nothing is persisted on a refusal


def test_phase_a_refuses_a_missing_event_and_a_failed_read(tmp_path):
    store = KS.VerificationEvidenceStore(tmp_path)
    refused(do_phase_a(store, session=pinned_session(event=None)),
            KL.KREADLIVE_EVENT_MISSING)
    failed = pinned_event(callback_executed=False, cb_status=7, kexec_rc=1, status='FAILED')
    refused(do_phase_a(store, session=pinned_session(event=failed)),
            KL.KREADLIVE_EVENT_NOT_EXECUTED)
    assert store.verification_run_ids() == []


def test_phase_a_refuses_a_non_strict_region(tmp_path):
    """Region semantics are unchanged: a STRUCTURAL_ONLY region is never read."""
    store = KS.VerificationEvidenceStore(tmp_path)
    structural = KL.synthetic_bounded_event(region='aperture_global', bytes_hex='ab' * 16,
                                            runtime_kbase=KBASE)
    refused(do_phase_a(store, session=pinned_session(event=structural)),
            KL.KREADLIVE_STRICT_IDENTITY_REQUIRED)


def test_phase_a_refuses_without_the_current_boot_binding(tmp_path):
    store = KS.VerificationEvidenceStore(tmp_path)
    refused(do_phase_a(store, boot_binding=None), KL.KREADLIVE_EVIDENCE_INVALID)
    assert store.verification_run_ids() == []


def test_phase_a_refuses_a_fixture_profile(tmp_path):
    store = KS.VerificationEvidenceStore(tmp_path)
    refused(do_phase_a(store, profile=dict(PROFILE, fixture=True)), KL.KREADLIVE_WRONG_PROFILE)
    assert store.verification_run_ids() == []


# ===========================================================================================
# the evidence store: rehash on load, bare flag, id hygiene
# ===========================================================================================
def test_evidence_rehash_on_load_detects_a_post_hoc_edit(tmp_path):
    store = KS.VerificationEvidenceStore(tmp_path)
    result = do_phase_a(store)
    path = pathlib.Path(result['evidence_path'])
    edited = json.loads(path.read_text())
    edited['observed_bytes_hex'] = '00' * 16          # the stored hash no longer matches
    path.write_text(json.dumps(edited, indent=1, sort_keys=True) + '\n')
    with pytest.raises(KS.StoreError) as excinfo:
        store.load_verification(KL.SIM_VERIFICATION_RUN)
    assert excinfo.value.reason == KS.STORE_REHASH_MISMATCH
    # and the live driver refuses it too, before any provider entry
    refused(do_phase_b(store), KL.KREADLIVE_EVIDENCE_REHASH_MISMATCH)


def test_bare_verified_flag_is_never_sufficient(tmp_path):
    store = KS.VerificationEvidenceStore(tmp_path)
    bare_path = store.verification_path('RUN-bare-flag')
    bare_path.parent.mkdir(parents=True, exist_ok=True)
    bare_path.write_text(json.dumps({'verified': True, 'outcome': 'PASS'}) + '\n')
    with pytest.raises(KS.StoreError) as excinfo:
        store.load_verification('RUN-bare-flag')
    assert excinfo.value.reason == KS.STORE_BARE_FLAG
    with pytest.raises(KS.StoreError) as excinfo:
        store.store_verification({'verified': True, 'outcome': 'PASS'})
    assert excinfo.value.reason == KS.STORE_BARE_FLAG
    # the driver refuses the bare flag as a record, with zero provider entries
    refused(do_phase_b(store, verification_run_id='RUN-bare-flag'),
            KL.KREADLIVE_EVIDENCE_BARE_FLAG)


def test_the_store_refuses_a_record_that_was_written_with_the_wrong_hash(tmp_path):
    store = KS.VerificationEvidenceStore(tmp_path)
    result = do_phase_a(store)
    evidence = dict(result['evidence'])
    evidence['boot_id'] = 'BOOT-' + 'f' * 16          # content changed, hash not recomputed
    with pytest.raises(KS.StoreError) as excinfo:
        store.store_verification(evidence)
    assert excinfo.value.reason == KS.STORE_REHASH_MISMATCH


def test_the_store_refuses_traversal_run_ids(tmp_path):
    store = KS.VerificationEvidenceStore(tmp_path)
    with pytest.raises(KS.StoreError) as excinfo:
        store.load_verification('../../etc/passwd')
    assert excinfo.value.reason == KS.STORE_ID_INVALID


def test_a_missing_record_is_refused_by_name(tmp_path):
    store = KS.VerificationEvidenceStore(tmp_path)
    refused(do_phase_b(store, verification_run_id='VRUN-not-there'),
            KL.KREADLIVE_EVIDENCE_MISSING)


# ===========================================================================================
# PHASE B: the session boundary
# ===========================================================================================
def test_session_boundary_record_a_is_rejected_in_session_b_and_the_evidence_is_accepted(
        tmp_path):
    """The contract's session boundary, both halves, on one stored record."""
    store = KS.VerificationEvidenceStore(tmp_path)
    result_a = do_phase_a(store)
    evidence = result_a['evidence']

    verdict = profile_preconditions(PROFILE, boot_binding=BINDING,
                                   current_boot_id=BINDING.boot_id)
    binding = w4_adapter.profile_binding_for_gate('kernel.read', verdict)

    def gate(record: dict, session_id: str):
        """The W4 gate as the driver walks it, on one capability record."""
        return gate_for('kernel.read', GateContext(
            capability_records=(record,),
            verification_records=(record['verification'],),
            evidence_refs=tuple(record['evidence_refs']),
            profile_binding=binding, session_id=session_id, boot_id=BINDING.boot_id,
            session_state='ACTIVE', provider=KL.PROVIDER_NAME, provider_type='NATIVE',
            wired=True, approval=APPROVAL))

    # (a) W12-A3: the derivation refuses to mint a record for the session the verification ran in,
    #     so a "carried over" record cannot even be constructed any more
    with pytest.raises(KL.DerivationRejected) as excinfo:
        KL.derive_capability_record(
            store, evidence_sha256=evidence['evidence_sha256'], read_run_id=KL.SIM_BOOT_READ_RUN,
            profile_sha256=PROFILE_SHA, boot_id=BINDING.boot_id,
            provider=KL.sim_provider(), context=KL.CONTEXT, session_id=KL.SIM_SESSION_A,
            approval=APPROVAL, expected=PINNED)
    assert excinfo.value.reason == KL.KREADLIVE_SESSION_REUSED, excinfo.value

    #     a session-bound record that is presented in the *other* session is still refused by the
    #     W4 gate itself (the gate's own binding check, on a record whose session id was moved)
    derived_for_b = KL.derive_capability_record(
        store, evidence_sha256=evidence['evidence_sha256'], read_run_id=KL.SIM_BOOT_READ_RUN,
        profile_sha256=PROFILE_SHA, boot_id=BINDING.boot_id,
        provider=KL.sim_provider(), context=KL.CONTEXT, session_id=KL.SIM_SESSION_B,
        approval=APPROVAL, expected=PINNED)
    assert gate(derived_for_b, KL.SIM_SESSION_B).decision == 'ELIGIBLE'
    record_for_a = dict(derived_for_b, session_id=KL.SIM_SESSION_A,
                        verification=dict(derived_for_b['verification'],
                                          session_id=KL.SIM_SESSION_A))
    assert gate(record_for_a, KL.SIM_SESSION_A).decision == 'ELIGIBLE'
    carried_over = gate(record_for_a, KL.SIM_SESSION_B)
    assert 'BINDING_MISMATCH' in carried_over.reasons, carried_over.reasons
    assert carried_over.decision != 'ELIGIBLE'

    # (b) the stored evidence is accepted as it is: rehashed on load, valid for the new session
    loaded = store.load_verification(KL.SIM_VERIFICATION_RUN)
    assert loaded['evidence_sha256'] == KS.canonical_evidence_sha256(loaded)
    assert loaded == evidence

    # (c) reusing run A's session id in run B is refused outright, before anything is sent
    reused = do_phase_b(store, session=KL.OfflineSession(session_id=KL.SIM_SESSION_A,
                                                         event=pinned_event()))
    refused(reused, KL.KREADLIVE_SESSION_REUSED)
    assert reused['event'] is None and reused['read_run_record'] is None

    # (d) the new session, from the same stored evidence, derives its own valid record
    fresh = do_phase_b(store)
    assert fresh['capability']['session_id'] == KL.SIM_SESSION_B
    assert fresh['capability']['session_id'] != evidence['verification_session_id']
    assert fresh['capability']['evidence_refs'] == [
        {'run_id': KL.SIM_VERIFICATION_RUN, 'sha256': evidence['evidence_sha256']}]
    assert gate(fresh['capability'], KL.SIM_SESSION_B).decision == 'ELIGIBLE'
    assert 'BINDING_MISMATCH' in gate(fresh['capability'], KL.SIM_SESSION_A).reasons


# ===========================================================================================
# PHASE B: the boot and profile boundaries
# ===========================================================================================
def test_boot_boundary_a_different_boot_refuses_before_any_provider_entry(tmp_path):
    store = KS.VerificationEvidenceStore(tmp_path)
    do_phase_a(store)
    other_boot = KL.synthetic_boot_binding(PROFILE, boot_time={'sec': 1789910256 + 3600,
                                                               'usec': 1})
    assert other_boot.boot_id != BINDING.boot_id
    result = do_phase_b(store, boot_binding=other_boot)
    refused(result, 'KREAD_STALE_BOOT_ID')
    assert result['decision'] is None and result['capability'] is None
    assert any('fresh verification run is required' in str(problem)
               for problem in result['problems'])
    assert store.read_run_ids() == []


def test_boot_boundary_without_a_binding_also_refuses(tmp_path):
    store = KS.VerificationEvidenceStore(tmp_path)
    do_phase_a(store)
    refused(do_phase_b(store, boot_binding=None), 'KREAD_STALE_BOOT_ID')


def test_profile_boundary_stored_evidence_for_another_profile_is_invalid(tmp_path):
    store = KS.VerificationEvidenceStore(tmp_path)
    foreign = KL.rehearsal_evidence(
        PINNED, verification_run_id=KL.SIM_VERIFICATION_RUN,
        read_run_id=KL.SIM_BOOT_READ_RUN, verification_session_id=KL.SIM_SESSION_A,
        profile_sha256='f' * 64, boot_id=BINDING.boot_id,
        provider=KL.sim_provider(live_approved=False))
    store.store_verification(foreign)
    result = do_phase_b(store)
    refused(result, 'KREAD_WRONG_PROFILE')
    assert result['decision'] is None and store.read_run_ids() == []


def test_profile_boundary_a_current_profile_that_is_not_the_real_one_is_refused(tmp_path):
    store = KS.VerificationEvidenceStore(tmp_path)
    do_phase_a(store)
    refused(do_phase_b(store, profile=dict(PROFILE, fixture=True)),
            KL.KREADLIVE_WRONG_PROFILE)
    refused(do_phase_b(store, profile=dict(PROFILE, notes='edited after the freeze')),
            KL.KREADLIVE_WRONG_PROFILE)
    assert store.read_run_ids() == []


# ===========================================================================================
# PHASE B: run separation (both id kinds) and the provider-entry count
# ===========================================================================================
def test_run_separation_run_ids_must_differ(tmp_path):
    store = rehearse_store(tmp_path)
    result = do_rehearsal_read(store, generic_read_run_id=KL.SIM_REHEARSAL_VERIFICATION_RUN)
    refused(result, KL.KREADLIVE_RUN_NOT_SEPARATE)
    assert result['event'] is None and store.read_run_ids() == []


def test_run_separation_session_ids_must_differ(tmp_path):
    store = rehearse_store(tmp_path)
    reused = do_rehearsal_read(store, session=KL.OfflineSession(
        session_id=KL.SIM_REHEARSAL_SESSION_A,
        event=KL.synthetic_bounded_event(region=KL.SIM_REHEARSAL_REGION,
                                         bytes_hex=REHEARSAL_BYTES, runtime_kbase=KBASE)))
    refused(reused, KL.KREADLIVE_SESSION_REUSED)
    assert store.read_run_ids() == []


def test_the_generic_read_grants_once_and_persists_both_separation_proofs(tmp_path):
    """The rehearsal window (rva > 0) exercises the whole grant -> read -> verify path."""
    store = rehearse_store(tmp_path)
    result = do_rehearsal_read(store)
    assert result['outcome'] == KL.OUTCOME_READ and result['ok'] is True, result['problems']
    assert result['provider_entries'] == 1 == result['generic_provider_entries']
    decision = result['decision']
    assert decision['outcome'] == 'GRANTED' and decision['provider_entry'] is True
    assert decision['reasons'] == [] and decision['stopped_at'] is None
    # exactly one provider entry, recorded as such in the run result and in the record
    record = store.load_read_run(KL.SIM_REHEARSAL_GENERIC_RUN)
    assert record['provider_entries'] == 1
    assert record['record_sha256'] == KS.canonical_record_sha256(record)
    # run separation: both id kinds, distinct and visible in the persisted evidence
    separation = result['run_separation']
    assert separation['run_ids_distinct'] is True
    assert separation['session_ids_distinct'] is True
    assert separation['separated'] is True
    assert separation['verification_run_id'] == KL.SIM_REHEARSAL_VERIFICATION_RUN
    assert separation['generic_read_run_id'] == KL.SIM_REHEARSAL_GENERIC_RUN
    assert separation['verification_session_id'] == KL.SIM_REHEARSAL_SESSION_A
    assert separation['read_session_id'] == KL.SIM_REHEARSAL_SESSION_B
    assert record['verification_run_id'] != record['read_run_id']
    assert record['verification_session_id'] != record['read_session_id']
    assert record['verification_evidence_sha256'] == result['evidence_sha256']
    # the W12 verifier agrees that the verification came from a separate run
    assert result['verification_reports']['generic']['run_separate'] is True
    # and the bytes of the read were verified against the window
    assert result['event_report']['bytes_hex'] == REHEARSAL_BYTES
    assert result['event_report']['output_sha256'] == \
        hashlib.sha256(bytes.fromhex(REHEARSAL_BYTES)).hexdigest()


def test_provider_entry_counts_for_both_phases(tmp_path):
    """RUN A: zero generic entries. RUN B (grant path): exactly one."""
    store = rehearse_store(tmp_path)
    assert do_rehearsal_read(store)['generic_provider_entries'] == 1
    pinned_store = KS.VerificationEvidenceStore(tmp_path / 'pinned')
    phase_a = do_phase_a(pinned_store)
    assert phase_a['generic_provider_entries'] == 0
    assert phase_a['evidence']['provider_entries'] == 0
    assert not [check for check in phase_a['checks']
                if check['name'] == 'no_generic_provider_entry_in_phase_a' and not check['ok']]


def test_phase_b_does_not_enter_the_provider_without_the_live_approval(tmp_path):
    store = rehearse_store(tmp_path)
    result = do_rehearsal_read(store, provider=KL.sim_provider(live_approved=False))
    refused(result, 'KREAD_LIVE_APPROVAL_REQUIRED')
    assert result['decision']['stopped_at'] == 'provider_router'
    assert store.read_run_ids() == []


def test_phase_b_does_not_enter_the_provider_and_does_not_read_a_deferred_chain(tmp_path):
    """A DEFERRED chain that reaches the prompt for live approval still sent nothing."""
    store = rehearse_store(tmp_path)
    result = do_rehearsal_read(store, approval=None,
                               provider=KL.sim_provider(live_approved=True))
    refused(result, 'APPROVAL_MISSING')
    assert result['decision']['stopped_at'] == 'w4_gate'
    assert result['event'] is None and store.read_run_ids() == []


def test_phase_b_refuses_under_recovery(tmp_path):
    store = rehearse_store(tmp_path)
    result = do_rehearsal_read(store, recovery=True)
    refused(result, 'KREAD_RECOVERY_REQUIRED')
    assert result['event'] is None and store.read_run_ids() == []


def test_the_pinned_rva0_window_binds_and_takes_exactly_one_provider_entry(tmp_path):
    """W12-RVA0-BINDING: the accepted RUN B window is the *relative* rva-0 locator.

    ``image_elf`` sits at the image base, so the pinned window's locator value is 0. The W5
    binding validates the locator (relative kind: ``0 <= rva < 2**64``, zero valid), and the
    runtime address is resolved later from the current boot's kernel base with checked
    arithmetic (non-zero, canonical, inside the pinned image window) - so the accepted window
    walks the whole chain: GRANTED, exactly one provider entry, the pinned bytes back and the
    read-run record written.
    """
    store = KS.VerificationEvidenceStore(tmp_path)
    phase_a = do_phase_a(store)
    assert phase_a['ok'] is True
    result = do_phase_b(store)
    assert result['ok'] is True, result['problems']
    assert result['outcome'] == KL.OUTCOME_READ
    assert result['provider_entries'] == result['generic_provider_entries'] == 1
    assert result['decision']['outcome'] == 'GRANTED'
    assert result['decision']['stopped_at'] is None
    assert result['capability']['session_id'] == KL.SIM_SESSION_B   # derived for this session
    assert result['event'] is not None and result['read_run_record'] is not None
    assert result['event_report']['bytes_hex'] == PINNED_BYTES
    # the runtime address is the boot's kernel base plus the relative window (rva 0 + offset 0)
    runtime_va = result['read_evidence']['resolved_runtime_va']
    assert runtime_va == KBASE + PINNED['rva'] + PINNED['offset'] != 0
    assert result['read_run_record']['provider_entries'] == 1
    assert store.read_run_ids() == [KL.SIM_GENERIC_RUN]
    # and the same code path still grants for a nonzero-RVA window (the rehearsal)
    assert do_rehearsal_read(rehearse_store(tmp_path))['ok'] is True


# ===========================================================================================
# the host-side event verifier
# ===========================================================================================
def test_event_verifier_rederives_the_kernel_base_and_refuses_a_foreign_one():
    event = pinned_event()
    assert KL.verify_bounded_event(event, profile=PROFILE, expected=PINNED)['verified'] is True
    bad = dict(event, kbase_candidate=KL.u64_hex(KBASE + 0x1000))
    report = KL.verify_bounded_event(bad, profile=PROFILE, expected=PINNED)
    assert report['verified'] is False
    assert any(str(p).startswith(KL.KREADLIVE_KBASE_MISMATCH) for p in report['problems'])
    bad_lstar = dict(event, lstar=KL.u64_hex(KBASE + 0x1000 + KL.XFAST_RVA))
    assert KL.verify_bounded_event(bad_lstar, profile=PROFILE,
                                   expected=PINNED)['verified'] is False


def test_event_verifier_refuses_claim_violations_and_bad_addresses():
    event = pinned_event()
    cases = [
        (dict(event, retry=True), KL.KREADLIVE_EVENT_CLAIM),
        (dict(event, writes_to_kernel=True), KL.KREADLIVE_EVENT_CLAIM),
        (dict(event, host_supplied_address=True), KL.KREADLIVE_EVENT_CLAIM),
        (dict(event, single_callback=False), KL.KREADLIVE_EVENT_CLAIM),
        (dict(event, resolved_runtime_va=KL.u64_hex(KBASE + 16)), KL.KREADLIVE_ADDRESS_MISMATCH),
        (dict(event, region_count=99), KL.KREADLIVE_TABLE_MISMATCH),
        (dict(event, max_read_len=16), KL.KREADLIVE_TABLE_MISMATCH),
    ]
    for tampered, reason in cases:
        report = KL.verify_bounded_event(tampered, profile=PROFILE, expected=PINNED)
        assert report['verified'] is False, tampered
        assert any(str(p).startswith(reason) for p in report['problems']), \
            (reason, report['problems'])
    missing = KL.verify_bounded_event(None, profile=PROFILE, expected=PINNED)
    assert missing['verified'] is False
    assert any(str(p).startswith(KL.KREADLIVE_EVENT_MISSING) for p in missing['problems'])


def test_event_verifier_refuses_bytes_that_are_not_the_expected_bytes():
    event = pinned_event(bytes_hex='22' * 16, )
    report = KL.verify_bounded_event(event, profile=PROFILE, expected=PINNED)
    assert report['verified'] is False
    assert any(str(p).startswith(KL.KREADLIVE_BYTES_MISMATCH) for p in report['problems'])


# ===========================================================================================
# the offline end-to-end simulation
# ===========================================================================================
def test_offline_end_to_end_simulation(tmp_path):
    report = KL.run_offline_simulation(store_root=tmp_path)
    assert report['ok'] is True, report['checks_failed']
    assert report['checks_failed'] == []
    assert report['schema'] == KL.SIMULATION_SCHEMA
    assert report['profile_sha256'] == PROFILE_SHA
    phase_a, phase_b = report['phase_a'], report['phase_b']
    assert phase_a['outcome'] == KL.OUTCOME_VERIFIED
    assert phase_a['provider_entries'] == 0
    assert phase_a['observed_bytes_hex'] == PINNED_BYTES
    assert phase_a['observed_sha256'] == PINNED_SHA
    assert phase_a['evidence_sha256']
    assert phase_b['outcome'] == KL.OUTCOME_READ             # the pinned window, bound
    assert phase_b['provider_entries'] == 1
    assert report['accepted_contract_met'] is True
    assert report['blocker'] is None
    finding = report['integration_finding']
    assert finding['id'] == 'W12-RVA0-BINDING' and finding['fixed_in_this_run'] is True
    assert finding['profile_unchanged'] == PROFILE_SHA
    rehearsal = report['rehearsal_phase_b']
    assert rehearsal['outcome'] == KL.OUTCOME_READ
    assert rehearsal['provider_entries'] == 1
    ids = report['ids']
    assert ids['verification_run_id'] != ids['read_run_id']
    assert ids['verification_session_id'] != ids['read_session_id']
    assert report['boundary_probe']['outcome'] == KL.OUTCOME_REFUSED
    assert any(str(p).startswith(KL.KREADLIVE_SESSION_REUSED)
               for p in report['boundary_probe']['problems'])
    # the transcript names both phases and the new run of run B
    steps = ' '.join(entry['step'] for entry in report['transcript'])
    assert 'RUN A' in steps and 'RUN B' in steps
    # the pinned store holds the verification record of run A and the granted read-run record
    assert report['store']['verification_run_ids'] == [KL.SIM_VERIFICATION_RUN]
    assert report['store']['read_run_ids'] == [KL.SIM_GENERIC_RUN]
    assert pathlib.Path(report['store_root']).exists()


def test_the_simulation_is_deterministic(tmp_path):
    def content(report: dict) -> str:
        def strip(value):
            if isinstance(value, dict):
                return {key: strip(item) for key, item in sorted(value.items())
                        if not key.endswith('_path') and not key.endswith('_root')}
            if isinstance(value, list):
                return [strip(item) for item in value]
            return value
        return json.dumps(strip(report), sort_keys=True)

    first = KL.run_offline_simulation(store_root=tmp_path / 'one')
    second = KL.run_offline_simulation(store_root=tmp_path / 'two')
    assert first['store_root'] != second['store_root']
    # the two runs are byte-identical once the store location is normalised away
    assert (content(first).replace(str(first['store_root']), '<store>') ==
            content(second).replace(str(second['store_root']), '<store>'))


def test_the_module_self_test_passes():
    assert KL._self_test() == []
    assert KS._self_test() == []


# ===========================================================================================
# the CLI wiring: two explicit phases, never chained
# ===========================================================================================
def _live_args(argv, monkeypatch, tmp_path):
    captured: dict = {}

    def fake_mode_live(args):
        captured['args'] = args
        return 0

    monkeypatch.setattr(cli, 'mode_live', fake_mode_live)
    base = ['live', '--psk-file', str(tmp_path / 'psk.bin'),
            '--payload-bin', str(tmp_path / 'payload.bin')]
    assert cli.main(base + argv) == 0
    return captured['args']


def test_cli_exposes_two_separate_phases(tmp_path, monkeypatch):
    verify = _live_args(['--w12-verify-run', '--w12-boot-id', 'BOOT-x'], monkeypatch, tmp_path)
    assert verify.w12_verify_run is True and verify.w12_read_run is False
    assert verify.w12_boot_id == 'BOOT-x'
    read = _live_args(['--w12-read-run', '--w12-boot-id', 'BOOT-x',
                       '--w12-verification-run-id', 'VRUN-1', '--w12-live-approved'],
                      monkeypatch, tmp_path)
    assert read.w12_read_run is True and read.w12_verify_run is False
    assert read.w12_verification_run_id == 'VRUN-1' and read.w12_live_approved is True
    # the phases are mutually exclusive: one invocation can never run both
    with pytest.raises(SystemExit):
        _live_args(['--w12-verify-run', '--w12-read-run'], monkeypatch, tmp_path)
    # a non-W12 run is untouched
    plain = _live_args([], monkeypatch, tmp_path)
    assert plain.w12_verify_run is False and plain.w12_read_run is False
    assert cli.w12_preflight(plain) == {}
    # the live and listen parsers both carry the phases
    captured = {}

    def fake_mode_listen(args):
        captured['args'] = args
        return 0

    monkeypatch.setattr(cli, 'mode_listen', fake_mode_listen)
    assert cli.main(['listen', '--psk-file', str(tmp_path / 'psk.bin'), '--bind-port', '1',
                     '--w12-verify-run', '--w12-boot-id', 'BOOT-x',
                     '--w12-rearm-confirmed']) == 0
    assert captured['args'].w12_verify_run is True
    assert captured['args'].w12_boot_id == 'BOOT-x'
    assert captured['args'].w12_rearm_confirmed is True
    assert captured['args'].w12_read_run is False


def test_cli_phases_require_their_own_confirmation_and_never_hand_off(tmp_path, monkeypatch):
    """No phase runs on a half-configured flow, and phase B needs phase A's run id."""
    psk = str(tmp_path / 'psk.bin')
    # phase A in listen mode without its own confirmation
    with pytest.raises(SystemExit, match='w12-rearm-confirmed'):
        cli.main(['listen', '--psk-file', psk, '--bind-port', '1', '--w12-verify-run',
                  '--w12-boot-id', 'BOOT-x'])
    # phase B without the verification run id (there is no automatic hand-off)
    with pytest.raises(SystemExit, match='w12-verification-run-id'):
        cli.main(['listen', '--psk-file', psk, '--bind-port', '1', '--w12-read-run',
                  '--w12-boot-id', 'BOOT-x', '--w12-rearm-confirmed'])
    # no boot binding, no phase
    with pytest.raises(SystemExit, match='w12-boot-id'):
        cli.main(['listen', '--psk-file', psk, '--bind-port', '1', '--w12-verify-run',
                  '--w12-rearm-confirmed'])
    # live mode: the missing confirmation is reported as BLOCKED by the preflight (and mode_live's
    # own gate refuses the upload), it never falls through to a phase
    args = argparse.Namespace(w12_verify_run=True, w12_read_run=False, w12_boot_id='BOOT-x',
                              mode='live', rearm_confirmed=False, w12_store=str(tmp_path),
                              w12_run_id=None, w12_verification_run_id=None,
                              w12_rearm_confirmed=False)
    config = cli.w12_preflight(args)          # prints BLOCKED, raises nothing
    assert config == {'phase': 'w12-verify-run', 'mode': 'live', 'boot_id': 'BOOT-x',
                      'store': str(tmp_path), 'run_id': None, 'verification_run_id': None,
                      'expected_window': None, 'w13_release': None, 'w12_approval': None}
    # a research release belongs to a read: the verification phase never takes one, and an
    # unreadable or refused release stops the invocation before anything exists (fail closed)
    with pytest.raises(SystemExit, match='belongs to a research READ'):
        cli.main(['listen', '--psk-file', psk, '--bind-port', '1', '--w12-verify-run',
                  '--w12-boot-id', 'BOOT-x', '--w12-rearm-confirmed',
                  '--w13-release', str(tmp_path / 'missing.json')])
    # a release without the section 70 approval BESIDE it is refused (owner separation rule)
    with pytest.raises(SystemExit, match='W13_RELEASE_APPROVAL_MISSING'):
        cli.main(['listen', '--psk-file', psk, '--bind-port', '1', '--w12-read-run',
                  '--w12-boot-id', 'BOOT-x', '--w12-verification-run-id', 'VRUN-x',
                  '--w12-rearm-confirmed', '--w13-release', str(tmp_path / 'missing.json')])
    # an unreadable approval is refused before anything else (fail closed, no fall-through)
    with pytest.raises(SystemExit, match='W12_APPROVAL_INVALID'):
        cli.main(['listen', '--psk-file', psk, '--bind-port', '1', '--w12-read-run',
                  '--w12-boot-id', 'BOOT-x', '--w12-verification-run-id', 'VRUN-x',
                  '--w12-approval', str(tmp_path / 'approval.json'),
                  '--w12-rearm-confirmed', '--w13-release', str(tmp_path / 'missing.json')])
    args.rearm_confirmed = True
    assert cli.w12_preflight(args)['phase'] == 'w12-verify-run'


def test_cli_phase_run_records_the_phase_and_the_entry_count(tmp_path):
    """``w12_phase_run`` writes the phase into the W8 evidence document, with its entry count."""
    rec = RunRecord(run_id='RUN-cli-phase-a', mode='live', repo={}, payload={}, transport={})
    args = argparse.Namespace(w12_boot_id=BINDING.boot_id, w12_store=str(tmp_path),
                              w12_run_id=KL.SIM_VERIFICATION_RUN, w12_verification_run_id=None,
                              w12_live_approved=False, w12_approval=None)
    result = cli.w12_phase_run(pinned_session(), rec, args, phase=KL.PHASE_VERIFY)
    assert result['outcome'] == KL.OUTCOME_VERIFIED
    assert rec.doc['w12_phase'] == KL.PHASE_VERIFY
    assert rec.doc['w12']['provider_entries'] == 0
    assert rec.doc['w12_artifacts']['verification_evidence_sha256'] == \
        result['evidence']['evidence_sha256']
    assert rec.doc['w12_artifacts']['decision'] is None       # phase A decides nothing
    entry_checks = [c for c in rec.doc['checks'] if 'provider entries' in c['name']]
    assert len(entry_checks) == 1 and entry_checks[0]['ok'] is True
    outcome_checks = [c for c in rec.doc['checks'] if 'outcome' in c['name']]
    assert len(outcome_checks) == 1 and outcome_checks[0]['ok'] is True
    assert (tmp_path / 'verification' / f'{KL.SIM_VERIFICATION_RUN}.json').exists()


def test_cli_phase_run_refuses_to_run_phase_b_without_a_verification_run_id(tmp_path):
    rec = RunRecord(run_id='RUN-cli-phase-b', mode='live', repo={}, payload={}, transport={})
    args = argparse.Namespace(w12_boot_id=BINDING.boot_id, w12_store=str(tmp_path),
                              w12_run_id=None, w12_verification_run_id=None,
                              w12_live_approved=True, w12_approval=None)
    with pytest.raises(ValueError, match='phase B needs the verification_run_id'):
        cli.w12_phase_run(KL.OfflineSession(session_id=KL.SIM_SESSION_B, event=pinned_event()),
                          rec, args, phase=KL.PHASE_READ)
