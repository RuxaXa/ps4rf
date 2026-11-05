#!/usr/bin/env python3
"""W12-A3 — the derivation authenticity gate: the mandated regressions.

W4 cannot tell a fully consistent, hand-injected ``PROVEN`` ``NATIVE`` record from one that was
really derived from stored ``VerificationEvidence``. W12-A3 moves that decision into the
*productive path*: the only constructor of a ``PROVEN`` ``kernel.read`` record is
:func:`tools.hostctl.kreadlive.derive_capability_record`, which is addressed by the evidence hash
and re-establishes every fact from the store, and the driver revalidates the derivation
immediately before the provider entry (``KREADLIVE_CAPABILITY_NOT_DERIVED``).

Nothing here talks to a console: the phases run through the synthetic session fixtures and a
temporary evidence store.
"""
from __future__ import annotations

import inspect
import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.hostctl import kreadlive as KL                                # noqa: E402
from tools.hostctl import kreadstore as KS                               # noqa: E402
from tools.profiles import kread_capability as KC                        # noqa: E402

PROFILE, PROFILE_SHA = KL.synthetic_profile()
BINDING = KL.synthetic_boot_binding(PROFILE)
PINNED = KL.bootstrap_expectation(PROFILE)
APPROVAL = KL.SIM_APPROVAL


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


def evidence_sha(store) -> str:
    return store.load_verification(KL.SIM_VERIFICATION_RUN)['evidence_sha256']


def record_path(store) -> pathlib.Path:
    return next(store.root.rglob(f'{KL.SIM_VERIFICATION_RUN}.json'))


def rewrite(store, mutate) -> dict:
    """Rewrite the stored record after applying *mutate* (the store's hash is recomputed)."""
    path = record_path(store)
    body = json.loads(path.read_text())
    mutate(body)
    body['evidence_sha256'] = KS.canonical_evidence_sha256(body)
    path.write_text(json.dumps(body, indent=1, sort_keys=True) + '\n')
    return body


def _derive(store, **over) -> dict:
    kwargs = dict(evidence_sha256=evidence_sha(store), read_run_id=KL.SIM_GENERIC_RUN,
                  profile_sha256=PROFILE_SHA, boot_id=BINDING.boot_id,
                  provider=KL.sim_provider(), context=KL.CONTEXT, session_id=KL.SIM_SESSION_B,
                  approval=APPROVAL, expected=PINNED)
    kwargs.update(over)
    return KL.derive_capability_record(store, **kwargs)


def hand_built(sha: str, **over) -> dict:
    """A fully plausible PROVEN NATIVE record -- built by hand, never derived."""
    record = {'name': 'kernel.read', 'availability': 'AVAILABLE', 'assurance': 'PROVEN',
              'context': KL.CONTEXT, 'provider': KL.PROVIDER_NAME, 'provider_type': 'NATIVE',
              'scope': 'SESSION', 'session_id': KL.SIM_SESSION_B, 'boot_id': BINDING.boot_id,
              'profile_sha256': PROFILE_SHA,
              'verification': {'run_id': KL.SIM_VERIFICATION_RUN, 'session_id': KL.SIM_SESSION_B,
                               'operation': 'verify.kernel.read', 'outcome': 'PASS',
                               'capability': 'kernel.read', 'provider': KL.PROVIDER_NAME,
                               'provider_type': 'NATIVE', 'scope': 'SESSION',
                               'boot_id': BINDING.boot_id, 'separate_from_read': True,
                               'evidence_ref': {'run_id': KL.SIM_VERIFICATION_RUN, 'sha256': sha}},
              'evidence_refs': [{'run_id': KL.SIM_VERIFICATION_RUN, 'sha256': sha}],
              'evidence_ref': {'run_id': KL.SIM_VERIFICATION_RUN, 'sha256': sha},
              'approval': dict(APPROVAL),
              'derivation': {'derived_from_evidence_sha256': sha,
                             'derived_from_verification_run_id': KL.SIM_VERIFICATION_RUN,
                             'derived_for_session_id': KL.SIM_SESSION_B,
                             'derived_for_boot_id': BINDING.boot_id,
                             'derived_for_profile_sha256': PROFILE_SHA,
                             'derived_for_read_run_id': KL.SIM_GENERIC_RUN,
                             'receipt_id': 'f' * 64}}
    record.update(over)
    return record


# ===========================================================================================
# 1. the decisive negative test: a hand-built record never reaches the provider
# ===========================================================================================
def test_a_hand_built_proven_record_never_reaches_the_provider(tmp_path, monkeypatch):
    """The owner's decisive case: skip the derivation, inject a plausible record -- the provider
    entry stays at zero and the reason is ``KREADLIVE_CAPABILITY_NOT_DERIVED``."""
    store = seeded_store(tmp_path)
    forged = hand_built(evidence_sha(store))
    monkeypatch.setattr(KL, 'derive_capability_record', lambda *args, **kwargs: dict(forged))
    result = do_phase_b(store)
    assert result['outcome'] == KL.OUTCOME_REFUSED, result['problems']
    assert result['provider_entries'] == 0 == result['generic_provider_entries']
    assert any(KL.KREADLIVE_CAPABILITY_NOT_DERIVED in str(problem)
               for problem in result['problems']), result['problems']
    assert result['event'] is None
    assert result['read_run_record'] is None
    assert store.read_run_ids() == [], 'a refused record must not write a read run'


def test_a_hand_built_record_without_any_derivation_block_is_refused(tmp_path):
    store = seeded_store(tmp_path)
    record = hand_built(evidence_sha(store))
    del record['derivation']
    problems = KL.revalidate_derivation(record, store=store, session_id=KL.SIM_SESSION_B,
                                        boot_id=BINDING.boot_id, profile_sha256=PROFILE_SHA,
                                        read_run_id=KL.SIM_GENERIC_RUN)
    assert any(KL.KREADLIVE_CAPABILITY_NOT_DERIVED in problem for problem in problems), problems
    assert 'hand-built' in ' '.join(problems)


def test_a_fabricated_receipt_id_is_refused(tmp_path):
    """A fabricated derivation block with a plausible receipt id is refused all the same: no such
    receipt was generated by this process."""
    store = seeded_store(tmp_path)
    record = hand_built(evidence_sha(store))
    assert record['derivation']['receipt_id'] == 'f' * 64
    problems = KL.revalidate_derivation(record, store=store, session_id=KL.SIM_SESSION_B,
                                        boot_id=BINDING.boot_id, profile_sha256=PROFILE_SHA,
                                        read_run_id=KL.SIM_GENERIC_RUN)
    assert any(KL.KREADLIVE_CAPABILITY_NOT_DERIVED in problem for problem in problems), problems
    assert 'receipt' in ' '.join(problems)


def test_a_stolen_receipt_id_on_another_record_is_refused(tmp_path):
    """The receipt is bound to the *content* of the derived record: copying a real receipt id onto
    a hand-built record still fails, because that receipt was generated for another record."""
    store = seeded_store(tmp_path)
    derived = _derive(store)
    stolen = hand_built(evidence_sha(store))
    stolen['derivation']['receipt_id'] = derived['derivation']['receipt_id']
    problems = KL.revalidate_derivation(stolen, store=store, session_id=KL.SIM_SESSION_B,
                                        boot_id=BINDING.boot_id, profile_sha256=PROFILE_SHA,
                                        read_run_id=KL.SIM_GENERIC_RUN)
    assert problems, 'a stolen receipt id must not validate another record'
    assert any('does not match the derivation it names' in problem for problem in problems), problems


def test_a_derived_record_passes_the_revalidation(tmp_path):
    store = seeded_store(tmp_path)
    record = _derive(store)
    assert KL.revalidate_derivation(record, store=store, session_id=KL.SIM_SESSION_B,
                                    boot_id=BINDING.boot_id, profile_sha256=PROFILE_SHA,
                                    read_run_id=KL.SIM_GENERIC_RUN) == []


def test_the_revalidation_is_bound_to_session_boot_profile_and_read_run(tmp_path):
    store = seeded_store(tmp_path)
    record = _derive(store)
    for label, over in (('session_id', {'session_id': 'SES-' + '9' * 32}),
                        ('boot_id', {'boot_id': 'BOOT-' + '9' * 16}),
                        ('profile_sha256', {'profile_sha256': 'a' * 64}),
                        ('read_run_id', {'read_run_id': 'RUN-' + '9' * 32})):
        current = {'session_id': KL.SIM_SESSION_B, 'boot_id': BINDING.boot_id,
                   'profile_sha256': PROFILE_SHA, 'read_run_id': KL.SIM_GENERIC_RUN, **over}
        problems = KL.revalidate_derivation(record, store=store, **current)
        assert any(KL.KREADLIVE_CAPABILITY_NOT_DERIVED in problem for problem in problems), \
            (label, problems)


def test_no_caller_input_can_supply_the_derivation_markers():
    """The productive path takes ids and bindings only: no parameter carries a record, a
    verification block or the markers, so raw caller input can never set them."""
    forbidden = {'capability', 'capability_record', 'record', 'derivation', 'verification',
                 'evidence', 'receipt', 'receipt_id'}
    for function in (KL.run_generic_read, KL.derive_capability_record):
        parameters = set(inspect.signature(function).parameters)
        assert not parameters & forbidden, (function.__name__, sorted(parameters & forbidden))
    with pytest.raises(TypeError):
        KL.run_generic_read(None, profile=PROFILE, boot_binding=BINDING, store=None,
                            verification_run_id='VRUN-x',
                            capability=hand_built('a' * 64))  # type: ignore[call-arg]


# ===========================================================================================
# 2. store manipulation
# ===========================================================================================
def test_the_valid_record_is_addressable_by_its_hash_and_reads_once(tmp_path):
    store = seeded_store(tmp_path)
    sha = evidence_sha(store)
    loaded = store.load_verification_by_sha256(sha)
    assert loaded['evidence_sha256'] == sha == KS.canonical_evidence_sha256(loaded)
    result = do_phase_b(store, evidence_sha256=sha)
    assert result['outcome'] == KL.OUTCOME_READ, result['problems']
    assert result['provider_entries'] == 1 == result['generic_provider_entries']


def test_a_one_byte_change_after_persisting_is_a_store_rehash_mismatch(tmp_path):
    store = seeded_store(tmp_path)
    sha = evidence_sha(store)
    path = record_path(store)
    body = json.loads(path.read_text())
    body['observed_sha256'] = 'de' * 32                    # one byte's worth, hash left untouched
    path.write_text(json.dumps(body, sort_keys=True))
    with pytest.raises(KS.StoreError) as excinfo:
        store.load_verification_by_sha256(sha)
    assert excinfo.value.reason == KS.STORE_REHASH_MISMATCH, excinfo.value.reason
    result = do_phase_b(store, evidence_sha256=sha)
    assert result['outcome'] == KL.OUTCOME_REFUSED
    assert result['provider_entries'] == 0
    assert any(KS.STORE_REHASH_MISMATCH in str(problem)
               for problem in result['problems']), result['problems']


def test_the_same_record_under_another_file_name_is_refused(tmp_path):
    store = seeded_store(tmp_path)
    sha = evidence_sha(store)
    source = record_path(store)
    (source.parent / 'VRUN-renamed-copy.json').write_text(source.read_text())
    with pytest.raises(KS.StoreError) as excinfo:
        store.load_verification_by_sha256(sha)
    assert excinfo.value.reason == KS.STORE_ID_INVALID, excinfo.value.reason


def test_a_record_rehashed_under_another_run_id_loses_the_old_address(tmp_path):
    store = seeded_store(tmp_path)
    sha = evidence_sha(store)
    path = record_path(store)

    def mutate(body):
        body['verification_run_id'] = 'VRUN-' + '7' * 16

    body = rewrite(store, mutate)
    path.unlink()
    (path.parent / f"{body['verification_run_id']}.json").write_text(
        json.dumps(body, indent=1, sort_keys=True) + '\n')
    with pytest.raises(KS.StoreError) as excinfo:
        store.load_verification_by_sha256(sha)
    assert excinfo.value.reason == KS.STORE_MISSING, excinfo.value.reason


def test_evidence_for_another_boot_is_refused(tmp_path):
    store = seeded_store(tmp_path)
    with pytest.raises(KL.DerivationRejected) as excinfo:
        _derive(store, boot_id='BOOT-' + '0' * 16)
    assert excinfo.value.reason == KC.KREAD_STALE_BOOT_ID, excinfo.value.reason


def test_evidence_for_another_profile_is_refused(tmp_path):
    store = seeded_store(tmp_path)
    with pytest.raises(KL.DerivationRejected) as excinfo:
        _derive(store, profile_sha256='a' * 64)
    assert excinfo.value.reason == KC.KREAD_WRONG_PROFILE, excinfo.value.reason


def test_evidence_for_another_capability_is_refused(tmp_path):
    store = seeded_store(tmp_path)
    rewrite(store, lambda body: body.update(capability='kernel.snapshot'))
    with pytest.raises(KL.DerivationRejected) as excinfo:
        _derive(store)
    assert excinfo.value.reason in ('KREADLIVE_EVIDENCE_INVALID', 'KREADLIVE_EXPECTATION_MISMATCH'), \
        excinfo.value.reason


def test_evidence_for_another_provider_is_refused(tmp_path):
    store = seeded_store(tmp_path)
    rewrite(store, lambda body: body.update(provider='someone-else-kread'))
    with pytest.raises(KL.DerivationRejected) as excinfo:
        _derive(store)
    assert excinfo.value.reason == KL.KREADLIVE_PROVIDER_MISMATCH, excinfo.value.reason


def test_the_same_run_id_for_verification_and_read_is_refused(tmp_path):
    store = seeded_store(tmp_path)
    with pytest.raises(KL.DerivationRejected) as excinfo:
        _derive(store, read_run_id=KL.SIM_VERIFICATION_RUN)
    assert excinfo.value.reason == KL.KREADLIVE_RUN_NOT_SEPARATE, excinfo.value.reason


def test_the_verification_session_is_never_used_for_the_read(tmp_path):
    store = seeded_store(tmp_path)
    with pytest.raises(KL.DerivationRejected) as excinfo:
        _derive(store, session_id=KL.SIM_SESSION_A)
    assert excinfo.value.reason == KL.KREADLIVE_SESSION_REUSED, excinfo.value.reason


def test_a_store_tampered_after_the_derivation_is_caught_at_entry_time(tmp_path):
    """The entry-time revalidation: derive, then tamper with the store, then re-check."""
    store = seeded_store(tmp_path)
    record = _derive(store)
    before = KS.canonical_evidence_sha256(store.load_verification_by_sha256(evidence_sha(store)))
    rewrite(store, lambda body: body.update(observed_sha256='ab' * 32))
    after = KS.canonical_evidence_sha256(store.load_verification_by_sha256(evidence_sha(store)))
    assert before != after, 'the tamper changed the record'
    problems = KL.revalidate_derivation(record, store=store, session_id=KL.SIM_SESSION_B,
                                        boot_id=BINDING.boot_id, profile_sha256=PROFILE_SHA,
                                        read_run_id=KL.SIM_GENERIC_RUN)
    assert problems, 'a tampered store must be refused at entry time'
    assert any(KS.STORE_REHASH_MISMATCH in problem or KS.STORE_MISSING in problem
               or KS.STORE_ID_INVALID in problem or 'no longer matches the derivation' in problem
               for problem in problems), problems


# ===========================================================================================
# 3. session B keeps its guarantees, and the persisted record is the derived one
# ===========================================================================================
def test_session_b_reads_once_and_persists_the_derived_record(tmp_path):
    store = seeded_store(tmp_path)
    result = do_phase_b(store)
    assert result['outcome'] == KL.OUTCOME_READ, result['problems']
    capability = result['capability']
    receipt_id = capability['derivation']['receipt_id']
    assert receipt_id in KL._DERIVATION_RECEIPTS
    record = store.load_read_run(KL.SIM_GENERIC_RUN)
    persisted = record['capability']
    assert persisted['derivation'] == capability['derivation']
    assert persisted['session_id'] == KL.SIM_SESSION_B
    assert persisted['assurance'] == 'PROVEN'
    assert persisted['evidence_refs'][0]['sha256'] == capability['derivation'][
        'derived_from_evidence_sha256']
    assert record['verification_session_id'] == KL.SIM_SESSION_A
    assert record['verification_run_id'] != record['read_run_id']
