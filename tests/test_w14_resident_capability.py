"""W14 §4/§6 (review follow-up) -- the resident agent's per-session capability derivation.

The reviewer's demand, as tests: *every* new session reloads the stored VerificationEvidence,
rehashes it, checks the current boot id and the current profile sha256 and derives a new SESSION
capability -- and a record minted for session A is never accepted in session B.

The frozen machinery (W12-A3/W13) owns the derivation itself; these tests hold it to the resident
case, where one agent serves many sessions in one lifetime and "derive once, reuse for the rest"
would be the natural mistake.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.hostctl import kreadlive as KL            # noqa: E402
from tools.hostctl import kreadstore as KS           # noqa: E402
from tools.hostctl import sessioncaps as SC          # noqa: E402

PROFILE, PROFILE_SHA = KL.synthetic_profile()
BINDING = KL.synthetic_boot_binding(PROFILE)
APPROVAL = KL.SIM_APPROVAL
PINNED = KL.bootstrap_expectation(PROFILE)
KBASE = KL.SIM_KBASE
LIFETIME = 'LIFE-host-standin-0.0-1'


def pinned_session(**over) -> KL.OfflineSession:
    """The same offline session fixture the W12/W13 suites use for the verification phase."""
    over.setdefault('session_id', KL.SIM_SESSION_A)
    over.setdefault('event', KL.synthetic_bounded_event(runtime_kbase=KBASE))
    return KL.OfflineSession(**over)


def verification_store(tmp_path: pathlib.Path) -> tuple[KS.VerificationEvidenceStore, str]:
    """A store holding one PASS verification record (the same fixture the W12/W13 suites use).

    Returns the store and the *already computed* evidence hash the derivation is addressed by.
    """
    store = KS.VerificationEvidenceStore(tmp_path)
    result = KL.run_verification(pinned_session(),
                                 profile=PROFILE, boot_binding=BINDING, store=store,
                                 provider=KL.sim_provider(live_approved=False),
                                 verification_run_id=KL.SIM_VERIFICATION_RUN,
                                 read_run_id=KL.SIM_BOOT_READ_RUN)
    return store, result['evidence']['evidence_sha256']


def derive(ledger: SC.ResidentCapabilityLedger, store, sha: str, session_id: str, **over) -> dict:
    kwargs = dict(store=store, session_id=session_id, evidence_sha256=sha,
                  run_id=KL.SIM_BOOT_READ_RUN, profile_sha256=PROFILE_SHA,
                  boot_id=BINDING.boot_id, provider=KL.sim_provider(), context=KL.CONTEXT,
                  approval=APPROVAL, expected=PINNED)
    kwargs.update(over)
    return ledger.derive_for_session(**kwargs)


def test_every_session_derives_its_own_capability_from_the_same_evidence(tmp_path):
    """One lifetime, two sessions: same stored evidence, two derivations, two session-bound records."""
    store, sha = verification_store(tmp_path)
    ledger = SC.ResidentCapabilityLedger(lifetime_id=LIFETIME)
    first = derive(ledger, store, sha, KL.SIM_SESSION_B)
    second = derive(ledger, store, sha, 'SES-second-session')

    for record in (first, second):
        assert record['assurance'] == 'PROVEN'
        assert record['scope'] == 'SESSION'
        assert record['session_id'] == record['verification']['derived_for_session']
    # same evidence, different session: the records are different, and each names its own session
    assert first['derivation']['derived_from_evidence_sha256'] == \
        second['derivation']['derived_from_evidence_sha256']
    assert first['session_id'] != second['session_id']
    assert first['derivation']['receipt_id'] != second['derivation']['receipt_id']
    assert SC.record_digest(first) != SC.record_digest(second)
    # the ledger records both derivations as evidence, bound to the lifetime
    evidence = ledger.evidence()
    assert evidence['lifetime_id'] == LIFETIME and evidence['sessions_derived'] == 2
    assert [entry['session_id'] for entry in evidence['capability_derivations']] == \
        [KL.SIM_SESSION_B, 'SES-second-session']
    assert all(entry['lifetime_id'] == LIFETIME for entry in evidence['capability_derivations'])


def test_session_a_record_is_never_accepted_in_session_b(tmp_path):
    """The rule the reviewer named: a record from session A does not authorise session B."""
    store, sha = verification_store(tmp_path)
    ledger = SC.ResidentCapabilityLedger(lifetime_id=LIFETIME)
    record_a = derive(ledger, store, sha, 'SES-a')

    # its own session accepts it (and revalidates against the store)
    assert ledger.accept(record_a, session_id='SES-a', store=store, boot_id=BINDING.boot_id,
                         profile_sha256=PROFILE_SHA, read_run_id=KL.SIM_BOOT_READ_RUN) == []
    # another session does not: refused before anything is sent
    with pytest.raises(KL.DerivationRejected) as excinfo:
        ledger.accept(record_a, session_id='SES-b', store=store, boot_id=BINDING.boot_id,
                      profile_sha256=PROFILE_SHA, read_run_id=KL.SIM_BOOT_READ_RUN)
    assert excinfo.value.reason == SC.SESSION_REUSED, excinfo.value
    # ... and neither does a session that has no derivation of its own
    with pytest.raises(KL.DerivationRejected) as excinfo:
        ledger.accept(record_a, session_id='SES-a', store=store, boot_id=BINDING.boot_id,
                      profile_sha256='0' * 64, read_run_id=KL.SIM_BOOT_READ_RUN)
    assert excinfo.value.reason.startswith(('KREAD', 'KREADLIVE')), excinfo.value
    assert 'PROFILE' in str(excinfo.value).upper(), excinfo.value


def test_one_session_derives_once_and_a_foreign_record_is_refused(tmp_path):
    store, sha = verification_store(tmp_path)
    ledger = SC.ResidentCapabilityLedger(lifetime_id=LIFETIME)
    derive(ledger, store, sha, 'SES-a')
    with pytest.raises(KL.DerivationRejected) as excinfo:
        derive(ledger, store, sha, 'SES-a')
    assert excinfo.value.reason == SC.DERIVED_TWICE

    # a *tampered* record is not the one this lifetime derived: the ledger's digest check refuses it
    tampered = dict(ledger._by_session['SES-a']['record'], assurance='OBSERVED')
    with pytest.raises(KL.DerivationRejected) as excinfo:
        ledger.accept(tampered, session_id='SES-a', store=store, boot_id=BINDING.boot_id,
                      profile_sha256=PROFILE_SHA, read_run_id=KL.SIM_BOOT_READ_RUN)
    assert excinfo.value.reason == SC.NOT_DERIVED, excinfo.value

    # and a second lifetime's derivation is a *new* record, never a carried-over one: the ledger of
    # the other lifetime binds it to that lifetime's session
    other = SC.ResidentCapabilityLedger(lifetime_id='LIFE-other')
    record_elsewhere = derive(other, store, sha, 'SES-a')
    assert other.evidence()['capability_derivations'][0]['lifetime_id'] == 'LIFE-other'
    with pytest.raises(KL.DerivationRejected) as excinfo:
        other.accept(record_elsewhere, session_id='SES-b', store=store, boot_id=BINDING.boot_id,
                     profile_sha256=PROFILE_SHA, read_run_id=KL.SIM_BOOT_READ_RUN)
    assert excinfo.value.reason == SC.SESSION_REUSED, excinfo.value


def test_the_current_boot_and_profile_are_checked_for_every_session(tmp_path):
    """A reboot or a profile change invalidates the derivation -- for the *next* session too."""
    store, sha = verification_store(tmp_path)
    ledger = SC.ResidentCapabilityLedger(lifetime_id=LIFETIME)
    with pytest.raises(KL.DerivationRejected) as excinfo:
        derive(ledger, store, sha, 'SES-next-boot', boot_id='BOOT-0000000000000000')
    # the frozen policy names the stale fact: a reboot means "a fresh verification run is required"
    assert excinfo.value.reason.startswith(('KREAD', 'KREADLIVE')), excinfo.value
    assert 'BOOT' in str(excinfo.value).upper() and 'fresh verification' in str(excinfo.value), \
        excinfo.value
    assert ledger.evidence()['sessions_derived'] == 0, 'a refused derivation is not evidence'
    with pytest.raises(KL.DerivationRejected) as excinfo:
        derive(ledger, store, sha, 'SES-next-profile', profile_sha256='1' * 64)
    assert excinfo.value.reason.startswith(('KREAD', 'KREADLIVE')), excinfo.value
    # the store still holds exactly one record: nothing was rewritten by the refusals
    assert store.verification_run_ids() == [KL.SIM_VERIFICATION_RUN]
