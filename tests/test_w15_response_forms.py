"""W15 -- the response form of the read trigger, pinned in both directions.

W14 wired `kernel.read` to the privileged provider. Since then the operation answers with the read
*record* instead of the frozen deferred privilege, and the host side had to learn both forms --
that is the one place where a silent widening would be dangerous, because "the answer arrived" and
"the answer is the record of the read I asked for" are different claims.

So this module pins the whole matrix:

* record form, valid            -> the read verifies (one provider entry, the pinned bytes)
* deferred form, valid          -> unchanged: the frozen W12 path still works
* naked ``{"status": "OK"}``    -> rejected (there is no read record, so nothing was answered)
* malformed record              -> rejected, in both readings: a partial record is not a record at
                                   all, and a record whose numbers lie fails the verification
* record naming another region / index / length -> rejected with that mismatch

Nothing here is allowed to pass because "a response arrived": every rejection is asserted by its own
refusal code, and every acceptance by a verified read.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.hostctl import kreadlive as KL                                       # noqa: E402
from tools.hostctl import kreadstore as KS                                      # noqa: E402
from tools.hostctl import live_w15 as W15                                       # noqa: E402
from tools.profiles.schema import canonical_profile_sha256                      # noqa: E402
from tools.research import classification as C                                  # noqa: E402
from tools.research import release as REL                                       # noqa: E402

PROFILE = C.DEFAULT_PROFILE
PROFILE_SHA = canonical_profile_sha256(PROFILE)
REGION = 'amd_iommu'
PAYLOAD = {'bin_sha256': '99' * 32, 'elf_sha256': '2e' * 32, 'build_manifest_sha256': '4d' * 32,
           'build_id': '032ffa3eb281384edeffcbb11c84e242', 'label': 'ps4rfd-live-w15'}


@pytest.fixture()
def fixture(tmp_path):
    binding = KL.synthetic_boot_binding(PROFILE)
    store = KS.VerificationEvidenceStore(tmp_path / 'store')
    verification = KL.run_verification(
        KL.OfflineSession(session_id=KL.SIM_SESSION_A, event=KL.synthetic_bounded_event()),
        profile=PROFILE, boot_binding=binding, store=store,
        provider=KL.sim_provider(live_approved=False))
    assert verification['outcome'] == 'VERIFIED', verification.get('problems')
    fixtures = W15.plan_fixtures(profile=PROFILE, profile_sha256=PROFILE_SHA, boot_id=binding.boot_id,
                                 payload=PAYLOAD,
                                 evidence_sha256=verification['evidence']['evidence_sha256'],
                                 verification_run_id=verification['verification_run_id'],
                                 # one release per test: ids are stamped to the minute otherwise, and
                                 # the one-shot ledger (correctly) refuses a second use of an id
                                 now=f'FORM-{tmp_path.name.split("-")[-1]}')
    window = REL.released_window(fixtures['release'], profile=PROFILE, profile_sha256=PROFILE_SHA,
                                 boot_id=binding.boot_id,
                                 approval_sha256=fixtures['approval_sha256'])['window']
    return {'binding': binding, 'store': store, 'verification': verification,
            'fixtures': fixtures, 'window': window}


def _record(fx, **overrides) -> dict:
    """The read record as a wired provider returns it: the verification accepts this shape."""
    record = KL.synthetic_bounded_event(region=REGION, bytes_hex=fx['fixtures']['expected_bytes'],
                                        runtime_kbase=KL.SIM_KBASE, region_index_override=1)
    record.update(overrides)
    return record


def _read(fx, *, response=None, event=None):
    session = KL.OfflineSession(session_id=KL.SIM_SESSION_B, event=event, response=response)
    return KL.run_generic_read(
        session, profile=PROFILE, boot_binding=fx['binding'], store=fx['store'],
        verification_run_id=fx['verification']['verification_run_id'],
        evidence_sha256=fx['verification']['evidence']['evidence_sha256'],
        approval=fx['fixtures']['approval'], provider=KL.sim_provider(live_approved=True),
        # the evidence is checked against the *pinned bootstrap* window (its default), the read is
        # about the released window: passing the released window as the evidence window would be the
        # relabelling the store's design forbids (A3 1.12/1.13)
        expected=fx['window'])


def _problems(result) -> str:
    return ' | '.join(str(problem) for problem in (result.get('problems') or []))


def test_the_record_form_is_accepted_and_verifies(fixture):
    """The form W14 introduced: the record itself is the answer to the trigger."""
    record = _record(fixture)
    result = _read(fixture, response={'header': {'in_reply_to': 'REQ-offline-0'}, 'status': 'OK',
                                      'result': record, 'cleanup': {'state': 'CLOSED'}},
                   event=None)
    assert result['outcome'] == 'READ', _problems(result)
    assert result['provider_entries'] == 1
    assert result['event_report']['verified'] is True
    assert result['event_report']['bytes_hex'] == fixture['fixtures']['expected_bytes']
    assert result['event_report']['region'] == REGION
    assert result['event_report']['requested_region_index'] == 1


def test_the_frozen_deferred_form_still_works(fixture):
    """The W12 semantics: the router answers deferred and the read arrives as the captured event."""
    result = _read(fixture, event=_record(fixture))            # the default response IS deferred
    assert result['outcome'] == 'READ', _problems(result)
    assert result['provider_entries'] == 1
    assert result['event_report']['verified'] is True


def test_a_naked_ok_without_a_record_is_rejected(fixture):
    """`{"status":"OK"}` is not an answer: nothing about a read is in it."""
    result = _read(fixture, response={'header': {'in_reply_to': 'REQ-offline-0'}, 'status': 'OK',
                                      'cleanup': {'state': 'CLOSED'}},
                   event=None)
    # fail closed: nothing was read, nothing was verified, nothing was persisted. The provider
    # *entry* itself did happen -- the router granted it and the trigger was sent; what must never
    # happen is that an empty OK is mistaken for a read.
    assert result['outcome'] == 'REFUSED', result
    assert result['event'] is None
    assert (result.get('event_report') or {}).get('verified') is not True
    # nothing was read: no read evidence, no persisted read run -- and the release stays spent, so
    # the failure cannot be retried with the same release (the entry happened, the read did not)
    assert result['read_evidence'] is None
    assert result['read_run_id'] not in fixture['store'].read_run_ids()
    assert fixture['store'].release_is_consumed(fixture['fixtures']['release']['release_id']) is True
    assert 'KREADLIVE_TRIGGER_NOT_DEFERRED' in _problems(result), _problems(result)


@pytest.mark.parametrize('missing', ['bytes_hex', 'sha256', 'copied_len', 'requested_region'])
def test_a_partial_record_is_not_a_record(fixture, missing):
    """A record missing one of its identifying fields is not recognised as one -- fail closed."""
    record = _record(fixture)
    record.pop(missing, None)
    result = _read(fixture, response={'header': {'in_reply_to': 'REQ-offline-0'}, 'status': 'OK',
                                      'result': record, 'cleanup': {'state': 'CLOSED'}},
                   event=None)
    assert result['outcome'] == 'REFUSED', result
    assert result['event'] is None
    assert (result.get('event_report') or {}).get('verified') is not True
    # nothing was read: no read evidence, no persisted read run -- and the release stays spent, so
    # the failure cannot be retried with the same release (the entry happened, the read did not)
    assert result['read_evidence'] is None
    assert result['read_run_id'] not in fixture['store'].read_run_ids()
    assert fixture['store'].release_is_consumed(fixture['fixtures']['release']['release_id']) is True
    assert 'KREADLIVE_TRIGGER_NOT_DEFERRED' in _problems(result), _problems(result)


def test_a_record_whose_numbers_lie_is_refused_by_the_verification(fixture):
    """A complete record that reports a different read is refused by the checks, not by the form."""
    record = _record(fixture, copied_len=8, bytes_hex='00' * 16)
    result = _read(fixture, response={'header': {'in_reply_to': 'REQ-offline-0'}, 'status': 'OK',
                                      'result': record, 'cleanup': {'state': 'CLOSED'}},
                   event=None)
    assert result['outcome'] == 'REFUSED', result
    assert result['provider_entries'] == 1     # the entry happened; the *read* is what failed
    report = result.get('event_report') or {}
    assert report.get('verified') is False, report
    problems = _problems(result)
    assert 'KREADLIVE_LENGTH_MISMATCH' in problems or 'KREADLIVE_BYTES_MISMATCH' in problems, problems


@pytest.mark.parametrize('field,value,expected_code', [
    ('region_index_override', 0, 'KREADLIVE_REGION'),
    ('requested_offset', 4, 'KREADLIVE_OFFSET_MISMATCH'),
    ('requested_length', 8, 'KREADLIVE_LENGTH_MISMATCH'),
])
def test_a_record_naming_another_window_is_refused(fixture, field, value, expected_code):
    """The record must describe the window that was released -- nothing else may verify.

    The region is named through its compiled row: a record that reports another row describes
    another window, whatever its name field says.
    """
    if field == 'region_index_override':
        record = KL.synthetic_bounded_event(region='image_elf', runtime_kbase=KL.SIM_KBASE,
                                            region_index_override=value)
    else:
        record = _record(fixture, **{field: value})
    result = _read(fixture, response={'header': {'in_reply_to': 'REQ-offline-0'}, 'status': 'OK',
                                      'result': record, 'cleanup': {'state': 'CLOSED'}},
                   event=None)
    assert result['outcome'] == 'REFUSED', result
    report = result.get('event_report') or {}
    assert report.get('verified') is False, report
    assert expected_code in _problems(result), _problems(result)


def test_the_acceptance_helper_is_the_only_place_the_two_forms_are_recognised(fixture):
    """The recognition lives in one function, and it is exact about both forms.

    `accept_trigger_response()` is what the frozen driver calls; the two accepted shapes are the
    deferred privilege and a *complete* record, and only those.
    """
    col = KL._Collector()
    record = _record(fixture)
    session = KL.OfflineSession(session_id='SES-form-check', event=None)
    KL.accept_trigger_response(session, {'status': 'OK', 'result': record}, col)
    assert col.ok and session.kernel_read_bounded == record

    col2 = KL._Collector()
    KL.accept_trigger_response(KL.OfflineSession(session_id='SES-form-check-2', event=None),
                               {'status': 'ERROR', 'error': {'code': 'OPERATION_DEFERRED'}}, col2)
    assert col2.ok

    col3 = KL._Collector()
    KL.accept_trigger_response(KL.OfflineSession(session_id='SES-form-check-3', event=None),
                               {'status': 'OK'}, col3)
    assert not col3.ok and 'KREADLIVE_TRIGGER_NOT_DEFERRED' in ' '.join(col3.problems)
