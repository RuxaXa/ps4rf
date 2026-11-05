#!/usr/bin/env python3
"""W16 -- the binding-match authorization model (offline; no console, no payload).

What these tests hold down: the window set is derived (never listed), a window set that is not
the candidate's own set is refused, a research approval can never authorise a binding match, a
window can be read exactly once per lifetime, and the only claim a match makes is "the returned
bytes are the pinned bytes" -- through the existing bounded-event verifier.
"""
from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
import sys                                                                       # noqa: E402
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.hostctl import kreadlive as KL                                        # noqa: E402
from tools.profiles import regions as R                                          # noqa: E402
from tools.research import approval as AP                                        # noqa: E402
from tools.research import binding_match as BM                                   # noqa: E402

PAYLOAD = {'bin_sha256': 'b' * 64, 'elf_sha256': 'e' * 64, 'build_manifest_sha256': 'm' * 64,
           'build_id': '1' * 32, 'label': 'ps4rfd-live-w16-1'}
REVISION_SHA = hashlib.sha256(
    (REPO / BM.CANDIDATE_PROFILE).read_bytes()).hexdigest()


def _approval(windows=None, *, pins=None, **changes) -> dict:
    windows = windows or BM.binding_windows()
    effective_pins = {window['region']: window['sha256'] for window in windows}
    effective_pins.update(pins or {})
    document = {
        'schema': BM.SCHEMA_APPROVAL,
        'id': '§70-W16-BINDING-MATCH-1',
        'state': 'APPROVED', 'approved': True, 'approver': 'owner',
        'source': 'owner W16 scope approval (transcribed)',
        'read_scope': BM.SCOPE_BINDING_MATCH,
        'revision_sha256': REVISION_SHA,
        'window_set_sha256': BM.window_set_sha256(windows),
        'windows': [{'region': window['region'], 'sha256': effective_pins[window['region']]}
                    for window in windows],
        'payload': dict(PAYLOAD),
        'boot_id': 'boot-1', 'verification_run_id': 'GRUN-1', 'evidence_sha256': 'f' * 64,
    }
    document.update(changes)
    return document


def _problems(approval) -> list[str]:
    return BM.approval_problems(approval, windows=BM.binding_windows(),
                                revision_sha256=REVISION_SHA, payload=PAYLOAD, boot_id='boot-1',
                                verification_run_id='GRUN-1', evidence_sha256='f' * 64)


def _event(window, *, bytes_hex=None, region=None, length=None) -> dict:
    return KL.synthetic_bounded_event(
        region=region or window['region'], offset=window['offset'],
        length=length or window['length'], bytes_hex=bytes_hex or window['bytes_hex'])


# --- the window set ---------------------------------------------------------------------------

def test_the_window_set_is_the_registrys_strict_ccp_set_and_is_derived():
    windows = BM.binding_windows()
    assert [window['region'] for window in windows] == [
        'ccp_submit_entry', 'ccp_device_gate', 'keymgr_claim_entry', 'keymgr_bind_entry',
        'keymgr_release_entry']
    for window in windows:
        region = R.get_region(window['region'])
        assert region is not None and region.provenance == R.CCP_PROVENANCE
        assert region.identity_status == R.IDENTITY_STRICT
        assert window['region_index'] == R.compiled_region_index(window['region'])
        assert window['length'] == region.length == 16 and window['offset'] == 0
        assert window['sha256'] == hashlib.sha256(bytes.fromhex(window['bytes_hex'])).hexdigest()
    assert BM.window_set_problems(windows) == []


def test_the_structural_pool_is_not_part_of_the_window_set():
    assert 'keymgr_pool' not in [window['region'] for window in BM.binding_windows()]
    assert R.get_region('keymgr_pool').identity_status == R.IDENTITY_STRUCTURAL_ONLY


def test_a_window_set_that_is_not_the_candidates_set_is_refused():
    windows = BM.binding_windows()
    assert any(BM.SET_INCOMPLETE in problem for problem in BM.window_set_problems(windows[:-1]))
    changed = [dict(window) for window in windows]
    changed[0]['bytes_hex'] = '00' * 16
    problems = BM.window_set_problems(changed)
    assert any(BM.WINDOW_NOT_IN_SET in problem for problem in problems)
    assert any(BM.MISMATCH in problem for problem in problems)          # bytes no longer hash
    moved = [dict(window) for window in windows]
    moved[0]['region_index'] = 0
    assert any(BM.WINDOW_NOT_IN_SET in problem for problem in BM.window_set_problems(moved))


def test_the_window_set_hash_changes_when_a_window_changes():
    windows = BM.binding_windows()
    changed = [dict(window) for window in windows]
    changed[3]['sha256'] = '0' * 64
    assert BM.window_set_sha256(changed) != BM.window_set_sha256(windows)


def test_binding_windows_fail_closed_when_the_candidate_pins_nothing():
    candidate = json.loads((REPO / BM.CANDIDATE_PROFILE).read_text())
    candidate['locators'] = {key: value for key, value in candidate['locators'].items()
                             if key != 'ccp.submit.entry'}
    with pytest.raises(ValueError, match=BM.APPROVAL_INVALID):
        BM.binding_windows(candidate)


# --- the approval -----------------------------------------------------------------------------

def test_a_binding_match_approval_that_pins_everything_is_accepted():
    assert _problems(_approval()) == []


def test_the_research_scope_is_refused_here():
    problems = _problems(_approval(read_scope=AP.READ_SCOPE_RESEARCH))
    assert any(BM.SCOPE_MISMATCH in problem for problem in problems)


def test_an_approval_with_a_release_field_is_refused():
    assert any(BM.SCOPE_MISMATCH in problem
               for problem in _problems(_approval(release_id='W16-READ-1')))


def test_a_missing_or_wrong_pin_is_refused():
    assert any(BM.APPROVAL_INVALID in problem
               for problem in _problems(_approval(revision_sha256='0' * 64)))
    assert any(BM.WINDOW_NOT_IN_SET in problem
               for problem in _problems(_approval(window_set_sha256='0' * 64)))
    assert any(BM.MISMATCH in problem for problem in _problems(_approval(pins={
        'ccp_submit_entry': '0' * 64})))
    assert any(BM.APPROVAL_INVALID in problem
               for problem in _problems(_approval(payload=dict(PAYLOAD, bin_sha256='x' * 64))))
    assert any(BM.APPROVAL_INVALID in problem
               for problem in _problems(_approval(boot_id='other-boot')))
    assert any(BM.APPROVAL_INVALID in problem
               for problem in _problems(_approval(state='PROPOSED', approved=False)))


def test_the_approval_id_is_the_canonical_hash_of_everything_the_owner_wrote():
    document = _approval()
    first = BM.approval_sha256(document)
    assert first == BM.approval_sha256(dict(document))
    assert first != BM.approval_sha256(dict(document, source='someone else'))


# --- the ledger --------------------------------------------------------------------------------

def test_a_window_is_read_exactly_once_per_lifetime():
    windows = BM.binding_windows()
    ledger = BM.new_ledger(revision_sha256=REVISION_SHA,
                           window_set=BM.window_set_sha256(windows))
    assert BM.consume(ledger, windows[0], observed_sha256=windows[0]['sha256']) == []
    assert any(BM.ALREADY_READ in problem
               for problem in BM.consume(ledger, windows[0], observed_sha256='0' * 64))
    assert ledger['consumed'] == ['ccp_submit_entry']


def test_the_ledger_is_bound_to_the_revision_and_the_window_set():
    windows = BM.binding_windows()
    ledger = BM.new_ledger(revision_sha256=REVISION_SHA,
                           window_set=BM.window_set_sha256(windows))
    assert BM.ledger_problems(ledger, revision_sha256=REVISION_SHA,
                              window_set=BM.window_set_sha256(windows)) == []
    assert any(BM.SCOPE_MISMATCH in problem
               for problem in BM.ledger_problems(ledger, revision_sha256='0' * 64,
                                                 window_set=BM.window_set_sha256(windows)))
    assert any(BM.WINDOW_NOT_IN_SET in problem
               for problem in BM.ledger_problems(ledger, revision_sha256=REVISION_SHA,
                                                 window_set='0' * 64))


def test_the_ledger_verdict_is_incomplete_until_every_window_was_read():
    windows = BM.binding_windows()
    ledger = BM.new_ledger(revision_sha256=REVISION_SHA,
                           window_set=BM.window_set_sha256(windows))
    for window in windows[:2]:
        BM.consume(ledger, window, observed_sha256=window['sha256'])
    verdict = BM.ledger_verdict(ledger, windows=windows)
    assert verdict['verdict'] == 'INCOMPLETE' and verdict['read'] == 2 and verdict['windows'] == 5
    assert verdict['missing'] == ['keymgr_claim_entry', 'keymgr_bind_entry', 'keymgr_release_entry']
    for window in windows[2:]:
        BM.consume(ledger, window, observed_sha256=window['sha256'])
    assert BM.ledger_verdict(ledger, windows=windows)['verdict'] == 'COMPLETE'


def test_the_ledger_round_trips_through_a_file(tmp_path):
    windows = BM.binding_windows()
    ledger = BM.new_ledger(revision_sha256=REVISION_SHA,
                           window_set=BM.window_set_sha256(windows))
    BM.consume(ledger, windows[0], observed_sha256=windows[0]['sha256'])
    path = tmp_path / 'ledger.json'
    digest = BM.save_ledger(path, ledger)
    reloaded = BM.load_ledger(path)
    assert reloaded == ledger and digest == BM.canonical_sha256(ledger)
    assert any(BM.ALREADY_READ in problem for problem in BM.consume(reloaded, windows[0]))


# --- the match ---------------------------------------------------------------------------------

def test_a_read_of_the_pinned_bytes_matches_and_a_tampered_read_does_not():
    window = BM.binding_windows()[0]
    good = BM.match_window(window, _event(window))
    assert good['match'] and good['verified_event'] and good['problems'] == []
    assert good['observed_sha256'] == window['sha256'] == good['expected_sha256']
    bad = BM.match_window(window, _event(window, bytes_hex='00' * 16))
    assert bad['match'] is False
    assert any(BM.MISMATCH in problem for problem in bad['problems'])


def test_a_read_of_another_region_or_another_length_is_refused():
    window = BM.binding_windows()[0]
    other = BM.match_window(window, _event(window, region='ccp_device_gate'))
    assert other['match'] is False
    assert any(BM.WINDOW_NOT_IN_SET in problem for problem in other['problems'])
    short = BM.match_window(window, _event(window, bytes_hex=window['bytes_hex'][:16], length=8))
    assert short['match'] is False


def test_a_missing_event_never_matches():
    window = BM.binding_windows()[0]
    result = BM.match_window(window, None)
    assert result['match'] is False and result['verified_event'] is False


def test_the_wave_report_is_complete_only_when_every_window_matched():
    windows = BM.binding_windows()
    partial = BM.match_report(windows, [BM.match_window(windows[0], _event(windows[0]))])
    assert partial['complete'] is False and partial['matched'] == 1
    assert any(BM.SET_INCOMPLETE in problem for problem in partial['problems'])
    full = BM.match_report(windows, [BM.match_window(window, _event(window))
                                     for window in windows])
    assert full['complete'] is True and full['matched'] == 5 and full['problems'] == []
    one_bad = BM.match_report(windows, [BM.match_window(windows[0], _event(windows[0])),
                                        BM.match_window(windows[1], _event(windows[1],
                                                                           bytes_hex='11' * 16))]
                              + [BM.match_window(window, _event(window))
                                 for window in windows[2:]])
    assert one_bad['complete'] is False and one_bad['matched'] == 4
