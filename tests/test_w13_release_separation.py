#!/usr/bin/env python3
"""W13 — trust-object separation and one-shot semantics for the first research read.

Owner ruling (W13 review): the section 70 approval and the W13 research release are **two trust
objects**:

* the approval answers *"may the already verified ``kernel.read`` provider run at all in this run?"*
  (existing approval schema/contract, :mod:`tools.research.approval`);
* the release answers *"which concrete research window may be read exactly once?"*
  (:mod:`tools.research.release`), bound to the approval by ``approval_sha256``.

The mandated regressions, one test each:

1. approval valid + release valid -> eligible
2. approval missing -> reject
3. release missing (research approval) -> reject
4. W13 release handed in as the approval -> schema reject
5. approval handed in as the W13 release -> schema reject
6. wrong ``approval_sha256`` in the release -> reject
7. already consumed release -> reject
8. stale boot -> reject
9. wrong profile -> reject
10. wrong region/window -> reject
11. provider entry = 0 on every refusal

plus the one-shot policy: consumed at the provider entry, never twice; a refusal *before* that
consumes nothing; a damaged consumption marker is invalid (never "not consumed").
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

from tools.hostctl import cli as CLI                                        # noqa: E402
from tools.hostctl import kreadlive as KL                                   # noqa: E402
from tools.hostctl import kreadstore as KS                                  # noqa: E402
from tools.profiles import regions as R                                      # noqa: E402
from tools.profiles.schema import canonical_profile_sha256                  # noqa: E402
from tools.research import approval as AP                                   # noqa: E402
from tools.research import classification as C                              # noqa: E402
from tools.research import release as REL                                   # noqa: E402

PROFILE = C.DEFAULT_PROFILE
PROFILE_SHA = canonical_profile_sha256(PROFILE)
# W17F: the transcribed owner records on disk are HISTORICAL evidence. They keep the profile
# identity that was valid when they were recorded; only synthetic/current paths use PROFILE_SHA.
TRANSCRIBED_PROFILE_SHA = '4a6f575c8b1aa7906d7a86d08fe5cc4e5dc1a2939a2de19fac40c7fa82771766'
LOCATOR = C.profile_locator(PROFILE, 'kernel.attest.amd_iommu') or {}
BYTES_HEX = LOCATOR['expected_bytes']['hex']
BYTES_SHA = hashlib.sha256(bytes.fromhex(BYTES_HEX)).hexdigest()
RVA = 0x7CE9E9
KBASE = KL.SIM_KBASE
BOOT = 'BOOT-w13-separation'
VRUN = 'VRUN-w13-separation'
RELEASE_ID = 'W13-SEPARATION-TEST'
APPROVAL_ID = '70-W13-SEPARATION-TEST'


# --- fixtures ---------------------------------------------------------------------------------
def seeded_store(root: pathlib.Path) -> tuple[KS.VerificationEvidenceStore, dict]:
    """A store holding a real phase-A record for the pinned bootstrap window (offline machinery)."""
    store = KS.VerificationEvidenceStore(root / 'store')
    session_id = 'SES-w13sep0000000000000000000000000001'
    result = KL.run_verification(
        KL.OfflineSession(session_id=session_id,
                          event=KL.synthetic_bounded_event(runtime_kbase=KBASE)),
        profile=PROFILE, boot_binding=KL.BootBinding(boot_id=BOOT, profile_sha256=PROFILE_SHA),
        store=store, provider=KL.sim_provider(live_approved=False),
        verification_run_id=VRUN, read_run_id='RUN-w13-separation-boot')
    assert result['outcome'] == KL.OUTCOME_VERIFIED, result['problems']
    return store, store.load_verification(VRUN)


def approval_document(evidence: dict, **over) -> dict:
    document = {'schema': AP.SCHEMA_APPROVAL, 'id': APPROVAL_ID, 'state': 'APPROVED',
                'approved': True, 'approver': 'owner',
                'recorded_by': 'offline separation test transcription',
                'read_scope': AP.READ_SCOPE_RESEARCH, 'profile_sha256': PROFILE_SHA, 'boot_id': BOOT,
                'verification_run_id': VRUN,
                'evidence_sha256': KS.canonical_evidence_sha256(evidence)}
    document.update(over)
    return document


def release_document(approval: dict, **over) -> dict:
    # W13-C1: the release pins the compiled table's row for the region -- derived, never guessed
    index = R.compiled_region_index('amd_iommu')
    assert index is not None, 'the compiled table must contain amd_iommu'
    document = REL.release_document(
        release_id=RELEASE_ID, region='amd_iommu', offset=0, length=16, region_index=index,
        expected_bytes=BYTES_HEX, expected_sha256=BYTES_SHA, profile_sha256=PROFILE_SHA,
        boot_id=BOOT, approval_sha256=AP.approval_sha256(approval), module=LOCATOR['module'],
        section=LOCATOR['section'], permissions=LOCATOR['permissions'],
        classification=C.CLASS_APPROVED_READ, rva=hex(RVA), notes=['offline separation test'])
    document.update(over)
    return document


def write(tmp_path: pathlib.Path, name: str, document: dict) -> str:
    path = pathlib.Path(tmp_path) / name
    path.write_text(json.dumps(document, indent=1, sort_keys=True))
    return str(path)


def context(tmp_path: pathlib.Path, *, approval_path=None, release_path=None, **over) -> argparse.Namespace:
    base = dict(mode='listen', w12_read_run=True, w12_verify_run=False, w12_boot_id=BOOT,
                w12_store=str(pathlib.Path(tmp_path) / 'store'),
                w12_run_id=None, w12_verification_run_id=VRUN, w12_live_approved=True,
                w12_rearm_confirmed=True, w12_approval=approval_path, w13_release=release_path)
    base.update(over)
    return argparse.Namespace(**base)


def refused_by_preflight(config: argparse.Namespace, reason: str) -> str:
    with pytest.raises(SystemExit) as excinfo:
        CLI.w12_preflight(config)
    message = str(excinfo.value)
    assert reason in message, message
    return message


def rehearsal_window(release: dict, approval: dict) -> dict:
    built = REL.released_window(release, profile=PROFILE, profile_sha256=PROFILE_SHA, boot_id=BOOT,
                                approval_sha256=AP.approval_sha256(approval))
    assert built['problems'] == [], built['problems']
    return built['window']


# ===============================================================================================
# 1. approval valid + release valid -> eligible
# ===============================================================================================
def test_a_valid_approval_and_a_valid_release_are_eligible(tmp_path):
    store, evidence = seeded_store(tmp_path)
    approval = approval_document(evidence)
    release = release_document(approval)
    config = context(tmp_path, approval_path=write(tmp_path, 'a.json', approval),
                     release_path=write(tmp_path, 'r.json', release))
    resolved = CLI.w12_preflight(config)
    assert resolved['expected_window']['region'] == 'amd_iommu'
    assert resolved['expected_window']['release_id'] == RELEASE_ID
    assert resolved['w13_release']['approval_sha256'] == AP.approval_sha256(approval)
    assert resolved['w12_approval']['id'] == APPROVAL_ID
    assert resolved['w12_approval']['sha256'] == AP.approval_sha256(approval)
    # the two records are distinct objects with distinct hashes
    assert AP.approval_sha256(approval) != REL.release_sha256(release)


# ===============================================================================================
# 2./3. a missing half is a refusal
# ===============================================================================================
def test_a_missing_approval_is_refused(tmp_path):
    store, evidence = seeded_store(tmp_path)
    approval = approval_document(evidence)
    release = release_document(approval)
    refused_by_preflight(context(tmp_path, release_path=write(tmp_path, 'r.json', release)),
                         'W13_RELEASE_APPROVAL_MISSING')
    # and on the phase path: refused, zero provider entries, the driver is never reached
    result = phase_run_result(tmp_path, approval_path=None,
                              release_path=write(tmp_path, 'r2.json', release))
    assert result['outcome'] == 'REFUSED' and result['generic_provider_entries'] == 0
    assert any('W13_RELEASE_APPROVAL_MISSING' in str(problem) for problem in result['problems'])


def test_a_missing_release_is_refused_for_a_research_approval(tmp_path):
    store, evidence = seeded_store(tmp_path)
    approval = approval_document(evidence)
    refused_by_preflight(context(tmp_path, approval_path=write(tmp_path, 'a.json', approval)),
                         'W13_RELEASE_REQUIRED')
    result = phase_run_result(tmp_path, approval_path=write(tmp_path, 'a2.json', approval),
                              release_path=None)
    assert result['outcome'] == 'REFUSED' and result['generic_provider_entries'] == 0
    assert any('W13_RELEASE_REQUIRED' in str(problem) for problem in result['problems'])


# ===============================================================================================
# 4./5. either record handed in for the other is a schema refusal
# ===============================================================================================
def test_a_release_handed_in_as_the_approval_is_refused(tmp_path):
    store, evidence = seeded_store(tmp_path)
    approval = approval_document(evidence)
    release = release_document(approval)
    release_path = write(tmp_path, 'r.json', release)
    # the same file in both slots is a separation violation
    refused_by_preflight(context(tmp_path, approval_path=release_path, release_path=release_path),
                         'W13_RELEASE_APPROVAL_NOT_SEPARATE')
    # the release in the approval slot fails the approval schema
    refused_by_preflight(context(tmp_path, approval_path=release_path,
                                 release_path=write(tmp_path, 'r2.json', release)),
                         'W12_APPROVAL_SCHEMA_INVALID')


def test_an_approval_handed_in_as_the_release_is_refused(tmp_path):
    store, evidence = seeded_store(tmp_path)
    approval = approval_document(evidence)
    approval_path = write(tmp_path, 'a.json', approval)
    refused_by_preflight(context(tmp_path, approval_path=approval_path,
                                 release_path=approval_path),  # same file: not separate
                         'W13_RELEASE_APPROVAL_NOT_SEPARATE')
    other = write(tmp_path, 'a2.json', approval)
    refused_by_preflight(context(tmp_path, approval_path=approval_path, release_path=other),
                         'W13_RELEASE_INVALID')


# ===============================================================================================
# 6. cross binding: release A + approval B -> refuse
# ===============================================================================================
def test_a_release_bound_to_another_approval_is_refused(tmp_path):
    store, evidence = seeded_store(tmp_path)
    approval = approval_document(evidence)
    stranger = approval_document(evidence, id='70-W13-OTHER')
    release = release_document(approval)
    document = json.loads(json.dumps(release))
    document['approval_sha256'] = AP.approval_sha256(stranger)
    refused_by_preflight(context(tmp_path, approval_path=write(tmp_path, 'a.json', approval),
                                 release_path=write(tmp_path, 'r.json', document)),
                         'W13_RELEASE_APPROVAL_MISMATCH')
    # a release that names its own hash as the approval is refused too
    document['approval_sha256'] = REL.release_sha256(document)
    refused_by_preflight(context(tmp_path, approval_path=write(tmp_path, 'a2.json', approval),
                                 release_path=write(tmp_path, 'r2.json', document)),
                         'W13_RELEASE_APPROVAL_MISMATCH')
    # a release without any binding is refused
    document.pop('approval_sha256')
    refused_by_preflight(context(tmp_path, approval_path=write(tmp_path, 'a3.json', approval),
                                 release_path=write(tmp_path, 'r3.json', document)),
                         'W13_RELEASE_APPROVAL_BINDING_MISSING')


# ===============================================================================================
# 7. one-shot: consumed release -> refuse, zero provider entries, never consumable twice
# ===============================================================================================
def test_the_release_is_consumed_at_the_provider_entry_and_never_twice(tmp_path):
    store, evidence = seeded_store(tmp_path)
    approval = approval_document(evidence)
    release = release_document(approval)
    window = rehearsal_window(release, approval)

    first = KL.run_generic_read(
        KL.OfflineSession(session_id='SES-w13sep0000000000000000000000000002',
                          event=KL.synthetic_bounded_event(region='amd_iommu', bytes_hex=BYTES_HEX,
                                                           runtime_kbase=KBASE)),
        profile=PROFILE, boot_binding=KL.BootBinding(boot_id=BOOT, profile_sha256=PROFILE_SHA),
        store=store, verification_run_id=VRUN, provider=KL.sim_provider(), approval=approval,
        generic_read_run_id='RUN-w13-separation-read', expected=window)
    assert first['outcome'] == KL.OUTCOME_READ, first['problems']
    assert first['provider_entries'] == 1 and first['generic_provider_entries'] == 1
    marker = store.load_release_consumption(RELEASE_ID)
    assert marker is not None and marker['consumed'] is True
    assert marker['consumed_at'] == 'provider_entry'
    assert marker['read_run_id'] == 'RUN-w13-separation-read'
    assert marker['approval_sha256'] == AP.approval_sha256(approval)
    assert (pathlib.Path(tmp_path) / 'store' / 'releases' / f'{RELEASE_ID}.json').exists()

    # the second attempt in the same store (and in the same process) reaches nothing
    KL._CONSUMED_RELEASES.pop(RELEASE_ID, None)          # simulate a fresh process, same store
    second = KL.run_generic_read(
        KL.OfflineSession(session_id='SES-w13sep0000000000000000000000000003',
                          event=KL.synthetic_bounded_event(region='amd_iommu', bytes_hex=BYTES_HEX,
                                                           runtime_kbase=KBASE)),
        profile=PROFILE, boot_binding=KL.BootBinding(boot_id=BOOT, profile_sha256=PROFILE_SHA),
        store=store, verification_run_id=VRUN, provider=KL.sim_provider(), approval=approval,
        generic_read_run_id='RUN-w13-separation-read-2', expected=window)
    assert second['outcome'] == KL.OUTCOME_REFUSED
    assert second['provider_entries'] == 0 and second['generic_provider_entries'] == 0
    assert any(KL.KREADLIVE_RELEASE_ALREADY_CONSUMED in str(problem)
               for problem in second['problems']), second['problems']

    # ... and the preflight refuses it as well
    refused_by_preflight(context(tmp_path, approval_path=write(tmp_path, 'a.json', approval),
                                 release_path=write(tmp_path, 'r.json', release)),
                         'W13_RELEASE_ALREADY_CONSUMED')


def test_a_released_region_with_a_different_returned_index_is_refused(tmp_path):
    """W13-C1: release amd_iommu (compiled index 1) while the payload served row 0.

    This is the first live W13 read replayed offline: the request named the released row, the
    payload reported image_elf -- the host must refuse, keep no read evidence and persist no
    window, and exactly one provider entry may have happened.
    """
    store, evidence = seeded_store(tmp_path)
    approval = approval_document(evidence)
    release = release_document(approval, release_id='W13-C1-ROW-0-REPLAY')
    window = rehearsal_window(release, approval)
    assert window['region_index'] == 1, window
    store.load_release_consumption  # noqa: B018 - the marker path is asserted below
    result = KL.run_generic_read(
        KL.OfflineSession(session_id='SES-w13sep0000000000000000000000000006',
                          event=KL.synthetic_bounded_event(
                              region='image_elf', bytes_hex='7f454c46020101090000000000000000',
                              region_index_override=0, runtime_kbase=KBASE)),
        profile=PROFILE, boot_binding=KL.BootBinding(boot_id=BOOT, profile_sha256=PROFILE_SHA),
        store=store, verification_run_id=VRUN, provider=KL.sim_provider(), approval=approval,
        generic_read_run_id='RUN-w13-c1-wrong-row', expected=window)
    assert result['outcome'] == KL.OUTCOME_REFUSED
    assert result['read_evidence'] is None and result['read_run_record'] is None
    assert result['provider_entries'] == 1, result['provider_entries']
    problems = ' '.join(str(p) for p in result['problems'])
    assert KL.KREADLIVE_REGION_MISMATCH in problems, problems
    marker = store.load_release_consumption('W13-C1-ROW-0-REPLAY')
    assert marker is not None and marker['consumed'] is True
    assert marker['consumed_at'] == 'provider_entry'


def test_a_payload_that_reports_the_wrong_index_for_the_right_region_is_refused(tmp_path):
    """The row id and the row index are two claims: neither may disagree with the release."""
    store, evidence = seeded_store(tmp_path)
    approval = approval_document(evidence)
    release = release_document(approval, release_id='W13-C1-WRONG-INDEX')
    window = rehearsal_window(release, approval)
    result = KL.run_generic_read(
        KL.OfflineSession(session_id='SES-w13sep0000000000000000000000000007',
                          event=KL.synthetic_bounded_event(
                              region='amd_iommu', bytes_hex=BYTES_HEX, region_index_override=0,
                              runtime_kbase=KBASE)),
        profile=PROFILE, boot_binding=KL.BootBinding(boot_id=BOOT, profile_sha256=PROFILE_SHA),
        store=store, verification_run_id=VRUN, provider=KL.sim_provider(), approval=approval,
        generic_read_run_id='RUN-w13-c1-wrong-index', expected=window)
    assert result['outcome'] == KL.OUTCOME_REFUSED
    assert result['read_evidence'] is None
    problems = ' '.join(str(p) for p in result['problems'])
    assert KL.KREADLIVE_REGION_INDEX_MISMATCH in problems, problems


def test_the_released_row_reads_and_verifies_with_the_matching_index(tmp_path):
    """Positive control: the same phase with the released row and the matching index is a READ."""
    store, evidence = seeded_store(tmp_path)
    approval = approval_document(evidence)
    release = release_document(approval, release_id='W13-C1-RIGHT-INDEX')
    window = rehearsal_window(release, approval)
    result = KL.run_generic_read(
        KL.OfflineSession(session_id='SES-w13sep0000000000000000000000000008',
                          event=KL.synthetic_bounded_event(region='amd_iommu', bytes_hex=BYTES_HEX,
                                                           runtime_kbase=KBASE)),
        profile=PROFILE, boot_binding=KL.BootBinding(boot_id=BOOT, profile_sha256=PROFILE_SHA),
        store=store, verification_run_id=VRUN, provider=KL.sim_provider(), approval=approval,
        generic_read_run_id='RUN-w13-c1-right-row', expected=window)
    assert result['outcome'] == KL.OUTCOME_READ, result['problems']
    report = result['event_report']
    assert report['requested_region_index'] == window['region_index'] == 1, report
    assert not any(KL.KREADLIVE_REGION_INDEX_MISMATCH in str(p) for p in result['problems'])
    assert result['read_evidence'] is not None


def test_a_refusal_before_the_provider_entry_consumes_nothing(tmp_path):
    store, evidence = seeded_store(tmp_path)
    approval = approval_document(evidence)
    release = release_document(approval, expected_boot_id='BOOT-somewhere-else')
    refused_by_preflight(context(tmp_path, approval_path=write(tmp_path, 'a.json', approval),
                                 release_path=write(tmp_path, 'r.json', release)),
                         'W13_RELEASE_BOOT_MISMATCH')
    assert store.load_release_consumption(RELEASE_ID) is None
    assert not (pathlib.Path(tmp_path) / 'store' / 'releases').exists()


def test_a_damaged_consumption_marker_is_never_not_consumed(tmp_path):
    store, evidence = seeded_store(tmp_path)
    approval = approval_document(evidence)
    release = release_document(approval)
    window = rehearsal_window(release, approval)
    marker = KS.build_consumption_record(
        release_id=RELEASE_ID, release_sha256=window['release_sha256'],
        approval_sha256=AP.approval_sha256(approval), profile_sha256=PROFILE_SHA, boot_id=BOOT,
        read_run_id='RUN-w13-separation-read', read_session_id='SES-w13sep0')
    store.store_release_consumption(marker)
    path = pathlib.Path(tmp_path) / 'store' / 'releases' / f'{RELEASE_ID}.json'
    document = json.loads(path.read_text())
    document['read_run_id'] = 'RUN-tampered'
    path.write_text(json.dumps(document, indent=1, sort_keys=True))
    with pytest.raises(KS.StoreError) as excinfo:
        store.load_release_consumption(RELEASE_ID)
    assert KS.W13_RELEASE_CONSUMPTION_INVALID in str(excinfo.value)
    refused_by_preflight(context(tmp_path, approval_path=write(tmp_path, 'a.json', approval),
                                 release_path=write(tmp_path, 'r.json', release)),
                         'W13_RELEASE_CONSUMPTION_INVALID')


def test_a_consumption_write_failure_never_allows_a_second_read(tmp_path, monkeypatch):
    store, evidence = seeded_store(tmp_path)
    approval = approval_document(evidence)
    release = release_document(approval)
    window = rehearsal_window(release, approval)
    KL._CONSUMED_RELEASES.pop(RELEASE_ID, None)

    def broken(record):
        raise KS.StoreError(KS.STORE_UNREADABLE, 'store is read-only in this test')

    monkeypatch.setattr(store, 'store_release_consumption', broken)
    first = KL.run_generic_read(
        KL.OfflineSession(session_id='SES-w13sep0000000000000000000000000004',
                          event=KL.synthetic_bounded_event(region='amd_iommu', bytes_hex=BYTES_HEX,
                                                           runtime_kbase=KBASE)),
        profile=PROFILE, boot_binding=KL.BootBinding(boot_id=BOOT, profile_sha256=PROFILE_SHA),
        store=store, verification_run_id=VRUN, provider=KL.sim_provider(), approval=approval,
        generic_read_run_id='RUN-w13-separation-broken-store', expected=window)
    assert first['outcome'] == KL.OUTCOME_REFUSED
    assert first['provider_entries'] == 0 and first['generic_provider_entries'] == 0
    assert any(KL.KREADLIVE_RELEASE_CONSUMPTION_FAILED in str(problem)
               for problem in first['problems']), first['problems']
    assert KL._CONSUMED_RELEASES.get(RELEASE_ID) is not None      # spent for this process
    monkeypatch.undo()
    second = KL.run_generic_read(
        KL.OfflineSession(session_id='SES-w13sep0000000000000000000000000005',
                          event=KL.synthetic_bounded_event(region='amd_iommu', bytes_hex=BYTES_HEX,
                                                           runtime_kbase=KBASE)),
        profile=PROFILE, boot_binding=KL.BootBinding(boot_id=BOOT, profile_sha256=PROFILE_SHA),
        store=store, verification_run_id=VRUN, provider=KL.sim_provider(), approval=approval,
        generic_read_run_id='RUN-w13-separation-after-failure', expected=window)
    assert second['outcome'] == KL.OUTCOME_REFUSED and second['provider_entries'] == 0
    assert any(KL.KREADLIVE_RELEASE_ALREADY_CONSUMED in str(problem)
               for problem in second['problems']), second['problems']


# ===============================================================================================
# 8./9./10. stale boot, wrong profile, wrong window -> refuse
# ===============================================================================================
def test_a_stale_boot_is_refused(tmp_path):
    store, evidence = seeded_store(tmp_path)
    approval = approval_document(evidence)
    release = release_document(approval)
    # a rebooted console: the approval is checked first, the release refuses anyway -- both are
    # boot-mismatch refusals and both happen before anything is contacted
    message = refused_by_preflight(
        context(tmp_path, approval_path=write(tmp_path, 'a.json', approval),
                release_path=write(tmp_path, 'r.json', release), w12_boot_id='BOOT-rebooted'),
        'KREAD_STALE_BOOT_ID')
    assert 'W13_RELEASE_BOOT_MISMATCH' in message or 'KREAD_STALE_BOOT_ID' in message
    assert store.load_release_consumption(RELEASE_ID) is None
    stale_approval = approval_document(evidence, boot_id='BOOT-rebooted')
    refused_by_preflight(context(tmp_path, approval_path=write(tmp_path, 'a2.json', stale_approval),
                                 release_path=write(tmp_path, 'r2.json', release_document(stale_approval))),
                         'KREAD_STALE_BOOT_ID')
    stale_release = release_document(approval, expected_boot_id='BOOT-rebooted')
    refused_by_preflight(context(tmp_path, approval_path=write(tmp_path, 'a3.json', approval),
                                 release_path=write(tmp_path, 'r3.json', stale_release)),
                         'W13_RELEASE_BOOT_MISMATCH')


def test_a_wrong_profile_is_refused(tmp_path):
    store, evidence = seeded_store(tmp_path)
    approval = approval_document(evidence)
    release = release_document(approval)
    assert REL.RELEASE_PROFILE_MISMATCH in {
        problem.split(':', 1)[0] for problem in REL.release_problems(
            release, profile=PROFILE, profile_sha256='b' * 64, boot_id=BOOT,
            approval_sha256=AP.approval_sha256(approval))}
    assert AP.APPROVAL_PROFILE_MISMATCH in {
        problem.split(':', 1)[0] for problem in AP.approval_problems(
            approval, profile_sha256='b' * 64, boot_id=BOOT, verification_run_id=VRUN,
            evidence_sha256=KS.canonical_evidence_sha256(evidence))}
    wrong = approval_document(evidence, profile_sha256='b' * 64)
    refused_by_preflight(context(tmp_path, approval_path=write(tmp_path, 'a.json', wrong),
                                 release_path=write(tmp_path, 'r.json', release)),
                         'KREAD_WRONG_PROFILE')


@pytest.mark.parametrize('mutation,reason', [
    ({'window': 'bytes'}, REL.RELEASE_BYTES_NOT_PINNED),
    ({'window': 'length'}, REL.RELEASE_LENGTH_MISMATCH),
    ({'window': 'offset'}, REL.RELEASE_WINDOW_MISMATCH),
    ({'window': 'sha'}, REL.RELEASE_WINDOW_MISMATCH),
    ({'window': 'region'}, REL.RELEASE_REGION_NOT_APPROVED_READ),
    ({'section': 'rodata'}, REL.RELEASE_SECTION_MISMATCH),
    ({'rva': '0x1000'}, REL.RELEASE_WINDOW_MISMATCH),
    ({'assurance': 'PROVEN'}, REL.RELEASE_FORBIDDEN_FIELD),
    ({'capability': {'name': 'kernel.read'}}, REL.RELEASE_FORBIDDEN_FIELD),
])
def test_a_wrong_window_or_authorisation_claim_is_refused(tmp_path, mutation, reason):
    store, evidence = seeded_store(tmp_path)
    approval = approval_document(evidence)
    release = release_document(approval)
    document = json.loads(json.dumps(release))
    if 'window' in mutation:
        what = mutation['window']
        if what == 'bytes':
            document['window']['expected_bytes'] = '00' * 16
            document['window']['expected_sha256'] = hashlib.sha256(bytes(16)).hexdigest()
        elif what == 'length':
            document['window']['length'] = 8
        elif what == 'offset':
            document['window']['offset'] = 4
        elif what == 'sha':
            document['window']['expected_sha256'] = 'ab' * 32
        elif what == 'region':
            document['window']['region'] = 'xfast_entry'
            document['window']['offset'] = 0
            document['window']['length'] = 16
    else:
        document.update(mutation)
    reasons = {problem.split(':', 1)[0] for problem in REL.release_problems(
        document, profile=PROFILE, profile_sha256=PROFILE_SHA, boot_id=BOOT,
        approval_sha256=AP.approval_sha256(approval))}
    assert reason in reasons, sorted(reasons)
    refused_by_preflight(context(tmp_path, approval_path=write(tmp_path, 'a.json', approval),
                                 release_path=write(tmp_path, 'r.json', document)),
                         reason)


# ===============================================================================================
# 11. provider entry == 0 on every refusal (and the driver is never reached)
# ===============================================================================================
def phase_run_result(tmp_path, *, approval_path, release_path, **over):
    """Run the CLI phase path with the driver stubbed out: it must never be reached."""
    from tools.hostctl.evidence import RunRecord

    calls: list = []

    def spy(*args, **kwargs):
        calls.append(kwargs)
        return {'ok': False, 'outcome': 'REFUSED', 'problems': ['stub'], 'provider_entries': 0,
                'generic_provider_entries': 0}

    original = KL.run_phase
    KL.run_phase = spy
    try:
        rec = RunRecord(run_id='RUN-w13-separation-phase', mode='live', repo={}, payload={},
                        transport={})
        result = CLI.w12_phase_run(KL.OfflineSession(session_id=KL.SIM_SESSION_B, event=None), rec,
                                   context(tmp_path, approval_path=approval_path,
                                           release_path=release_path, **over),
                                   phase=KL.PHASE_READ)
    finally:
        KL.run_phase = original
    result = dict(result)
    result['driver_called'] = bool(calls)
    return result


def test_every_refusal_keeps_the_provider_entry_at_zero(tmp_path):
    store, evidence = seeded_store(tmp_path)
    approval = approval_document(evidence)
    release = release_document(approval)
    approval_path = write(tmp_path, 'a.json', approval)
    release_path = write(tmp_path, 'r.json', release)
    cases = {
        'approval missing': (None, release_path, {}),
        'release missing': (approval_path, None, {}),
        'same file': (release_path, release_path, {}),
        'approval as release': (approval_path, approval_path, {}),
        'stale boot': (approval_path, release_path, {'w12_boot_id': 'BOOT-rebooted'}),
    }
    for label, (approval_arg, release_arg, over) in cases.items():
        result = phase_run_result(tmp_path, approval_path=approval_arg, release_path=release_arg,
                                  **over)
        assert result['outcome'] == 'REFUSED', label
        assert result['generic_provider_entries'] == 0, label
        assert result['driver_called'] is False, label
        assert store.load_release_consumption(RELEASE_ID) is None, label
    # a release bound to a stranger is refused as well
    stranger = approval_document(evidence, id='70-W13-OTHER')
    document = json.loads(json.dumps(release))
    document['approval_sha256'] = AP.approval_sha256(stranger)
    result = phase_run_result(tmp_path, approval_path=approval_path,
                              release_path=write(tmp_path, 'stranger.json', document))
    assert result['outcome'] == 'REFUSED' and result['generic_provider_entries'] == 0
    assert result['driver_called'] is False
    assert any('W13_RELEASE_APPROVAL_MISMATCH' in str(p) for p in result['problems'])


# ===============================================================================================
# the CLI surface itself (no sockets, no upload)
# ===============================================================================================
def test_both_flags_exist_on_the_live_and_listen_surface():
    import subprocess
    for mode in ('live', 'listen'):
        proc = subprocess.run([sys.executable, str(REPO_ROOT / 'tools/hostctl/cli.py'), mode,
                               '--help'], capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr
        assert '--w13-release' in proc.stdout
        assert '--w12-approval' in proc.stdout


def test_the_reference_records_on_disk_are_separate_and_bound():
    """The transcribed owner records: separate documents, separate hashes, correct binding."""
    W13C1 = pathlib.Path('/home/hermes/.hermes/cache/scratch/ps4rf-w13-c1')
    approval_path = W13C1 / 'approval-w13c1-read1.json'
    release_path = W13C1 / 'release-w13c1-read1.json'
    if not (approval_path.exists() and release_path.exists()):
        pytest.skip('the transcribed records are not present in this environment')
    approval = AP.load_approval(approval_path)
    release = REL.load_release(release_path)
    assert approval['schema'] == AP.SCHEMA_APPROVAL
    assert release['schema'] == REL.SCHEMA_RELEASE
    assert AP.is_research_approval(approval) is True
    assert hashlib.sha256(approval_path.read_bytes()).hexdigest() != \
        hashlib.sha256(release_path.read_bytes()).hexdigest()
    assert AP.approval_sha256(approval) != REL.release_sha256(release)
    assert release['approval_sha256'] == AP.approval_sha256(approval)
    assert AP.approval_problems(approval) == []
    assert REL.release_problems(release, profile=PROFILE, profile_sha256=TRANSCRIBED_PROFILE_SHA,
                                boot_id=approval['boot_id'],
                                approval_sha256=AP.approval_sha256(approval)) == []
    assert 'window' not in approval, 'the approval must not name a window'
    assert 'approved' not in release, 'the release must not carry an approval flag'
