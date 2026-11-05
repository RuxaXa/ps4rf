#!/usr/bin/env python3
"""W13 — the release gate and the released-window read path.

Owner decision (W13 read 1, option A): a *dedicated* release record names the ONE window a research
read may touch. These tests pin the whole gate offline:

* the reference record builds the pinned window and carries the release id
* every mutation of the record is refused with its own reason (state, region class, plan membership,
  hand-picked bytes, length, offset, sha256, profile, boot, section wording)
* a non-bootstrap window without a release id can never be read (``KREADLIVE_WINDOW_NOT_RELEASED``,
  zero provider entries)
* the frozen W12 bootstrap path is unchanged, and the stored evidence is still checked against the
  *bootstrap* window (A3 §1.12/1.13) while the read is about the released window
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.hostctl import kreadlive as KL                                    # noqa: E402
from tools.hostctl import kreadstore as KS                                   # noqa: E402
from tools.profiles import regions as R                                     # noqa: E402
from tools.profiles.schema import canonical_profile_sha256                   # noqa: E402
from tools.research import classification as C                              # noqa: E402
from tools.research import read_plan as RP                                  # noqa: E402
from tools.research import approval as AP                                   # noqa: E402
from tools.research import release as REL                                   # noqa: E402

PROFILE = C.DEFAULT_PROFILE
PROFILE_SHA = canonical_profile_sha256(PROFILE)
# W17F: the transcribed owner records on disk are HISTORICAL evidence. They keep the profile
# identity that was valid when they were recorded; only synthetic/current paths use PROFILE_SHA.
TRANSCRIBED_PROFILE_SHA = '4a6f575c8b1aa7906d7a86d08fe5cc4e5dc1a2939a2de19fac40c7fa82771766'
BOOT = 'BOOT-f0329415c5d8517d'
LOCATOR = C.profile_locator(PROFILE, 'kernel.attest.amd_iommu') or {}
BYTES_HEX = LOCATOR['expected_bytes']['hex']
BYTES_SHA = hashlib.sha256(bytes.fromhex(BYTES_HEX)).hexdigest()
RELEASE_PATH = pathlib.Path('/home/hermes/.hermes/cache/scratch/ps4rf-w13-c1/release-w13c1-read1.json')
APPROVAL_PATH = pathlib.Path('/home/hermes/.hermes/cache/scratch/ps4rf-w13-c1/approval-w13c1-read1.json')
HISTORICAL_RELEASE = pathlib.Path('/home/hermes/.hermes/cache/scratch/ps4rf-w13/'
                                  'release-w13-read1.json')
C1_PAYLOAD = json.loads(RELEASE_PATH.read_text())['payload'] if RELEASE_PATH.exists() else {}

#: a synthetic section 70 approval for the release tests: the release is always bound to one
APPROVAL = {'schema': AP.SCHEMA_APPROVAL, 'id': '70-REFERENCE', 'state': 'APPROVED',
            'approved': True, 'approver': 'owner', 'recorded_by': 'reference fixture',
            'read_scope': AP.READ_SCOPE_RESEARCH, 'profile_sha256': PROFILE_SHA, 'boot_id': BOOT,
            'verification_run_id': 'VRUN-reference', 'evidence_sha256': 'a' * 64}
APPROVAL_SHA = AP.approval_sha256(APPROVAL)


def reference_release(**over) -> dict:
    index = R.compiled_region_index('amd_iommu')
    assert index is not None, 'the compiled table must contain amd_iommu'
    document = REL.release_document(
        region='amd_iommu', offset=0, length=16, region_index=index, expected_bytes=BYTES_HEX,
        expected_sha256=BYTES_SHA, profile_sha256=PROFILE_SHA, boot_id=BOOT,
        release_id='W13-READ-1-LIVE-APPROVAL', module=LOCATOR['module'],
        section=LOCATOR['section'], permissions=LOCATOR['permissions'],
        classification=C.CLASS_APPROVED_READ, rva=hex(R.regions()['amd_iommu'].rva or 0),
        approval_sha256=APPROVAL_SHA)
    document.update(over)
    return document


def problems(document: dict) -> list[str]:
    return REL.release_problems(document, profile=PROFILE, profile_sha256=PROFILE_SHA, boot_id=BOOT,
                                approval_sha256=APPROVAL_SHA)


def reasons(document: dict) -> set[str]:
    return {problem.split(':', 1)[0] for problem in problems(document)}


# ===============================================================================================
# 1. the reference record and the transcribed owner release
# ===============================================================================================
def test_the_reference_release_builds_the_pinned_window():
    built = REL.released_window(reference_release(), profile=PROFILE, profile_sha256=PROFILE_SHA,
                               boot_id=BOOT)
    assert built['problems'] == []
    window = built['window']
    assert window['region'] == 'amd_iommu'
    assert window['offset'] == 0 and window['length'] == 16
    assert window['rva'] == 0x7CE9E9 and window['bytes_hex'] == BYTES_HEX
    assert window['sha256'] == BYTES_SHA
    assert window['release_id'] == 'W13-READ-1-LIVE-APPROVAL'
    assert window['problems'] == []


def test_the_transcribed_owner_records_are_accepted_and_pinned():
    """The two records on disk: separate documents, bound to each other (owner separation rule)."""
    assert RELEASE_PATH.exists() and APPROVAL_PATH.exists(), 'both records must be transcribed'
    approval = AP.load_approval(APPROVAL_PATH)
    document = REL.load_release(RELEASE_PATH)
    assert document['state'] == 'APPROVED' and 'approved' not in document
    assert AP.is_research_approval(approval) is True and 'window' not in approval
    assert AP.approval_problems(approval) == []
    approval_sha = AP.approval_sha256(approval)
    assert document['approval_sha256'] == approval_sha
    assert approval_sha != REL.release_sha256(document)
    built = REL.released_window(document, profile=PROFILE, profile_sha256=TRANSCRIBED_PROFILE_SHA, boot_id=BOOT,
                                approval_sha256=approval_sha)
    assert built['problems'] == []
    assert built['window']['bytes_hex'] == BYTES_HEX
    assert built['window']['release_id'] == document['release_id']
    assert built['window']['approval_sha256'] == approval_sha
    assert built['release']['region'] == 'amd_iommu'
    assert built['release']['expected_sha256'] == BYTES_SHA


def test_the_release_module_self_test_is_green():
    assert REL._self_test() == []


def test_a_wrong_compiled_index_in_the_release_is_refused():
    """W13-C1: the release pins the compiled table's row; a hand-picked index is refused."""
    document = REL.load_release(RELEASE_PATH)
    reference = list(REL.release_problems(
        document, profile=PROFILE, profile_sha256=TRANSCRIBED_PROFILE_SHA, boot_id=BOOT,
        approval_sha256=AP.approval_sha256(AP.load_approval(APPROVAL_PATH))))
    assert reference == [], reference
    compiled = R.compiled_region_index('amd_iommu')
    assert document['window']['region_index'] == compiled == 1
    for wrong in (0, 2, compiled + 1):
        mutated = dict(document, window=dict(document['window'], region_index=wrong))
        reasons = {p.split(':', 1)[0] for p in REL.release_problems(
            mutated, profile=PROFILE, profile_sha256=TRANSCRIBED_PROFILE_SHA, boot_id=BOOT,
            approval_sha256=AP.approval_sha256(AP.load_approval(APPROVAL_PATH)))}
        assert REL.RELEASE_INDEX_MISMATCH in reasons, (wrong, reasons)
    # a window block that names no index at all is a schema-level refusal (the field is required)
    without = dict(document, window={k: v for k, v in document['window'].items()
                                     if k != 'region_index'})
    reasons = {p.split(':', 1)[0] for p in REL.release_problems(
        without, profile=PROFILE, profile_sha256=TRANSCRIBED_PROFILE_SHA, boot_id=BOOT,
        approval_sha256=AP.approval_sha256(AP.load_approval(APPROVAL_PATH)))}
    assert REL.RELEASE_INVALID in reasons, reasons


def test_a_release_bound_to_another_payload_is_refused():
    """The new binding: a release for one build never authorises a run of another one."""
    document = REL.load_release(RELEASE_PATH)
    pinned = document['payload']
    assert REL.payload_problems(document, bin_sha256=pinned['bin_sha256'],
                                elf_sha256=pinned['elf_sha256'],
                                build_manifest_sha256=pinned['build_manifest_sha256']) == []
    for field in ('bin_sha256', 'elf_sha256', 'build_manifest_sha256'):
        problems = REL.payload_problems(document, bin_sha256=('0' * 64), elf_sha256=('0' * 64),
                                        build_manifest_sha256=('0' * 64))
        assert any(REL.RELEASE_PAYLOAD_MISMATCH in p for p in problems), (field, problems)
    # and a release that names half a payload is refused instead of half-checked
    broken = dict(document, payload={k: v for k, v in pinned.items() if k != 'elf_sha256'})
    problems = REL.payload_problems(broken, bin_sha256=pinned['bin_sha256'],
                                    elf_sha256=pinned['elf_sha256'],
                                    build_manifest_sha256=pinned['build_manifest_sha256'])
    assert any(REL.RELEASE_PAYLOAD_MISMATCH in p for p in problems), problems


def test_the_historical_read1_release_is_superseded_and_cannot_be_reissued():
    """The consumed W13 read-1 record stays historical evidence: no index, no payload binding."""
    if not HISTORICAL_RELEASE.exists():
        pytest.skip('the historical read-1 record is not present in this environment')
    historical = REL.load_release(HISTORICAL_RELEASE)
    assert historical['release_id'] == 'W13-READ-1-LIVE-APPROVAL'
    assert 'region_index' not in historical['window']
    reasons = {p.split(':', 1)[0] for p in REL.release_problems(
        historical, profile=PROFILE, profile_sha256=TRANSCRIBED_PROFILE_SHA, boot_id=BOOT,
        approval_sha256=historical['approval_sha256'])}
    assert REL.RELEASE_INVALID in reasons, reasons


# ===============================================================================================
# 2. every mutation is refused with its own reason
# ===============================================================================================
def test_a_release_must_be_approved():
    assert REL.RELEASE_NOT_APPROVED in reasons(reference_release(state='PENDING'))
    # the release never carries an approval flag: that field belongs to the separate 70 record
    assert REL.RELEASE_FORBIDDEN_FIELD in reasons(reference_release(approved=True))
    assert REL.RELEASE_FORBIDDEN_FIELD in reasons(reference_release(approval={'state': 'APPROVED'}))
    assert REL.RELEASE_FORBIDDEN_FIELD in reasons(reference_release(assurance='PROVEN'))
    assert REL.RELEASE_FORBIDDEN_FIELD in reasons(reference_release(
        capability_record={'name': 'kernel.read'}))


def test_a_malformed_release_is_refused():
    assert REL.RELEASE_INVALID in reasons({'state': 'APPROVED'})
    assert REL.RELEASE_INVALID in reasons(reference_release(window={'region': 'amd_iommu'}))
    assert REL.RELEASE_INVALID in reasons(reference_release(window=dict(
        reference_release()['window'], expected_bytes='zz', expected_sha256='00')))
    with pytest.raises(ValueError):
        REL.load_release('/nonexistent/release.json')


@pytest.mark.parametrize('name', ('image_elf', 'xfast_entry', 'boottime', 'aperture_global',
                                  'boottime_node', 'boottime_bintime'))
def test_only_approved_read_regions_can_be_released(name):
    """Identity-only, structural-only and unresolved regions can never be released."""
    document = reference_release()
    region = R.regions()[name]
    document['window'].update(region=name, offset=0,
                              length=region.length if region.length else 16)
    assert REL.RELEASE_REGION_NOT_APPROVED_READ in reasons(document), name


def test_a_region_outside_the_plan_cannot_be_released():
    assert REL.RELEASE_REGION_NOT_IN_PLAN in {
        problem.split(':', 1)[0]
        for problem in REL.release_problems(reference_release(), profile=PROFILE,
                                            profile_sha256=PROFILE_SHA, boot_id=BOOT,
                                            plan={'entries': []})}


def test_hand_picked_bytes_are_refused():
    document = reference_release()
    document['window']['expected_bytes'] = '00' * 16
    document['window']['expected_sha256'] = hashlib.sha256(bytes(16)).hexdigest()
    assert REL.RELEASE_BYTES_NOT_PINNED in reasons(document)


def test_a_different_length_is_refused():
    document = reference_release()
    document['window']['length'] = 8
    assert REL.RELEASE_LENGTH_MISMATCH in reasons(document) or \
        REL.RELEASE_WINDOW_MISMATCH in reasons(document)


def test_an_offset_outside_the_window_is_refused():
    document = reference_release()
    document['window']['offset'] = 4
    assert REL.RELEASE_WINDOW_MISMATCH in reasons(document)


def test_a_wrong_expected_sha256_is_refused():
    document = reference_release()
    document['window']['expected_sha256'] = 'ab' * 32
    assert REL.RELEASE_WINDOW_MISMATCH in reasons(document)


def test_a_wrong_profile_is_refused():
    assert REL.RELEASE_PROFILE_MISMATCH in reasons(reference_release(profile_sha256='b' * 64))


def test_a_wrong_boot_is_refused():
    assert REL.RELEASE_BOOT_MISMATCH in reasons(reference_release(expected_boot_id='BOOT-other'))


def test_a_contradicting_section_claim_is_refused():
    """The rodata/`text` lesson, now enforced for releases too."""
    assert REL.RELEASE_SECTION_MISMATCH in reasons(reference_release(section='rodata'))
    assert REL.RELEASE_SECTION_MISMATCH in reasons(reference_release(permissions='rw-'))
    assert REL.RELEASE_SECTION_MISMATCH in reasons(reference_release(module='userland'))
    assert REL.RELEASE_REGION_NOT_APPROVED_READ in reasons(
        reference_release(classification='IDENTITY_ONLY'))


# ===============================================================================================
# 3. the driver-side guard: no non-bootstrap window without a release
# ===============================================================================================
def seeded_store(tmp_path) -> KS.VerificationEvidenceStore:
    """A store holding a real phase-A record for the PINNED bootstrap window (sim machinery)."""
    profile, profile_sha = KL.synthetic_profile()
    binding = KL.synthetic_boot_binding(profile)
    store = KS.VerificationEvidenceStore(tmp_path / 'store')
    result = KL.run_verification(
        KL.OfflineSession(session_id=KL.SIM_SESSION_A,
                          event=KL.synthetic_bounded_event(runtime_kbase=KL.SIM_KBASE)),
        profile=profile, boot_binding=binding, store=store,
        provider=KL.sim_provider(live_approved=False),
        verification_run_id=KL.SIM_VERIFICATION_RUN, read_run_id=KL.SIM_BOOT_READ_RUN)
    assert result['outcome'] == KL.OUTCOME_VERIFIED, result['problems']
    return store


def test_a_non_bootstrap_window_without_a_release_id_cannot_be_read(tmp_path):
    """The guard: only the pinned bootstrap window or an owner-released window may be read."""
    store = seeded_store(tmp_path)
    profile, _sha = KL.synthetic_profile()
    binding = KL.synthetic_boot_binding(profile)
    unmarked = KL.window_for('code_anchor', bytes_hex='22' * 24, profile=profile)
    assert 'release_id' in unmarked and unmarked['release_id'] is None
    result = KL.run_generic_read(
        KL.OfflineSession(session_id=KL.SIM_SESSION_B,
                          event=KL.synthetic_bounded_event(region='code_anchor',
                                                           bytes_hex='22' * 24,
                                                           runtime_kbase=KL.SIM_KBASE)),
        profile=profile, boot_binding=binding, store=store,
        verification_run_id=KL.SIM_VERIFICATION_RUN, provider=KL.sim_provider(),
        approval=KL.SIM_APPROVAL, generic_read_run_id=KL.SIM_GENERIC_RUN, expected=unmarked)
    assert result['outcome'] == KL.OUTCOME_REFUSED
    assert result['provider_entries'] == 0 and result['generic_provider_entries'] == 0
    assert any(KL.KREADLIVE_WINDOW_NOT_RELEASED in str(problem)
               for problem in result['problems']), result['problems']


def test_the_released_window_is_the_only_extra_window_that_passes_the_guard(tmp_path):
    """Same window, now released: the guard is silent and the W12 chain is reached."""
    store = seeded_store(tmp_path)
    profile, _sha = KL.synthetic_profile()
    binding = KL.synthetic_boot_binding(profile)
    released = KL.window_for('code_anchor', bytes_hex='22' * 24, profile=profile,
                             release_id='SIM-RELEASE',
                             release_sha256=hashlib.sha256(b'SIM-RELEASE-DOC').hexdigest(),
                             approval_sha256=hashlib.sha256(b'SIM-APPROVAL').hexdigest())
    result = KL.run_generic_read(
        KL.OfflineSession(session_id=KL.SIM_SESSION_B,
                          event=KL.synthetic_bounded_event(region='code_anchor',
                                                           bytes_hex='22' * 24,
                                                           runtime_kbase=KL.SIM_KBASE)),
        profile=profile, boot_binding=binding, store=store,
        verification_run_id=KL.SIM_VERIFICATION_RUN, provider=KL.sim_provider(),
        approval=KL.SIM_APPROVAL, generic_read_run_id=KL.SIM_GENERIC_RUN, expected=released)
    assert not any(KL.KREADLIVE_WINDOW_NOT_RELEASED in str(problem)
                   for problem in result['problems']), result['problems']


# ===============================================================================================
# 4. the frozen bootstrap path and the evidence/proof split
# ===============================================================================================
def test_the_bootstrap_default_is_unchanged():
    profile, profile_sha = KL.synthetic_profile()
    pinned = KL.bootstrap_expectation(profile)
    assert pinned['region'] == 'image_elf' and pinned['offset'] == 0
    assert pinned['rva'] == 0 and pinned['length'] == 16
    assert pinned.get('release_id') is None      # the bootstrap window is never released
    assert profile_sha == canonical_profile_sha256(profile)


def test_the_derivation_checks_the_evidence_against_the_bootstrap_window(tmp_path):
    """A released window must not weaken A3: the stored evidence is still bootstrap-bound.

    The read below uses a *released* window while the store holds the pinned phase-A record; the
    evidence still has to satisfy the bootstrap expectation, so a store record for another window
    cannot authorise a release read.
    """
    store = seeded_store(tmp_path)
    profile, _sha = KL.synthetic_profile()
    binding = KL.synthetic_boot_binding(profile)
    evidence = store.load_verification(KL.SIM_VERIFICATION_RUN)
    assert evidence['region'] == 'image_elf'
    released = KL.window_for('code_anchor', bytes_hex='22' * 24, profile=profile,
                             release_id='SIM-RELEASE',
                             release_sha256=hashlib.sha256(b'SIM-RELEASE-DOC').hexdigest(),
                             approval_sha256=hashlib.sha256(b'SIM-APPROVAL').hexdigest())
    result = KL.run_generic_read(
        KL.OfflineSession(session_id=KL.SIM_SESSION_B,
                          event=KL.synthetic_bounded_event(region='code_anchor',
                                                           bytes_hex='22' * 24,
                                                           runtime_kbase=KL.SIM_KBASE)),
        profile=profile, boot_binding=binding, store=store,
        verification_run_id=KL.SIM_VERIFICATION_RUN, provider=KL.sim_provider(),
        approval=KL.SIM_APPROVAL, generic_read_run_id=KL.SIM_GENERIC_RUN, expected=released)
    # whatever the verdict, the bootstrap window is what the evidence was judged against: the
    # refusal must never be about the released region and the run must never silently rebind
    assert all(KL.KREADLIVE_WINDOW_NOT_RELEASED not in str(problem)
               for problem in result['problems']), result['problems']
    assert result['generic_provider_entries'] <= 1


# ===============================================================================================
# 5. the CLI keeps the frozen bootstrap behaviour when no release is given
# ===============================================================================================
def cli_args(tmp_path, **over):
    import argparse
    base = dict(w12_boot_id=BOOT, w12_store=str(tmp_path), w12_run_id=None,
                w12_verification_run_id='VRUN-ae918ffe023e9e9c', w12_live_approved=True,
                w12_approval=None, w13_release=None)
    base.update(over)
    return argparse.Namespace(**base)


def test_without_a_release_the_cli_keeps_the_frozen_bootstrap_behaviour(monkeypatch, tmp_path):
    from tools.hostctl import cli as CLI
    from tools.hostctl.evidence import RunRecord
    from tools.hostctl import kreadlive as KLMOD

    captured: dict = {}
    monkeypatch.setattr(KLMOD, 'run_phase', lambda phase, session, **kw: (
        captured.update(kw), {'ok': False, 'outcome': 'REFUSED', 'problems': [],
                              'provider_entries': 0, 'generic_provider_entries': 0})[1])
    rec = RunRecord(run_id='RUN-w13-cli-parity', mode='live', repo={}, payload={}, transport={})
    CLI.w12_phase_run(KL.OfflineSession(session_id='SES-w13cliparity000000000000000000000001',
                                        event=None), rec,
                      cli_args(tmp_path, w13_release=None, w12_approval=None),
                      phase=KLMOD.PHASE_READ)
    assert captured.get('expected') is None, 'the W12 path must keep passing no window'
    assert 'w13_release' not in rec.doc


def test_release_and_plan_agree_on_the_first_region():
    plan = RP.read_plan()
    assert plan['live_status'] == RP.LIVE_STATUS_NOT_RELEASED
    first = plan['entries'][0]
    assert first['region'] == 'amd_iommu'
    assert (first['offset'], first['length']) == (0, 16)
    assert first['expected_datatype'] and 'text' in first['expected_datatype']
