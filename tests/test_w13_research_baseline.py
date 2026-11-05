#!/usr/bin/env python3
"""W13 — read-only research baseline: the mandated regressions.

The owner's §12 list, plus the classification invariants that keep the baseline honest:

* ``IDENTITY_ONLY`` cannot be read generically (the W13 path refuses it; the frozen identity rules
  that own those regions stay untouched)
* ``APPROVED_READ`` can be read (plan entry, frozen rules, dataset, artifact)
* ``STRUCTURAL_ONLY`` is rejected by the research path
* ``UNRESOLVED`` is rejected everywhere, including by the frozen request model
* stale boot / wrong profile / missing VerificationEvidence are refused
* a pointer follow outside an approved target is refused (``UNRESOLVED_TARGET`` included)
* differential output has no authorisation effect (real W6 round trip, W4 impact NONE)
* dataset hashes are deterministic; duplicate snapshots deduplicate
* a raw runtime VA in the request is still refused

No live step: every case runs offline against the registry, a temporary dataset and temporary
artifacts.
"""
from __future__ import annotations

import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.hostctl import kreadlive as KL                                   # noqa: E402
from tools.hostctl import kreadstore as KS                                  # noqa: E402
from tools.profiles import kread as KR                                      # noqa: E402
from tools.profiles import regions as R                                     # noqa: E402
from tools.research import classification as C                              # noqa: E402
from tools.research import dataset as D                                     # noqa: E402
from tools.research import pointer_follow as P                              # noqa: E402
from tools.research import read_plan as RP                                  # noqa: E402
from tools.research import w6_contract as W6                                # noqa: E402

APPROVED = ('amd_iommu', 'gbase_vtophys', 'code_anchor', 'copyout_prologue', 'prison0_static')
IDENTITY_ONLY = ('image_elf', 'xfast_entry', 'boottime')
STRUCTURAL = ('aperture_global',)
UNRESOLVED = ('boottime_node', 'boottime_bintime')
KBASE = 0xFFFFFFFF998F4000

WM12_A2 = ('tests/test_w12a2_assurance_consistency.py',)
REGISTRY = R.regions()


# --- fixtures ----------------------------------------------------------------------------------
def bytes_for(region: R.Region) -> bytes:
    """Deterministic bytes for a synthetic research read of *region*."""
    length = min(region.length or 0, R.MAX_READ_LEN)
    return bytes((index * 7 + 3) & 0xFF for index in range(length))


def read_run_record(region: R.Region, *, bytes_value: bytes | None = None,
                    read_run_id: str = 'RUN-w13-test', outcome: str = 'READ',
                    separation: bool = True) -> dict:
    raw = bytes_for(region) if bytes_value is None else bytes_value
    import hashlib
    return {
        'schema': 'ps4rf.kread.read-run.v1',
        'read_run_id': read_run_id,
        'outcome': outcome,
        'provider_entries': 1,
        'run_separation': {'separated': separation, 'run_ids_distinct': separation,
                           'session_ids_distinct': separation},
        'read_evidence': {
            'schema': 'ps4rf.kread.read-evidence.v1',
            'requested_region': region.name,
            'requested_offset': 0,
            'requested_length': len(raw),
            'observed_length': len(raw),
            'bytes_hex': raw.hex(),
            'output_sha256': hashlib.sha256(raw).hexdigest(),
            'resolved_rva': 'UNMEASURED',
            'provider': {'name': KL.PROVIDER_NAME, 'provider_type': KL.PROVIDER_TYPE},
        },
    }


# ===============================================================================================
# 1. the classification and promotion policy
# ===============================================================================================
def test_the_matrix_covers_every_region_with_no_implicit_promotion():
    matrix = C.classification_matrix()
    assert C.classification_problems() == []
    assert {row['region'] for row in matrix['rows']} == set(REGISTRY)
    assert sum(matrix['counts'].values()) == len(REGISTRY)
    for row in matrix['rows']:
        if row['class'] == C.CLASS_APPROVED_READ:
            assert all(result['pass'] for result in row['criteria'].values()), row['region']
            assert row['review'] and row['review']['purpose'], row['region']


def test_approved_read_is_exactly_the_reviewed_five_in_registry_order():
    assert tuple(region.name for region in C.approved_read_regions()) == APPROVED


@pytest.mark.parametrize('name', IDENTITY_ONLY + STRUCTURAL + UNRESOLVED)
def test_only_approved_read_regions_appear_in_the_plan(name):
    entry_names = {entry['region'] for entry in RP.read_plan()['entries']}
    assert name not in entry_names
    assert C.classify(REGISTRY[name]) != C.CLASS_APPROVED_READ


@pytest.mark.parametrize('name', IDENTITY_ONLY + STRUCTURAL + UNRESOLVED)
def test_the_research_path_refuses_every_non_approved_region(tmp_path, name):
    """Plan, dataset and W6 artifact all refuse; only APPROVED_READ may produce an artifact."""
    region = REGISTRY[name]
    assert name not in {entry['region'] for entry in RP.read_plan()['entries']}
    dataset = D.ResearchDataset(tmp_path)
    with pytest.raises(D.DatasetError):
        dataset.add_read(read_run_record=read_run_record(region), region_name=name, kbase=KBASE,
                         profile_sha256='a' * 64, boot_id='BOOT-w13')
    with pytest.raises(W6.ContractError):
        W6.read_inventory(read_run_record=read_run_record(region), region_name=name)


def test_identity_only_regions_keep_their_frozen_identity_role():
    """The identity windows stay readable *as identity*: W13 only keeps them out of research."""
    for name in IDENTITY_ONLY:
        region = REGISTRY[name]
        if name == 'boottime':
            assert region.identity_status == R.IDENTITY_STRICT
            assert R.may_read(region)          # the W11.2 binding path is unchanged
        else:
            assert R.may_read(region)
        assert C.classify(region) == C.CLASS_IDENTITY_ONLY


def test_structural_only_stays_structural_only_and_is_never_a_fingerprint():
    region = REGISTRY['aperture_global']
    assert C.classify(region) == C.CLASS_STRUCTURAL_ONLY
    assert not R.is_strict_source(region)
    assert 'aperture_global' in C.KNOWN_UNSTABLE
    row = {r['region']: r for r in C.classification_matrix()['rows']}['aperture_global']
    assert row['criteria']['no_known_instability']['pass'] is False


@pytest.mark.parametrize('name', UNRESOLVED)
def test_unresolved_regions_are_refused_everywhere(name):
    region = REGISTRY[name]
    assert C.classify(region) == C.CLASS_UNRESOLVED
    assert not R.may_read(region)
    # the schema gate accepts the *shape* (four keys); the region model refuses the region
    KR.parse_request({'operation': 'kernel.read', 'region': name, 'offset': 0, 'length': 8})
    with pytest.raises(KR.KReadReject) as excinfo:
        R.resolve_read(name, 0, 8)
    assert excinfo.value.reason == KR.KREAD_UNRESOLVED_REGION


@pytest.mark.parametrize('name', APPROVED)
def test_approved_read_regions_can_be_read(tmp_path, name):
    region = REGISTRY[name]
    assert C.classify(region) == C.CLASS_APPROVED_READ
    assert R.may_read(region)
    resolved = R.resolve_read(name, 0, min(region.length or 0, R.MAX_READ_LEN))
    assert resolved.region.name == name
    dataset = D.ResearchDataset(tmp_path)
    added = dataset.add_read(read_run_record=read_run_record(region), region_name=name,
                             kbase=KBASE, profile_sha256='a' * 64, boot_id='BOOT-w13',
                             timestamp='2026-10-06T00:00:00Z')
    assert added['added'] and not added['deduplicated']
    document = W6.read_inventory(read_run_record=read_run_record(region), region_name=name)
    assert document['entries'][0]['locator'] == {'kind': 'rva', 'value': region.rva}
    assert dataset.problems() == []


def test_the_plan_never_releases_itself_and_carries_no_address():
    plan = RP.read_plan()
    assert plan['live_status'] == RP.LIVE_STATUS_NOT_RELEASED
    assert RP.plan_problems(plan) == []
    blob = json.dumps(plan)
    for forbidden in ('runtime_va', '"address"', '"slide"', 'kbase'):
        assert forbidden not in blob
    assert plan['entries'][0]['region'] == 'amd_iommu'         # the owner's priority A
    assert {entry['region'] for entry in plan['entries']} == set(APPROVED)


def test_the_plan_entries_stay_inside_their_regions():
    for entry in RP.read_plan()['entries']:
        region = REGISTRY[entry['region']]
        assert entry['offset'] == 0
        assert entry['length'] == min(region.length or 0, R.MAX_READ_LEN)
        assert entry['length'] <= entry['max_length'] <= R.MAX_READ_LEN
        assert entry['offset'] + entry['length'] <= (region.length or 0)
        assert entry['purpose'] and entry['expected_datatype'] and entry['why_read_safe']


# ===============================================================================================
# 2. the bindings a read still needs (unchanged from W12)
# ===============================================================================================
def _seeded_store(tmp_path):
    from tools.hostctl import kreadlive as KL2
    store = KS.VerificationEvidenceStore(tmp_path)
    profile, profile_sha = KL2.synthetic_profile()
    binding = KL2.synthetic_boot_binding(profile)
    result = KL2.run_verification(
        KL2.OfflineSession(session_id=KL2.SIM_SESSION_A,
                           event=KL2.synthetic_bounded_event(runtime_kbase=KL2.SIM_KBASE)),
        profile=profile, boot_binding=binding, store=store,
        provider=KL2.sim_provider(live_approved=False),
        verification_run_id=KL2.SIM_VERIFICATION_RUN, read_run_id=KL2.SIM_BOOT_READ_RUN)
    assert result['outcome'] == KL2.OUTCOME_VERIFIED, result['problems']
    return store, profile, profile_sha, binding


def test_a_stale_boot_is_refused():
    """The derivation refuses an evidence record of another boot (the load-bearing check)."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        store, profile, profile_sha, binding = _seeded_store(tmp)
        evidence = store.load_verification(KL.SIM_VERIFICATION_RUN)
        with pytest.raises(KL.DerivationRejected) as excinfo:
            KL.derive_capability_record(
                store, evidence_sha256=evidence['evidence_sha256'],
                read_run_id=KL.SIM_GENERIC_RUN, profile_sha256=profile_sha,
                boot_id='BOOT-' + '0' * 16, provider=KL.sim_provider(), context=KL.CONTEXT,
                session_id=KL.SIM_SESSION_B, approval=None,
                expected=KL.bootstrap_expectation(profile))
        assert excinfo.value.reason == 'KREAD_STALE_BOOT_ID'


def test_a_wrong_profile_is_refused():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        store, profile, _profile_sha, _binding = _seeded_store(tmp)
        evidence = store.load_verification(KL.SIM_VERIFICATION_RUN)
        with pytest.raises(KL.DerivationRejected) as excinfo:
            KL.derive_capability_record(
                store, evidence_sha256=evidence['evidence_sha256'],
                read_run_id=KL.SIM_GENERIC_RUN, profile_sha256='b' * 64,
                boot_id=_binding.boot_id, provider=KL.sim_provider(), context=KL.CONTEXT,
                session_id=KL.SIM_SESSION_B, approval=None,
                expected=KL.bootstrap_expectation(profile))
        assert excinfo.value.reason == 'KREAD_WRONG_PROFILE'


def test_a_missing_verification_evidence_is_refused(tmp_path):
    store = KS.VerificationEvidenceStore(tmp_path)
    profile, profile_sha = KL.synthetic_profile()
    binding = KL.synthetic_boot_binding(profile)
    result = KL.run_generic_read(
        KL.OfflineSession(session_id=KL.SIM_SESSION_B, event=KL.synthetic_bounded_event()),
        profile=profile, boot_binding=binding, store=store,
        verification_run_id=KL.SIM_VERIFICATION_RUN, provider=KL.sim_provider(),
        approval=KL.SIM_APPROVAL, generic_read_run_id=KL.SIM_GENERIC_RUN,
        expected=KL.bootstrap_expectation(profile))
    assert result['outcome'] == KL.OUTCOME_REFUSED
    assert result['provider_entries'] == 0
    assert any('EVIDENCE' in problem or 'STORE' in problem for problem in result['problems'])


# ===============================================================================================
# 3. bounded pointer follow
# ===============================================================================================
SOURCE = {'read_run_id': 'RUN-w13-test', 'region': 'prison0_static', 'sha256': 'ab' * 32}


@pytest.mark.parametrize('name', STRUCTURAL + IDENTITY_ONLY)
def test_a_pointer_follow_into_a_non_approved_target_is_refused(name):
    region = REGISTRY[name]
    region_rva = region.rva
    assert region_rva is not None
    with pytest.raises(P.PointerFollowRefused) as excinfo:
        P.evaluate(pointer_value=KBASE + region_rva, pointer_source=SOURCE, kbase=KBASE)
    assert excinfo.value.reason == P.REASON_TARGET_NOT_APPROVED


def test_a_pointer_that_maps_nowhere_is_an_unresolved_target_and_stops():
    with pytest.raises(P.PointerFollowRefused) as excinfo:
        P.evaluate(pointer_value=0x1000, pointer_source=SOURCE, kbase=KBASE)
    assert excinfo.value.reason == P.REASON_UNRESOLVED_TARGET


def test_a_pointer_from_a_non_approved_read_is_refused():
    with pytest.raises(P.PointerFollowRefused) as excinfo:
        P.evaluate(pointer_value=0x1000,
                   pointer_source={'read_run_id': 'RUN-x', 'region': 'image_elf'}, kbase=KBASE)
    assert excinfo.value.reason == P.REASON_SOURCE_NOT_APPROVED


def test_a_non_canonical_pointer_is_refused():
    with pytest.raises(P.PointerFollowRefused) as excinfo:
        P.evaluate(pointer_value=0x600000000000, pointer_source=SOURCE, kbase=KBASE)
    assert excinfo.value.reason == P.REASON_NOT_CANONICAL


def test_a_follow_produces_a_candidate_request_not_a_read():
    target = REGISTRY['code_anchor']
    follow = P.evaluate(pointer_value=KBASE + target.rva, pointer_source=SOURCE, kbase=KBASE,
                        expected_class='code')
    assert follow['automatic'] is False
    assert follow['candidate_request']['region'] == 'code_anchor'
    assert follow['candidate_request']['length'] <= R.MAX_READ_LEN
    assert 'its own live approval' in follow['requires']
    assert P.policy_problems() == []


# ===============================================================================================
# 4. dataset determinism and the W6 integration
# ===============================================================================================
def test_dataset_hashes_are_deterministic_across_insertion_order(tmp_path):
    region_a, region_b = REGISTRY['amd_iommu'], REGISTRY['code_anchor']
    first, second = D.ResearchDataset(tmp_path / 'one'), D.ResearchDataset(tmp_path / 'two')
    for dataset in (first, second):
        for region in (region_a, region_b):
            dataset.add_read(read_run_record=read_run_record(region), region_name=region.name,
                             kbase=KBASE, profile_sha256='a' * 64, boot_id='BOOT-w13',
                             timestamp='2026-10-06T00:00:00Z')
    assert first.index_sha256() == second.index_sha256()
    assert first.problems() == [] and second.problems() == []
    blobs = sorted(path.name for path in first.blob_root.iterdir())
    assert blobs == [entry['sha256'] for entry in sorted(first.index()['snapshots'],
                                                         key=lambda item: item['sha256'])]


def test_duplicate_snapshots_deduplicate(tmp_path):
    region = REGISTRY['amd_iommu']
    dataset = D.ResearchDataset(tmp_path)
    first = dataset.add_read(read_run_record=read_run_record(region), region_name=region.name,
                             kbase=KBASE, profile_sha256='a' * 64, boot_id='BOOT-w13',
                             timestamp='2026-10-06T00:00:00Z')
    second = dataset.add_read(read_run_record=read_run_record(region), region_name=region.name,
                              kbase=KBASE, profile_sha256='a' * 64, boot_id='BOOT-w13',
                              timestamp='2026-10-06T00:00:09Z')
    assert first['added'] is True and second['deduplicated'] is True
    assert len(dataset.index()['snapshots']) == 1
    assert len(list(dataset.blob_root.iterdir())) == 1
    assert dataset.problems() == []


def test_a_read_run_without_separation_proof_is_not_archived(tmp_path):
    region = REGISTRY['amd_iommu']
    dataset = D.ResearchDataset(tmp_path)
    with pytest.raises(D.DatasetError):
        dataset.add_read(read_run_record=read_run_record(region, separation=False),
                         region_name=region.name, kbase=KBASE, profile_sha256='a' * 64,
                         boot_id='BOOT-w13')
    with pytest.raises(D.DatasetError):
        dataset.add_read(read_run_record=read_run_record(region, outcome='REFUSED'),
                         region_name=region.name, kbase=KBASE, profile_sha256='a' * 64,
                         boot_id='BOOT-w13')


def test_a_sensitive_window_is_flagged_never_expanded(tmp_path):
    region = REGISTRY['amd_iommu']
    dataset = D.ResearchDataset(tmp_path)
    marker = b'password=1234567'          # 16 bytes: exactly the amd_iommu window
    record = read_run_record(region, bytes_value=marker)
    record['read_evidence']['observed_length'] = len(marker)
    record['read_evidence']['requested_length'] = len(marker)
    added = dataset.add_read(read_run_record=record, region_name=region.name, kbase=KBASE,
                             profile_sha256='a' * 64, boot_id='BOOT-w13')
    assert added['snapshot']['sensitive_review_required'] is True
    assert added['snapshot']['sensitive_hints']
    assert dataset.problems() == []


def test_the_differential_output_has_no_authorization_effect(tmp_path):
    region = REGISTRY['amd_iommu']
    before_record = read_run_record(region, read_run_id='RUN-before')
    after_record = read_run_record(region, read_run_id='RUN-after',
                                   bytes_value=bytes((index * 5 + 1) & 0xFF
                                                     for index in range(region.length or 0)))
    before = W6.read_inventory(read_run_record=before_record, region_name=region.name)
    after = W6.read_inventory(read_run_record=after_record, region_name=region.name)
    before_path, after_path = tmp_path / 'before.json', tmp_path / 'after.json'
    W6.write_inventory(before_path, before)
    W6.write_inventory(after_path, after)

    plan_before = RP.read_plan()
    classes_before = {row['region']: row['class']
                      for row in C.classification_matrix()['rows']}
    report = W6.run_differential(before_path, after_path)
    candidates = W6.candidates_of(report)
    assert W6.artifact_differences(before, after)
    assert candidates, 'a real difference must produce an observation'
    for candidate in candidates:
        assert candidate['status'] == 'OBSERVATION'
        assert candidate['impact']['w4'] == 'NONE'
    assert RP.read_plan() == plan_before
    assert {row['region']: row['class'] for row in C.classification_matrix()['rows']} \
        == classes_before
    assert W6.contract_problems() == []


def test_the_artifact_carries_no_boot_or_address_field():
    region = REGISTRY['code_anchor']
    document = W6.read_inventory(read_run_record=read_run_record(region), region_name=region.name)
    blob = json.dumps(document)
    for forbidden in W6.FORBIDDEN_IN_ARTIFACT:
        assert f'"{forbidden}"' not in blob
    assert document['entries'][0]['locator']['kind'] == 'rva'


# ===============================================================================================
# 5. the frozen request rules still hold
# ===============================================================================================
@pytest.mark.parametrize('key', ('address', 'addr', 'va', 'pointer'))
def test_a_raw_runtime_va_in_the_request_is_still_refused(key):
    """Every key the request model calls an address is refused as an address."""
    assert KR.is_raw_address_key(key)
    with pytest.raises(KR.KReadReject) as excinfo:
        KR.parse_request({'operation': 'kernel.read', 'region': 'amd_iommu', 'offset': 0,
                          'length': 8, key: 0xFFFFFFFF998F4000})
    assert excinfo.value.reason == KR.KREAD_SCHEMA_RAW_ADDRESS, key


@pytest.mark.parametrize('key', ('runtime_va', 'runtime_address', 'kernel_address', 'ksa',
                                 'kaddr', 'offset_address'))
def test_similar_address_names_are_refused_as_unknown_keys(key):
    """Names the model does not know are refused too -- there is no address field to reach."""
    with pytest.raises(KR.KReadReject) as excinfo:
        KR.parse_request({'operation': 'kernel.read', 'region': 'amd_iommu', 'offset': 0,
                          'length': 8, key: 0xFFFFFFFF998F4000})
    assert excinfo.value.reason == KR.KREAD_SCHEMA_UNKNOWN_KEY, key
    assert 'address' not in KR.KReadRequest.__dataclass_fields__


def test_the_w13_path_keeps_the_region_window_bounds():
    region = REGISTRY['code_anchor']
    assert region.length is not None
    with pytest.raises(KR.KReadReject):
        R.resolve_read('code_anchor', 0, region.length + 1)
    with pytest.raises(KR.KReadReject):
        R.resolve_read('code_anchor', -1, 8)
    assert R.registry_problems() == []


# ===============================================================================================
# 6. section / permission consistency (the pre-live check for the first research region)
# ==============================================================================================
PINNED_AMD_IOMMU_BYTES = '414d4420494f4d4d5500696f6d6d7520'          # profile expected_bytes
PINNED_AMD_IOMMU_SHA256 = '0e5db66bb6e045a242282881beb9525d80f00efdccd3586da7d2692e74d4cc5f'
PINNED_IMAGE_SHA256 = 'cf157ffdbae872a20bbb9a46c8518b53d96c1ed75d4e73878466a295d92eca35'


def test_amd_iommu_pinned_facts_are_unambiguous():
    """Every value below comes from the pinned artifacts; nothing is invented here.

    profile locator ``kernel.attest.amd_iommu`` + the W9 attest table entry for the same rva; the
    expected sha256 is the hash of the profile's pinned bytes (byte-verified against the pinned
    FW13.52 image ``kernel.bin`` sha256 cf157ffd...).
    """
    locator = C.profile_locator(C.DEFAULT_PROFILE, 'kernel.attest.amd_iommu')
    assert locator is not None
    assert locator['module'] == 'kernel'
    assert locator['section'] == 'text'
    assert locator['permissions'] == 'r-x'
    assert locator['policy'] == 'STRICT_FINGERPRINT'
    assert locator['locator'] == {'kind': 'rva', 'value': 0x7CE9E9}
    assert locator['expected_bytes'] == {'hex': PINNED_AMD_IOMMU_BYTES, 'offset': 0}
    assert locator['provenance']['source'].find('kernel.bin') >= 0
    assert locator['provenance']['sha256'] == PINNED_IMAGE_SHA256
    import hashlib
    assert hashlib.sha256(bytes.fromhex(PINNED_AMD_IOMMU_BYTES)).hexdigest() == \
        PINNED_AMD_IOMMU_SHA256
    attest = C.ATTEST['amd_iommu']
    assert (attest['rva'], attest['length'], attest['kind'], attest['policy']) == \
        (0x7CE9E9, 16, 'static', 'strict')
    region = REGISTRY['amd_iommu']
    assert (region.rva, region.length) == (0x7CE9E9, 16)
    assert region.locator == 'kernel.attest.amd_iommu'


def test_amd_iommu_is_never_described_as_rodata():
    """The pinned section is ``text`` with ``r-x``: the wording must not claim rodata."""
    decision = C.REVIEW_DECISIONS['amd_iommu']
    blob = ' '.join((decision.expected_datatype, decision.purpose, decision.rationale)).lower()
    assert 'rodata' not in blob
    assert 'text' in decision.expected_datatype and 'r-x' in decision.expected_datatype
    entry = [item for item in RP.read_plan()['entries'] if item['region'] == 'amd_iommu'][0]
    assert 'rodata' not in json.dumps(entry).lower()
    assert entry['permissions'] == 'r-x'
    assert C.datatype_section_conflict(REGISTRY['amd_iommu'], decision.expected_datatype) is None


def test_no_decision_or_plan_text_contradicts_the_pinned_section():
    """Every region: the text may only name the section the pinned profile declares."""
    for name, region in REGISTRY.items():
        decision = C.REVIEW_DECISIONS.get(name)
        if decision is not None:
            text = ' '.join((decision.expected_datatype, decision.purpose, decision.rationale))
            assert C.datatype_section_conflict(region, text) is None, name
    for entry in RP.read_plan()['entries']:
        text = ' '.join((entry['expected_datatype'], entry['purpose'], entry['why_read_safe']))
        assert C.datatype_section_conflict(REGISTRY[entry['region']], text) is None, entry['region']


def test_the_section_rule_goes_red_on_a_contradiction():
    """The rule is load bearing: a rodata claim on a text region must be caught."""
    region = REGISTRY['amd_iommu']
    assert C.datatype_section_conflict(region, 'rodata string window') is not None
    assert C.datatype_section_conflict(region, 'window in the text segment') is None
    assert C.datatype_section_conflict(REGISTRY['prison0_static'], 'data window') is None
    assert C.datatype_section_conflict(REGISTRY['prison0_static'], 'text prologue') is not None


# ===============================================================================================
# 7. the modules' own self-tests
# ===============================================================================================
def test_every_w13_module_self_test_is_green():
    assert C._self_test() == []
    assert RP._self_test() == []
    assert D._self_test() == []
    assert P._self_test() == []
    assert W6._self_test() == []
