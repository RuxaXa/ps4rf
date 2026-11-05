#!/usr/bin/env python3
"""W12-A-D1 pinned regressions: the *compiled target table* vs the *policy registry*.

Deviation ``W12-A-D1`` -- ``COMPILED_REGION_COUNT_COMPARED_TO_POLICY_REGISTRY_TOTAL``,
disposition ``HOST_VERIFIER_BUG`` -- refused the live phase A evidence because the verifier
compared the payload's compiled region count (9) against the policy registry total (11,
including the two entries ``native/target/gen_kread_regions.py`` refuses by design).

Every test here pins one half of the fix, so the masking cannot come back:

* the normative source ``regions.compiled_regions()`` -- count, order and index mapping;
* the fail-closed invariants (duplicate entry, incomplete target entry, empty table);
* the live verifier's check -- 9 accepted, 8 and 11 refused;
* the payload-reported index/rva/length against the *compiled* table;
* the simulation, which must feed the check through the same production path.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.hostctl import kreadlive as KL                                    # noqa: E402
from tools.profiles import regions                                           # noqa: E402
from tools.profiles.kread import KREAD_TABLE_INVALID, KReadReject               # noqa: E402

PROFILE, PROFILE_SHA = KL.synthetic_profile()
BINDING = KL.synthetic_boot_binding(PROFILE)
PINNED = KL.bootstrap_expectation(PROFILE)
COMPILED = regions.compiled_regions()
POLICY_TOTAL = len(regions.regions())


def repaired_event(**overrides) -> dict:
    """One payload-shaped event whose table fields are the ones the live payload reports."""
    kwargs = {'region_count': len(COMPILED)}
    kwargs.update(overrides)
    return KL.synthetic_bounded_event(**kwargs)


def table_check(report: dict) -> dict:
    checks = {entry['name']: entry for entry in report['checks']}
    return checks['generated_table_matches_registry']


# --------------------------------------------------------------- the normative source

def test_compiled_table_is_fifteen_while_the_policy_registry_has_seventeen():
    """The frozen numbers of this deviation: the compiled table is the policy registry minus
    the UNRESOLVED entries refused by design.

    W12 pinned 9 compiled + 2 refused = 11 policy. W16 adds six CCP/keymgr binding windows
    (five STRICT + the keymgr slot pool STRUCTURAL_ONLY); Track A adds the five read-only
    observation windows of docs/P4-A-OBSERVATION-WINDOWS.md (STRUCTURAL_ONLY, never identity
    sources). So the live numbers are 20 + 2 = 22 and the relation -- compiled = policy -
    refused_by_design -- is unchanged.
    """
    assert POLICY_TOTAL == 22
    assert len(COMPILED) == 20
    assert POLICY_TOTAL - len(COMPILED) == 2
    assert len(regions.compiled_region_names()) == 20


def test_no_unresolved_entry_reaches_the_compiled_table():
    compiled_names = set(regions.compiled_region_names())
    for name, region in regions.regions().items():
        if region.identity_status == regions.IDENTITY_UNRESOLVED:
            assert name not in compiled_names, f'{name} must never be compiled'
        else:
            assert name in compiled_names, f'{name} must be compiled'
    assert not [region for region in COMPILED
                if region.identity_status == regions.IDENTITY_UNRESOLVED]


def test_every_compiled_region_is_registered_and_complete():
    registered = regions.regions()
    for region in COMPILED:
        assert region.name in registered
        assert region.identity_status != regions.IDENTITY_UNRESOLVED
        assert isinstance(region.rva, int) and isinstance(region.length, int)
        assert region.rva >= 0 and region.length >= 1
        assert region.policy in regions.POLICY_VALUES
        assert region.provenance
        assert regions.may_read(region)


def test_the_compiled_order_is_the_registry_order_minus_the_refused_entries():
    expected = tuple(name for name, region in regions.regions().items()
                     if region.identity_status != regions.IDENTITY_UNRESOLVED)
    assert regions.compiled_region_names() == expected
    assert regions.compiled_table_problems() == []


def test_indices_are_compiled_indices_not_policy_indices():
    for index, region in enumerate(COMPILED):
        assert regions.compiled_region_index(region.name) == index
    assert regions.compiled_region_index('image_elf') == 0
    assert regions.compiled_region_index('boottime') == 8
    # the refused-by-design entries have no target index at all
    assert regions.compiled_region_index('boottime_node') is None
    assert regions.compiled_region_index('boottime_bintime') is None
    assert regions.compiled_region_index('not_a_region') is None


# --------------------------------------------------------------- verification of the live shape

def test_the_live_shaped_event_passes_with_the_compiled_count():
    """The exact live event shape (the compiled count of the current table) must verify."""
    report = KL.verify_bounded_event(repaired_event(), profile=PROFILE, expected=PINNED)
    check = table_check(report)
    assert check['ok'] is True
    assert f'compiled={len(COMPILED)}' in check['detail']
    assert report['verified'] is True
    assert report['problems'] == []


@pytest.mark.parametrize('wrong_count', [8, 9, 11])
def test_recorded_wrong_counts_from_the_deviation_are_refused(wrong_count):
    """The historical wrong values stay refused: 8 = W12 'one below' the then-compiled 9,
    9 = the W12 compiled count, 11 = the W12 policy total. All of them are wrong for the
    current 15-row table too -- the check is against the *compiled* table, never a constant."""
    assert wrong_count != len(COMPILED)
    report = KL.verify_bounded_event(repaired_event(region_count=wrong_count), profile=PROFILE,
                                     expected=PINNED)
    check = table_check(report)
    assert check['ok'] is False
    assert check['reason'] == KL.KREADLIVE_TABLE_MISMATCH
    assert report['verified'] is False
    assert f'region_count={wrong_count}' in check['detail']
    assert f'{KL.KREADLIVE_TABLE_MISMATCH}: ' in report['problems'][0]


def test_reported_policy_total_and_neighbours_are_refused():
    """The pre-fix bug in the other direction: the policy total (and one around the compiled
    count) must not be accepted either."""
    for wrong_count in (POLICY_TOTAL, len(COMPILED) - 1, len(COMPILED) + 1):
        assert wrong_count != len(COMPILED)
        report = KL.verify_bounded_event(repaired_event(region_count=wrong_count),
                                         profile=PROFILE, expected=PINNED)
        check = table_check(report)
        assert check['ok'] is False, wrong_count
        assert check['reason'] == KL.KREADLIVE_TABLE_MISMATCH, wrong_count
        assert report['verified'] is False, wrong_count
        assert f'compiled={len(COMPILED)}' in check['detail'], wrong_count


def test_a_wrong_region_count_also_breaks_the_byteeness_check_of_the_live_pack():
    """Same shape as the deviation pack: the compiled count expected, the policy total reported
    by a stale host expectation."""
    live_event = repaired_event()
    assert live_event['region_count'] == len(COMPILED)
    stale_expectation = len(regions.regions())
    assert stale_expectation == POLICY_TOTAL == 22
    assert live_event['region_count'] != stale_expectation      # the deviation, pinned


# --------------------------------------------------------------- payload claims vs the table

def test_payload_region_index_mismatch_is_refused():
    event = repaired_event(region='copyout_prologue')
    assert event['requested_region_index'] == 5                  # compiled index of that region
    event['requested_region_index'] = 6                          # policy index it would report
    report = KL.verify_bounded_event(event, profile=PROFILE, expected=None)
    checks = {entry['name']: entry for entry in report['checks']}
    assert checks['region_index_matches_registry_order']['ok'] is False
    assert checks['region_index_matches_registry_order']['reason'] == KL.KREADLIVE_TABLE_MISMATCH
    assert report['verified'] is False


def test_payload_rva_mismatch_is_refused():
    event = repaired_event(region='amd_iommu')
    entry = regions.get_region('amd_iommu')
    event['region_rva'] = KL.u64_hex(int(entry.rva) + 1)          # not the compiled rva
    report = KL.verify_bounded_event(event, profile=PROFILE, expected=None)
    checks = {entry_['name']: entry_ for entry_ in report['checks']}
    assert checks['region_rva_matches_registry']['ok'] is False
    assert report['verified'] is False


def test_payload_length_mismatch_is_refused():
    event = repaired_event(region='amd_iommu', length=8)
    event['requested_length'] = '16'                              # rva/length pair disagrees
    report = KL.verify_bounded_event(event, profile=PROFILE, expected=None)
    checks = {entry['name']: entry for entry in report['checks']}
    assert checks['offset_length_sum_matches_checked_add']['ok'] is False
    assert report['verified'] is False


# --------------------------------------------------------------- fail-closed invariants

def make_region(name: str, *, identity=regions.IDENTITY_STRICT, rva=4096, length=16,
                policy=regions.POLICY_APPROVED_BOUNDED_RESEARCH,
                provenance=('tools/profiles/regions.py',)):
    return regions.Region(name=name, rva=rva, length=length, identity_status=identity,
                          policy=policy, provenance=provenance, locator='kernel.attest.test',
                          profile_requirement='the active profile', notes='test entry')


def test_duplicate_region_fails_closed():
    duplicate = [make_region('a_region'), make_region('a_region')]
    with pytest.raises(KReadReject) as exc:
        regions.compiled_regions(duplicate)
    assert exc.value.reason == KREAD_TABLE_INVALID
    assert 'twice' in str(exc.value)
    assert regions.compiled_table_problems(duplicate)


def test_incomplete_target_entry_fails_closed():
    for incomplete in (make_region('missing_rva', rva=None),
                       make_region('missing_length', length=None),
                       make_region('no_provenance', provenance=())):
        with pytest.raises(KReadReject) as exc:
            regions.compiled_regions([incomplete, make_region('healthy')])
        assert exc.value.reason == KREAD_TABLE_INVALID
        assert regions.compiled_table_problems([incomplete, make_region('healthy')])


def test_a_table_without_a_single_readable_region_fails_closed():
    only_refused = [make_region('refused', identity=regions.IDENTITY_UNRESOLVED, rva=None,
                               length=None, policy=regions.POLICY_NOT_APPROVED)]
    with pytest.raises(KReadReject) as exc:
        regions.compiled_regions(only_refused)
    assert exc.value.reason == KREAD_TABLE_INVALID
    assert regions.compiled_table_problems(only_refused)


def test_unresolved_entries_between_compiled_entries_do_not_shift_indices():
    """A refused entry may sit anywhere in the policy registry without moving target indices."""
    interleaved = [
        make_region('first'),
        make_region('refused_middle', identity=regions.IDENTITY_UNRESOLVED, rva=None, length=None,
                    policy=regions.POLICY_NOT_APPROVED),
        make_region('second'),
        make_region('refused_tail', identity=regions.IDENTITY_UNRESOLVED, rva=None, length=None,
                    policy=regions.POLICY_NOT_APPROVED),
        make_region('third'),
    ]
    assert regions.compiled_region_names(interleaved) == ('first', 'second', 'third')
    assert regions.compiled_region_index('second', interleaved) == 1
    assert regions.compiled_region_index('third', interleaved) == 2
    assert regions.compiled_region_index('refused_middle', interleaved) is None
    assert regions.compiled_table_problems(interleaved) == []
    # and the production table keeps the same invariant
    assert regions.compiled_region_index('copyout_prologue') == 5
    assert [region.name for region in regions.compiled_regions()[:6]] == \
        ['image_elf', 'amd_iommu', 'gbase_vtophys', 'code_anchor', 'xfast_entry',
         'copyout_prologue']


# --------------------------------------------------------------- the simulation must not mask it

def test_the_simulation_uses_the_same_production_path_as_the_live_check():
    simulated = KL.synthetic_bounded_event()
    assert simulated['region_count'] == len(regions.compiled_regions()) == len(COMPILED)
    assert simulated['region_count'] != len(regions.regions())
    report = KL.verify_bounded_event(simulated, profile=PROFILE, expected=PINNED)
    assert table_check(report)['ok'] is True


def test_the_offline_run_still_reports_a_verified_phase_a():
    result = KL.run_offline_simulation()
    assert result['ok'] is True
    assert result['accepted_contract_met'] is True
    assert result['blocker'] is None
    assert result['phase_b']['provider_entries'] == 1


# ------------------------------------------- W16: the binding windows reach the module by index
#
# The module (`native/target/ps4rf_kread.c`) may not spell the CCP/keymgr row names: the
# subsystem scan in ``build_manifest.gate_kread`` reads that file case-insensitively for
# ``ccp``/``keymgr`` and would refuse the artefact. So the generator emits the five indices
# under neutral names and the module addresses the windows through them. This is the pinned
# half of that rule: the alias must exist, be indices only, point at exactly the five STRICT
# windows of the revision candidate, and stay neutral itself.

CANDIDATE = 'profiles/fw1352/profile-13.52-ccp1.json'
REGIONS_HEADER = REPO_ROOT / 'native' / 'target' / 'ps4rf_kread_regions.h'


def _binding_alias(header: str) -> tuple[int | None, list[int]]:
    """(declared count, indices in order) from the generated header; (None, []) when absent."""
    count: int | None = None
    indices: dict[int, int] = {}
    for line in header.splitlines():
        if not line.startswith('#define PS4RF_KREAD_BINDING_WINDOW'):
            continue
        _, name, value = line.split()
        assert value.endswith('u'), f'{name} must be an unsigned index literal'
        if name == 'PS4RF_KREAD_BINDING_WINDOW_COUNT':
            count = int(value[:-1])
        else:
            indices[int(name.rsplit('_', 1)[1])] = int(value[:-1])
    return count, [indices[i] for i in sorted(indices)]


def test_the_five_binding_windows_compile_to_their_append_only_indices():
    """The candidate's five windows, by compiled index, under neutral generated names."""
    header = REGIONS_HEADER.read_text()
    count, indices = _binding_alias(header)
    expected = [regions.compiled_region_index(region.name) for region in COMPILED
                if region.identity_status == regions.IDENTITY_STRICT
                and CANDIDATE in region.provenance]
    assert expected == [9, 10, 11, 12, 13], expected
    assert count == len(expected) == 5
    assert indices == expected
    # the alias is neutral: the module can name it without tripping the subsystem scan
    alias_lines = [line for line in header.splitlines()
                   if line.startswith('#define PS4RF_KREAD_BINDING_WINDOW')]
    for line in alias_lines:
        assert 'ccp' not in line.lower() and 'keymgr' not in line.lower(), line


def test_the_binding_alias_covers_the_strict_windows_and_never_the_structural_pool():
    """`keymgr_pool` is STRUCTURAL_ONLY: it must not be addressable through the alias."""
    header = REGIONS_HEADER.read_text()
    count, indices = _binding_alias(header)
    assert count == 5, 'the alias must exist and cover the five windows'
    pool = regions.compiled_region_index('keymgr_pool')
    assert pool is not None and pool not in indices
    for index in indices:
        assert COMPILED[index].identity_status == regions.IDENTITY_STRICT
        assert COMPILED[index].length == 16
