"""W12 registry tests: every number traced to evidence, every bound fail-closed.

These tests read the evidence files directly (the generated W9 attestation table, the
W11.2 boot-read constants, the boot identity artefact, the promoted profile) and compare
them against the registry, so the registry can never drift from its sources. The negative
matrix then drives :func:`tools.profiles.regions.resolve_read` case by case, including the
reviewer-mandated cases (structural-only as identity source, unresolved, non-canonical,
u64 wraparound, exact region end, one byte over the end, length 0/4097). No network, no
console, deterministic.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import re
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:                      # pragma: no cover - import bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from tools.hostctl import bootpriv                                      # noqa: E402
from tools.profiles import promotion                                    # noqa: E402
from tools.profiles import regions as reg                               # noqa: E402
from tools.profiles.kread import (                                      # noqa: E402
    KREAD_CROSS_REGION, KREAD_LENGTH_EXCEEDS_MAX, KREAD_LENGTH_ZERO,
    KREAD_NEGATIVE_OFFSET, KREAD_NON_CANONICAL_ADDRESS, KREAD_OFFSET_OVERFLOW,
    KREAD_POLICY_NOT_APPROVED, KREAD_STRICT_IDENTITY_REQUIRED, KREAD_UNKNOWN_REGION,
    KREAD_UNRESOLVED_REGION, KReadReject, U64_MAX, is_canonical_x86_64,
)

TARGET = REPO_ROOT / 'native' / 'target'
BOOT_IDENTITY = REPO_ROOT / 'profiles' / 'fw1352' / 'boot-identity.json'
PROFILE_PATH = REPO_ROOT / 'profiles' / 'fw1352' / 'profile-13.52.json'
#: the W16 revision candidate: it carries the CCP/keymgr binding locators, but it is NOT the
#: promoted profile (docs/P4-CCP-ACCEPTANCE-REQ.md section 7 -- promotion needs the live match)
PROFILE_CCP1_PATH = REPO_ROOT / 'profiles' / 'fw1352' / 'profile-13.52-ccp1.json'
ATTEST_HEADER = TARGET / 'ps4rf_attest_data.h'

# the exact numbers the evidence files state (re-checked against them below)
W9_STRICT = {
    'image_elf': (0x0, 16),
    'amd_iommu': (0x7CE9E9, 16),
    'gbase_vtophys': (0x815BBC, 16),
    'code_anchor': (0x4CF6A0, 24),
    'xfast_entry': (0x1C0, 8),
    'copyout_prologue': (0x2BD6A0, 8),
    'prison0_static': (0x111FA18, 8),
}
APERTURE_RVA, APERTURE_LEN = 0x23D3DF8, 8
BOOTTIME_RVA, BOOTTIME_LEN = 0x224C6C8, 16
# W16: the CCP/keymgr binding windows of the revision candidate (profile-13.52-ccp1.json) --
# five 16 byte text fingerprints plus the keymgr slot pool, whose bytes are runtime state and
# therefore STRUCTURAL_ONLY. The candidate is not the promoted profile; see
# test_w16_ccp_windows_match_the_revision_candidate.
CCP_STRICT = {
    'ccp_submit_entry': (0x625330, 16),
    'ccp_device_gate': (0x3B2EE0, 16),
    'keymgr_claim_entry': (0x62C570, 16),
    'keymgr_bind_entry': (0x62BF50, 16),
    'keymgr_release_entry': (0x62C610, 16),
}
CCP_STRUCTURAL = {'keymgr_pool': (0x266C8E0, 2048)}
#: Track A: the read-only observation windows (docs/P4-A-OBSERVATION-WINDOWS.md) -- proven,
#: STRUCTURAL_ONLY by rule (runtime state), never identity sources, read by the payload's own
#: fixed step on the owner's decision of 2026-10-07.
A_OBS = {'keymgr_ctx_lock': (0x2668008, 88), 'keymgr_sm_gate': (0x266C800, 96),
         'ccp_stage_msg': (0x2694000, 64), 'ccp_stage_ptr': (0x2694060, 8),
         'ccp_client_a_buf': (0x2658000, 128)}
ALL_PINNED = dict(W9_STRICT, aperture_global=(APERTURE_RVA, APERTURE_LEN),
                  boottime=(BOOTTIME_RVA, BOOTTIME_LEN), **CCP_STRICT, **CCP_STRUCTURAL,
                  **A_OBS)
#: the proven regions that are NOT identity sources (aperture_global W9/W10, keymgr_pool W16,
#: the five Track A observation windows)
NON_STRICT_PINNED = ('aperture_global', 'keymgr_pool', *A_OBS)
UNRESOLVED_NAMES = ('boottime_node', 'boottime_bintime')


def _reject(reason, fn, *args, **kwargs):
    with pytest.raises(KReadReject) as excinfo:
        fn(*args, **kwargs)
    assert excinfo.value.reason == reason, \
        f'expected {reason}, got {excinfo.value.reason}'
    assert isinstance(excinfo.value.detail, str) and excinfo.value.detail
    return excinfo.value


def _synthetic(name: str, rva, length, identity_status, policy) -> reg.Region:
    """A test-only region injected at the lookup seam; the registry stays evidence-only."""
    return reg.Region(name=name, rva=rva, length=length, identity_status=identity_status,
                      policy=policy, provenance=('synthetic test region',),
                      locator=None, profile_requirement='none (test only)',
                      notes='test-only region, never part of the shipped registry')


def _with_regions(monkeypatch, *injected: reg.Region) -> None:
    table = {region.name: region for region in injected}
    monkeypatch.setattr(reg, 'get_region', lambda name: table.get(name))


# --- the registry against its evidence sources --------------------------------------------

def test_registry_w9_windows_match_the_generated_attestation_table():
    rows = {row['id']: row for row in promotion.parse_w9_table()}
    assert set(rows) == set(W9_STRICT) | {'aperture_global'}
    for name, (rva, length) in W9_STRICT.items():
        region = reg.get_region(name)
        assert region is not None, name
        assert (region.rva, region.length) == (rva, length), name
        assert (region.rva, region.length) == (rows[name]['rva'], rows[name]['len']), name
        assert region.identity_status == reg.IDENTITY_STRICT, name
        assert rows[name]['policy'] == 'STRICT_FINGERPRINT', name
    aperture = reg.get_region('aperture_global')
    assert aperture is not None
    assert (aperture.rva, aperture.length) == (APERTURE_RVA, APERTURE_LEN)
    assert aperture.identity_status == reg.IDENTITY_STRUCTURAL_ONLY
    assert rows['aperture_global']['policy'] == 'STRUCTURAL_ONLY'


def test_registry_w9_windows_match_a_direct_parse_of_the_header():
    # a second, independent mechanism next to promotion.parse_w9_table: read the hex
    # values straight out of the generated header, so a wrong registry number fails even
    # if some shared parser were wrong too
    text = ATTEST_HEADER.read_text()
    for name, (rva, length) in list(W9_STRICT.items()) + \
            [('aperture_global', (APERTURE_RVA, APERTURE_LEN))]:
        chars = "', '".join(name)
        pattern = (r"\{ \{\s*'(?:" + chars + r")', '\\0'\s*\}, "
                   r"0x([0-9A-Fa-f]+)u,\s*(\d+)u,")
        match = re.search(pattern, text)
        assert match is not None, f'{name}: not found in {ATTEST_HEADER.name}'
        assert (int(match.group(1), 16), int(match.group(2))) == (rva, length), name
        region = reg.get_region(name)
        assert region is not None and (region.rva, region.length) == (rva, length), name


def test_registry_w9_windows_match_the_promoted_profile():
    profile = json.loads(PROFILE_PATH.read_text())
    windows = dict(W9_STRICT, aperture_global=(APERTURE_RVA, APERTURE_LEN))
    for name, (rva, length) in windows.items():
        locator = profile['locators'][f'kernel.attest.{name}']
        region = reg.get_region(name)
        assert region is not None, name
        expected = (reg.IDENTITY_STRUCTURAL_ONLY if name == 'aperture_global'
                    else reg.IDENTITY_STRICT)
        assert region.identity_status == expected == locator['policy'], name
        assert locator['locator']['value'] == rva == region.rva, name
        assert region.locator == f'kernel.attest.{name}', name
        # the profile's expected bytes must be exactly the window the registry names
        assert len(bytes.fromhex(locator['expected_bytes']['hex'])) == length, name


def test_boottime_region_matches_the_w11_2_source_of_truth():
    code = (TARGET / 'ps4rf_bootread.c').read_text()
    header = (TARGET / 'ps4rf_bootread.h').read_text()
    match = re.search(r'#define PS4RF_BOOTREAD_SOURCE_RVA (0x[0-9A-Fa-f]+)u', code)
    assert match is not None, 'boot-read source RVA define not found'
    assert int(match.group(1), 16) == BOOTTIME_RVA
    match = re.search(r'#define PS4RF_BOOTREAD_READ_LEN (\d+)u', header)
    assert match is not None, 'boot-read read length define not found'
    assert int(match.group(1)) == BOOTTIME_LEN
    artefact = json.loads(BOOT_IDENTITY.read_text())
    candidate = next(c for c in artefact['boot_instance_candidates']
                     if c['id'] == 'kern.boottime.kernel_variable')
    assert int(candidate['rva'], 16) == BOOTTIME_RVA
    assert '16 bytes' in candidate['rva_or_api']
    assert candidate['confidence'] == 'HIGH'
    assert bootpriv.SOURCE_RVA == BOOTTIME_RVA
    assert bootpriv.READ_LEN == BOOTTIME_LEN
    region = reg.get_region('boottime')
    assert region is not None
    assert (region.rva, region.length, region.identity_status) == \
        (BOOTTIME_RVA, BOOTTIME_LEN, reg.IDENTITY_STRICT)
    assert region.locator == 'kern.boottime.kernel_variable'


def test_unresolved_regions_come_from_the_boot_identity_evidence_without_numbers():
    artefact = json.loads(BOOT_IDENTITY.read_text())
    candidates = {c['id']: c for c in artefact['boot_instance_candidates']}
    assert {'kern.boottime.node', 'kern.boottimebin.bintime'} <= set(candidates)
    # the node genuinely cannot be pinned: the artefact names two different RVAs for it
    node = candidates['kern.boottime.node']
    assert node['rva'] == '0x1a5ef90'
    assert '0x1a5efb8' in node['rva_or_api']
    assert node['rva'] != '0x1a5efb8'
    for name, locator in (('boottime_node', 'kern.boottime.node'),
                          ('boottime_bintime', 'kern.boottimebin.bintime')):
        region = reg.get_region(name)
        assert region is not None, name
        assert region.identity_status == reg.IDENTITY_UNRESOLVED, name
        assert region.rva is None and region.length is None, name
        assert region.policy == reg.POLICY_NOT_APPROVED, name
        assert region.locator == locator, name
        assert region.provenance == ('profiles/fw1352/boot-identity.json',), name


# --- the reviewed entry fields ------------------------------------------------------------

def test_every_region_carries_the_reviewed_fields():
    for region in reg.regions().values():
        assert region.policy in reg.POLICY_VALUES, region.name
        assert region.provenance and all(isinstance(s, str) and s
                                         for s in region.provenance), region.name
        assert region.sources == region.provenance, region.name
        assert isinstance(region.locator, str) and region.locator, region.name
        assert region.profile_requirement.strip(), region.name
        assert region.notes.strip(), region.name
        assert region.max_size == region.length, region.name
        for source in region.provenance:
            assert (REPO_ROOT / source).is_file(), f'{region.name}: missing source {source}'


def test_every_region_locator_binds_to_an_existing_identifier():
    profile = json.loads(PROFILE_PATH.read_text())
    revision = json.loads(PROFILE_CCP1_PATH.read_text())
    artefact = json.loads(BOOT_IDENTITY.read_text())
    boot_ids = {c['id'] for c in artefact['boot_instance_candidates']}
    for region in reg.regions().values():
        locator = region.locator
        assert isinstance(locator, str) and locator, region.name
        if locator.startswith('kernel.attest.'):
            assert locator in profile['locators'], region.name
        elif locator in revision['locators']:
            # W16: the CCP/keymgr binding windows are bound by the revision CANDIDATE only --
            # while the candidate is unpromoted its locators must not appear in the promoted
            # profile. A promotion moves them there and updates this branch deliberately.
            assert locator not in profile['locators'], region.name
        elif locator.startswith('obs.'):
            # Track A: the observation windows (docs/P4-A-OBSERVATION-WINDOWS.md) are neither
            # profile locators nor boot-instance candidates. Their locator identifier names the
            # observation itself and is deliberately in no profile and in no boot-identity set --
            # the region must carry the observation provenance, and it is read only by the
            # payload's own fixed step.
            assert reg.A_OBS_PROVENANCE[0] in region.provenance, region.name
        else:
            assert locator in boot_ids, region.name


def test_readability_rule_is_frozen():
    # STRICT_FINGERPRINT regions may be read; any other region needs the explicit
    # approved bounded-research policy; UNRESOLVED is never readable
    for name in ALL_PINNED:
        region = reg.get_region(name)
        assert region is not None and reg.may_read(region), name
    for name in UNRESOLVED_NAMES:
        region = reg.get_region(name)
        assert region is not None and not reg.may_read(region), name
    assert reg.POLICY_APPROVED_BOUNDED_RESEARCH in reg.READABLE_POLICIES
    assert reg.POLICY_NOT_APPROVED not in reg.READABLE_POLICIES


def test_unreadable_policy_refuses_both_read_modes(monkeypatch):
    synthetic = _synthetic('synthetic_not_approved', 0x1000, 64,
                           reg.IDENTITY_STRUCTURAL_ONLY, reg.POLICY_NOT_APPROVED)
    _with_regions(monkeypatch, synthetic)
    assert not reg.may_read(synthetic)
    _reject(KREAD_POLICY_NOT_APPROVED, reg.resolve_read, synthetic.name, 0, 8)
    _reject(KREAD_POLICY_NOT_APPROVED, reg.resolve_read, synthetic.name, 0, 8,
            structural_only=True)


# --- registry integrity -------------------------------------------------------------------

def test_no_duplicate_names_and_lookup_semantics():
    table = reg.regions()
    names = [region.name for region in table.values()]
    assert len(names) == len(set(names)) == len(table)
    for key, region in table.items():
        assert key == region.name
        assert reg.get_region(key) is region
    assert reg.get_region('does_not_exist') is None
    assert reg.get_region(42) is None   # type: ignore[arg-type]  # non-string resolves to nothing


def test_registry_integrity_and_expected_membership():
    table = reg.regions()
    assert {r.name for r in table.values()
            if r.identity_status != reg.IDENTITY_UNRESOLVED} == set(ALL_PINNED)
    assert {r.name for r in table.values()
            if r.identity_status == reg.IDENTITY_STRUCTURAL_ONLY} == set(NON_STRICT_PINNED)
    assert {r.name for r in table.values()
            if r.identity_status == reg.IDENTITY_UNRESOLVED} == set(UNRESOLVED_NAMES)
    for region in table.values():
        if region.identity_status == reg.IDENTITY_UNRESOLVED:
            assert region.rva is None and region.length is None
            assert region.policy == reg.POLICY_NOT_APPROVED
            assert not reg.may_read(region)
            continue
        assert isinstance(region.rva, int) and not isinstance(region.rva, bool)
        assert region.rva >= 0, region.name
        assert isinstance(region.length, int) and region.length >= 1, region.name
        assert is_canonical_x86_64(region.rva), region.name
        # inside the 64 MiB pinned image window: no entry reaches into DMAP/page tables
        assert region.rva + region.length <= reg.IMAGE_WINDOW_MAX_RVA, region.name
        assert reg.may_read(region), region.name
        if region.identity_status == reg.IDENTITY_STRICT:
            assert region.policy == reg.POLICY_APPROVED_BOUNDED_RESEARCH, region.name
    assert reg.MAX_READ_LEN == 4096
    assert reg.registry_problems() == []


def test_registry_dataclass_rejects_malformed_entries():
    valid = reg.Region(name='x', rva=0, length=8, identity_status=reg.IDENTITY_STRICT,
                       policy=reg.POLICY_APPROVED_BOUNDED_RESEARCH, provenance=('x',),
                       locator=None, profile_requirement='none', notes='x')
    assert dataclasses.replace(valid).name == 'x'
    with pytest.raises(ValueError):
        dataclasses.replace(valid, name='')
    with pytest.raises(ValueError):
        dataclasses.replace(valid, identity_status='NOT_A_STATUS')
    with pytest.raises(ValueError):
        dataclasses.replace(valid, policy='MAYBE')
    with pytest.raises(ValueError):
        dataclasses.replace(valid, provenance=[])
    with pytest.raises(ValueError):
        dataclasses.replace(valid, provenance=('',))
    with pytest.raises(ValueError):
        dataclasses.replace(valid, rva='not-an-int')


def test_regions_returns_a_defensive_copy():
    table = reg.regions()
    table.clear()
    assert len(reg.regions()) == len(ALL_PINNED) + len(UNRESOLVED_NAMES)


def test_non_strict_proven_regions_are_the_aperture_and_the_ccp_pool_window():
    """The proven regions that are not identity sources, and nothing else.

    W9/W10 froze ``aperture_global`` as STRUCTURAL_ONLY (its value is boot dependent); W16 adds
    ``keymgr_pool`` for the same reason (the slot pool bytes are runtime state). Every other
    proven region must stay a STRICT identity source -- that is the property which keeps a
    runtime-state window out of the identity path.
    """
    for name in NON_STRICT_PINNED:
        region = reg.get_region(name)
        assert region is not None, name
        assert region.identity_status == reg.IDENTITY_STRUCTURAL_ONLY, name
        assert not reg.is_strict_source(region), name
        assert region.policy == reg.POLICY_APPROVED_BOUNDED_RESEARCH, name
    for name in ALL_PINNED:
        if name in NON_STRICT_PINNED:
            continue
        region = reg.get_region(name)
        assert region is not None, name
        assert reg.is_strict_source(region), name


def test_w16_ccp_windows_match_the_revision_candidate():
    """Every W16 window's rva/length is the revision candidate's own locator number.

    The candidate (profiles/fw1352/profile-13.52-ccp1.json) is the promotion target, so its
    numbers are the only admissible source for these regions; the test also pins that the
    candidate is still a *candidate* (its locators are absent from the promoted profile) and
    that the append-only layout left every earlier compiled index untouched.
    """
    revision = json.loads(PROFILE_CCP1_PATH.read_text())
    promoted = json.loads(PROFILE_PATH.read_text())
    for name in (*CCP_STRICT, *CCP_STRUCTURAL):
        region = reg.get_region(name)
        assert region is not None, name
        assert region.locator in revision['locators'], name
        locator = revision['locators'][region.locator]
        assert locator['locator']['kind'] == 'rva', name
        assert locator['locator']['value'] == region.rva, name
        assert region.locator not in promoted['locators'], name
        expected = locator['expected_bytes']
        if region.identity_status == reg.IDENTITY_STRICT:
            assert locator['policy'] == 'STRICT_FINGERPRINT', name
            assert expected is not None and expected['offset'] == 0, name
            assert len(bytes.fromhex(expected['hex'])) == region.length, name
        else:
            assert locator['policy'] == 'STRUCTURAL_ONLY', name
            assert expected is None, name
    # append-only: the W16 windows follow the W9..W11.2 entries, so no index moved
    names = reg.compiled_region_names()
    assert names[:9] == ('image_elf', 'amd_iommu', 'gbase_vtophys', 'code_anchor', 'xfast_entry',
                         'copyout_prologue', 'prison0_static', 'aperture_global', 'boottime')
    assert names[9:] == tuple(CCP_STRICT) + tuple(CCP_STRUCTURAL) + tuple(A_OBS)
    assert reg.compiled_region_index('boottime') == 8
    for index, name in enumerate(names):
        assert reg.compiled_region_index(name) == index


def test_registry_module_cli_self_test_and_matrix():
    self_test = subprocess.run([sys.executable, str(REPO_ROOT / 'tools' / 'profiles' /
                                                   'regions.py'), '--self-test'],
                               capture_output=True, text=True, cwd=str(REPO_ROOT))
    assert self_test.returncode == 0, self_test.stdout + self_test.stderr
    assert 'ok' in self_test.stdout and 'FAILED' not in self_test.stdout
    matrix = subprocess.run([sys.executable, str(REPO_ROOT / 'tools' / 'profiles' /
                                                 'regions.py'), '--matrix'],
                            capture_output=True, text=True, cwd=str(REPO_ROOT))
    assert matrix.returncode == 0, matrix.stderr
    report = json.loads(matrix.stdout)
    assert report['max_read_len'] == 4096
    entries = {entry['name']: entry for entry in report['regions']}
    assert set(entries) == set(ALL_PINNED) | set(UNRESOLVED_NAMES)
    assert entries['boottime']['rva'] == hex(BOOTTIME_RVA)
    assert entries['aperture_global']['may_read'] is True
    assert entries['aperture_global']['identity_status'] == reg.IDENTITY_STRUCTURAL_ONLY
    assert entries['boottime_node']['may_read'] is False
    assert all('policy' in entry and 'locator' in entry and 'max_size' in entry
               for entry in entries.values())


# --- resolution: refusals -------------------------------------------------------------------

def test_unknown_region_is_refused_first():
    _reject(KREAD_UNKNOWN_REGION, reg.resolve_read, 'not_a_region', 0, 1)
    _reject(KREAD_UNKNOWN_REGION, reg.resolve_read, 'not_a_region', -1, 0)


def test_unresolved_regions_refuse_every_read():
    for name in UNRESOLVED_NAMES:
        for offset, length in ((0, 16), (0, 1), (1, 8)):
            _reject(KREAD_UNRESOLVED_REGION, reg.resolve_read, name, offset, length)
            _reject(KREAD_UNRESOLVED_REGION, reg.resolve_read, name, offset, length,
                    structural_only=True)


def test_structural_only_region_presented_as_strict_identity_read_is_refused(monkeypatch):
    # aperture_global: approved policy, but STRUCTURAL_ONLY must never serve as a
    # trusted identity source
    _reject(KREAD_STRICT_IDENTITY_REQUIRED, reg.resolve_read, 'aperture_global',
            0, APERTURE_LEN)
    synthetic = _synthetic('synthetic_structural', 0x2000, 64,
                           reg.IDENTITY_STRUCTURAL_ONLY,
                           reg.POLICY_APPROVED_BOUNDED_RESEARCH)
    _with_regions(monkeypatch, synthetic)
    _reject(KREAD_STRICT_IDENTITY_REQUIRED, reg.resolve_read, synthetic.name, 0, 8)
    # the explicit observation request is the only readable form
    resolved = reg.resolve_read(synthetic.name, 0, 8, structural_only=True)
    assert resolved.address == 0x2000


def test_aperture_global_is_refused_as_strict_identity_source():
    reject = _reject(KREAD_STRICT_IDENTITY_REQUIRED, reg.resolve_read, 'aperture_global',
                     0, APERTURE_LEN)
    assert 'STRUCTURAL_ONLY' in reject.detail
    _reject(KREAD_STRICT_IDENTITY_REQUIRED, reg.resolve_read, 'aperture_global', 0, 1)


def test_aperture_global_is_readable_only_as_structural_observation():
    resolved = reg.resolve_read('aperture_global', 0, APERTURE_LEN, structural_only=True)
    assert (resolved.address, resolved.rva, resolved.offset, resolved.length) == \
        (APERTURE_RVA, APERTURE_RVA, 0, APERTURE_LEN)
    assert resolved.region.name == 'aperture_global'
    tail = reg.resolve_read('aperture_global', APERTURE_LEN - 1, 1, structural_only=True)
    assert tail.address == APERTURE_RVA + APERTURE_LEN - 1
    _reject(KREAD_CROSS_REGION, reg.resolve_read, 'aperture_global', APERTURE_LEN - 1, 2,
            structural_only=True)


def test_strict_region_reads_resolve_by_default():
    resolved = reg.resolve_read('boottime', 0, BOOTTIME_LEN)
    assert (resolved.address, resolved.rva, resolved.offset, resolved.length) == \
        (BOOTTIME_RVA, BOOTTIME_RVA, 0, BOOTTIME_LEN)
    assert resolved.region.identity_status == reg.IDENTITY_STRICT
    # an explicit structural request on a STRICT region stays readable (observation)
    observed = reg.resolve_read('boottime', 4, 8, structural_only=True)
    assert observed.address == BOOTTIME_RVA + 4


def test_negative_offset_is_refused():
    _reject(KREAD_NEGATIVE_OFFSET, reg.resolve_read, 'boottime', -1, 16)
    _reject(KREAD_NEGATIVE_OFFSET, reg.resolve_read, 'boottime', -1, 0)


def test_offset_overflow_is_refused():
    _reject(KREAD_OFFSET_OVERFLOW, reg.resolve_read, 'boottime', U64_MAX, 16)
    # offset + length == 2**64 exactly: still not representable in u64
    _reject(KREAD_OFFSET_OVERFLOW, reg.resolve_read, 'boottime', U64_MAX, 1)
    _reject(KREAD_OFFSET_OVERFLOW, reg.resolve_read, 'boottime', 2 ** 63, 2 ** 63)
    _reject(KREAD_OFFSET_OVERFLOW, reg.resolve_read, 'boottime', U64_MAX - 4095, 4096)


def test_offset_near_two_pow_63_does_not_wrap_and_fails_containment():
    # 2**63 + 16 still fits unsigned 64 bits: the refusal must come from containment,
    # not from a wrap that never happened
    _reject(KREAD_CROSS_REGION, reg.resolve_read, 'boottime', 2 ** 63, 16)
    _reject(KREAD_CROSS_REGION, reg.resolve_read, 'boottime', U64_MAX - 16, 16)


def test_length_zero_and_above_max_are_refused():
    _reject(KREAD_LENGTH_ZERO, reg.resolve_read, 'boottime', 0, 0)
    _reject(KREAD_LENGTH_ZERO, reg.resolve_read, 'boottime', 15, 0)
    _reject(KREAD_LENGTH_ZERO, reg.resolve_read, 'boottime', BOOTTIME_LEN, 0)
    # 4097 would also cross the 16 byte region; the maximum check owns this failure
    _reject(KREAD_LENGTH_EXCEEDS_MAX, reg.resolve_read, 'boottime', 0, 4097)
    _reject(KREAD_LENGTH_EXCEEDS_MAX, reg.resolve_read, 'boottime', 0, 10 ** 6)
    # the negative-offset check still owns its failure, before the maximum check
    _reject(KREAD_NEGATIVE_OFFSET, reg.resolve_read, 'boottime', -1, 4097)


def test_offset_exactly_at_region_end_and_one_byte_over():
    for name, (rva, length) in ALL_PINNED.items():
        # offset exactly at the end: nothing may be read there
        _reject(KREAD_CROSS_REGION, reg.resolve_read, name, length, 1,
                structural_only=True)
        # offset + length exactly one byte over the end (the last byte belongs to the
        # region, the byte after it does not)
        _reject(KREAD_CROSS_REGION, reg.resolve_read, name, length - 1, 2,
                structural_only=True)
        _reject(KREAD_CROSS_REGION, reg.resolve_read, name, 0, length + 1,
                structural_only=True)


def test_last_legal_byte_and_full_region_reads_are_accepted():
    for name, (rva, length) in ALL_PINNED.items():
        last = reg.resolve_read(name, length - 1, 1, structural_only=True)
        assert (last.address, last.offset, last.length) == (rva + length - 1, length - 1, 1)
        full = reg.resolve_read(name, 0, length, structural_only=True)
        assert (full.address, full.rva, full.offset, full.length) == (rva, rva, 0, length)
        assert full.region.name == name
        # STRICT regions are also readable without the observation flag
        if name not in NON_STRICT_PINNED:
            assert reg.resolve_read(name, 0, length).address == rva


def test_exact_maximum_4096_is_accepted_and_4097_is_refused(monkeypatch):
    # no evidence region is 4096 bytes long, so the exact ceiling is exercised on a
    # synthetic region injected at the lookup seam; the registry itself stays evidence-only
    synthetic = _synthetic('synthetic_4096', 0x1000, reg.MAX_READ_LEN,
                           reg.IDENTITY_STRICT, reg.POLICY_APPROVED_BOUNDED_RESEARCH)
    _with_regions(monkeypatch, synthetic)
    resolved = reg.resolve_read('synthetic_4096', 0, reg.MAX_READ_LEN)
    assert (resolved.address, resolved.length) == (0x1000, reg.MAX_READ_LEN)
    assert resolved.region.max_size == reg.MAX_READ_LEN
    _reject(KREAD_LENGTH_EXCEEDS_MAX, reg.resolve_read, 'synthetic_4096', 0,
            reg.MAX_READ_LEN + 1)
    _reject(KREAD_CROSS_REGION, reg.resolve_read, 'synthetic_4096', 1, reg.MAX_READ_LEN)


def test_non_canonical_resolved_address_is_refused(monkeypatch):
    poison = _synthetic('poison_non_canonical', 1 << 47, 4096, reg.IDENTITY_STRICT,
                        reg.POLICY_APPROVED_BOUNDED_RESEARCH)
    wrap = _synthetic('poison_wrap', U64_MAX - 7, 4096, reg.IDENTITY_STRICT,
                      reg.POLICY_APPROVED_BOUNDED_RESEARCH)
    _with_regions(monkeypatch, poison, wrap)
    _reject(KREAD_NON_CANONICAL_ADDRESS, reg.resolve_read, 'poison_non_canonical', 0, 16)
    # offset 8 + length 16 passes containment (region is 4096 bytes) but rva + offset
    # overflows u64: non-canonical, not served
    _reject(KREAD_NON_CANONICAL_ADDRESS, reg.resolve_read, 'poison_wrap', 8, 16)


def test_canonical_predicate_boundaries():
    assert is_canonical_x86_64(0)
    assert is_canonical_x86_64((1 << 47) - 1)
    assert is_canonical_x86_64(0xFFFF800000000000)
    assert is_canonical_x86_64(U64_MAX)
    assert not is_canonical_x86_64(1 << 47)
    assert not is_canonical_x86_64((1 << 48) - 1)
    assert not is_canonical_x86_64(0xFFFF7FFFFFFFFFFF)
    assert not is_canonical_x86_64(U64_MAX + 1)
    assert not is_canonical_x86_64(-1)
    assert not is_canonical_x86_64(True)


def test_registry_dataclasses_are_frozen():
    region = reg.get_region('boottime')
    assert region is not None
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(region, 'rva', 1)
    resolved = reg.resolve_read('boottime', 0, BOOTTIME_LEN)
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(resolved, 'address', 0)
