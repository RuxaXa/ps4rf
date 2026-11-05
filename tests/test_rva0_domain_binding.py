#!/usr/bin/env python3
"""W12-RVA0-BINDING: the relative locator domain and the runtime address domain.

Wave-owner ruling (2026-10-06): the accepted payload stays unchanged, ``image_elf @ RVA 0x0``
stays ``BOOTSTRAP_VERIFY_REGION``, and the reported blocker is fixed as a *domain modelling*
defect -- **rva 0 is valid, a runtime address of 0 is not**. These tests are the mandated
regressions for that fix:

=============================== =====================================================
rva = 0                         VALID locator value
runtime_va = 0                  REJECT (a runtime address is never 0)
kbase + rva0                    runtime_va == kbase
rva != 0                        existing behaviour unchanged
rva overflow                    REJECT
kbase + rva overflow            REJECT
non-canonical runtime VA        REJECT
image_elf profile binding       PROFILE_MATCH
image_elf phase B simulation    exactly ONE provider entry, valid evidence
UNRESOLVED                      still REJECT
STRUCTURAL_ONLY                 still REJECT
stale boot                      still REJECT
wrong profile                   still REJECT
=============================== =====================================================

Offline only: no console, no socket, no payload, no profile change.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.hostctl import kreadlive as KL                                       # noqa: E402
from tools.profiles import kread_capability as KC                               # noqa: E402
from tools.profiles import regions                                              # noqa: E402
from tools.profiles import schema as S                                          # noqa: E402
from tools.profiles.binding import BootBinding                                  # noqa: E402
from tools.profiles.kread import KReadReject                                    # noqa: E402

PROFILE = json.loads((REPO_ROOT / 'profiles' / 'fw1352' / 'profile-13.52.json').read_text())
PROFILE_SHA = S.canonical_profile_sha256(PROFILE)
KBASE = KL.SIM_KBASE
PINNED_REGION, PINNED_OFFSET, PINNED_LENGTH = 'image_elf', 0, 16
PINNED_BYTES = '7f454c46020101090000000000000000'
REQUEST = {'operation': 'kernel.read', 'region': PINNED_REGION, 'offset': PINNED_OFFSET,
           'length': PINNED_LENGTH}
CONTEXT = 'JAILBROKEN_PROCESS'
SESSION_ID = 'SES-' + '0' * 16


def boot_binding() -> BootBinding:
    """The real profile bound to a derived boot id (the W5 binding input)."""
    return BootBinding.from_profile(PROFILE, KL.synthetic_boot_binding(PROFILE).boot_id)


def provider(*, live_approved: bool = True) -> dict:
    return {'name': 'ps4rfd-kread-privileged', 'provider_type': 'NATIVE', 'state': 'WIRED',
            'live_approved': live_approved}


def capability(*, boot_id: str, session_id: str = SESSION_ID) -> dict:
    return {
        'name': 'kernel.read', 'availability': 'AVAILABLE', 'assurance': 'PROVEN',
        'context': CONTEXT, 'provider': provider()['name'], 'provider_type': 'NATIVE',
        'scope': 'SESSION', 'session_id': session_id, 'boot_id': boot_id,
        'profile_sha256': PROFILE_SHA,
        'verification': {'run_id': 'RUN-' + '2' * 32, 'operation': 'verify.kernel.read',
                         'outcome': 'PASS', 'capability': 'kernel.read',
                         'provider': provider()['name'], 'provider_type': 'NATIVE',
                         'session_id': session_id, 'boot_id': boot_id,
                         'separate_from_read': True},
        'evidence_ref': {'run_id': 'RUN-' + '2' * 32, 'sha256': 'b' * 64},
        'approval': {'approved': True, 'state': 'APPROVED', 'id': 'CMR-w12-rva0'},
    }


def decide(request: dict | None = None, *, boot_binding_=None, profile: dict | None = None):
    request = REQUEST if request is None else request
    binding = boot_binding() if boot_binding_ is None else boot_binding_
    profile = PROFILE if profile is None else profile
    bound = binding.boot_id
    return KC.decide(request, registry=regions, profile=profile, boot_binding=binding,
                     context=CONTEXT, capability=capability(boot_id=bound), recovery=False,
                     provider=provider())


# --- 1. rva = 0 is a valid locator ---------------------------------------------------------
def test_rva_zero_is_a_valid_locator():
    assert S.validate_locator_value('rva', 0) == []
    assert S.validate_locator_value('relative', 0) == []
    assert S.LOCATOR_VALUE_DOMAINS == {'rva': 'rva', 'relative': 'rva'}
    # the profile itself carries image_elf as a relative locator at the image base
    locator = PROFILE['locators']['kernel.attest.image_elf']['locator']
    assert locator == {'kind': 'rva', 'value': 0}
    assert S.validate_locator_value(locator['kind'], locator['value']) == []
    # the module's declared kind is what the W5 binding validates against
    assert S.module_locator_kind(PROFILE, 'kernel') == 'rva'
    # unknown kinds fail closed
    assert S.validate_locator_value('absolute', 0)
    assert S.module_locator_kind(PROFILE, 'not_a_module') is None


# --- 2. runtime_va = 0 is rejected ---------------------------------------------------------
def test_runtime_address_zero_is_rejected():
    assert S.validate_field_value('runtime_va', 0)          # non-empty == refused
    assert S.validate_field_value('addr', 0)                # the runtime addr rule is unchanged
    with pytest.raises(KReadReject) as exc:
        regions.checked_kernel_address(0, 0)
    assert exc.value.reason == 'KREAD_ZERO_RUNTIME_ADDRESS'
    resolved = regions.resolve_read(PINNED_REGION, PINNED_OFFSET, PINNED_LENGTH)
    with pytest.raises(KReadReject) as exc2:
        regions.resolve_runtime(resolved, 0)
    assert exc2.value.reason == 'KREAD_ZERO_RUNTIME_ADDRESS'


# --- 3. kbase + rva 0 == kbase -------------------------------------------------------------
def test_kbase_plus_rva_zero_is_the_kbase():
    resolved = regions.resolve_read(PINNED_REGION, PINNED_OFFSET, PINNED_LENGTH)
    runtime = regions.resolve_runtime(resolved, KBASE)
    assert runtime.rva == 0
    assert runtime.runtime_base_va == KBASE
    assert runtime.runtime_address == KBASE
    assert regions.checked_kernel_address(KBASE, 0) == KBASE
    # the decision grants on exactly this window and takes exactly one provider entry
    decision = decide()
    assert decision.outcome == 'GRANTED' and decision.provider_entry is True
    assert decision.stopped_at is None and decision.reasons == []


# --- 4. a nonzero rva behaves exactly as before --------------------------------------------
def test_nonzero_rva_behaviour_is_unchanged():
    resolved = regions.resolve_read('amd_iommu', 0, 16)
    assert resolved.rva == 8186345
    runtime = regions.resolve_runtime(resolved, KBASE)
    assert runtime.runtime_base_va == KBASE + resolved.rva
    assert runtime.runtime_address == KBASE + resolved.rva
    assert S.validate_locator_value('rva', resolved.rva) == []
    assert decide({'operation': 'kernel.read', 'region': 'amd_iommu', 'offset': 0,
                   'length': 16}).outcome == 'GRANTED'
    # the evidence still composes rva + offset and kbase + rva exactly as before
    evidence = KC.fixed_read_evidence(REQUEST, regions.resolve_read(
        PINNED_REGION, PINNED_OFFSET, PINNED_LENGTH), run_id='RUN-' + 'a' * 32,
        bytes_hex=PINNED_BYTES, runtime_kbase=KBASE, profile_sha256=PROFILE_SHA,
        boot_id=boot_binding().boot_id, provider=provider())
    assert evidence['resolved_rva'] == 0
    assert evidence['resolved_runtime_va'] == KBASE


# --- 5. an rva overflow is rejected ----------------------------------------------------------
def test_rva_overflow_is_rejected():
    assert S.validate_locator_value('rva', 2 ** 64)
    assert S.validate_locator_value('rva', -1)
    assert S.validate_locator_value('rva', True)            # a bool is not a position
    with pytest.raises(KReadReject) as exc:
        regions.resolve_read(PINNED_REGION, 16, 2 ** 64 - 8)
    assert exc.value.reason in ('KREAD_OFFSET_OVERFLOW', 'KREAD_CROSS_REGION')


# --- 6. kbase + rva overflow is rejected ----------------------------------------------------
def test_kbase_plus_rva_overflow_is_rejected():
    nonzero = regions.resolve_read('amd_iommu', 0, 16)
    with pytest.raises(KReadReject) as exc:
        regions.checked_kernel_address(2 ** 64 - 8, nonzero.rva)
    assert exc.value.reason == 'KREAD_RUNTIME_OVERFLOW'
    with pytest.raises(KReadReject) as exc2:
        regions.resolve_runtime(nonzero, 2 ** 64 - 8)
    assert exc2.value.reason == 'KREAD_RUNTIME_OVERFLOW'
    assert S.validate_field_value('runtime_va', 2 ** 64)


# --- 7. a non-canonical resolved runtime VA is rejected --------------------------------------
def test_noncanonical_runtime_address_is_rejected():
    resolved = regions.resolve_read(PINNED_REGION, PINNED_OFFSET, PINNED_LENGTH)
    with pytest.raises(KReadReject) as exc:
        regions.resolve_runtime(resolved, 0x0001_0000_0000_0000)
    assert exc.value.reason == 'KREAD_NON_CANONICAL_ADDRESS'
    assert S.validate_field_value('runtime_va', 0x0001_0000_0000_0000)
    assert S.validate_field_value('runtime_va', 0xffff_ffff_998f_4000) == []


# --- 8. the image_elf profile binding is a PROFILE_MATCH ------------------------------------
def test_image_elf_profile_binding_is_a_profile_match():
    binding = boot_binding()
    verdict = S.profile_preconditions(PROFILE, boot_binding=binding,
                                      current_boot_id=binding.boot_id)
    assert verdict.matched is True
    assert S.PROFILE_MATCH in verdict.codes
    assert verdict.profile_sha256 == PROFILE_SHA == \
        '51b59db31ee47a9e2c5450ddfad002a80a407bf727f9ac5ae19558b82c3a4819'
    assert verdict.evidence_backed is True
    # and the W5 binding for the pinned window is bound (present, hashed, locator recorded)
    decision = decide()
    assert decision.outcome == 'GRANTED'
    full = KC.decide(REQUEST, registry=regions, profile=PROFILE, boot_binding=binding,
                     context=CONTEXT, capability=capability(boot_id=binding.boot_id),
                     recovery=False, provider=provider())
    assert full.stopped_at is None


# --- 9. the image_elf phase B simulation takes exactly one provider entry --------------------
def test_image_elf_phase_b_simulation_takes_exactly_one_provider_entry(tmp_path):
    report = KL.run_offline_simulation(store_root=tmp_path)
    assert report['ok'] is True, report['checks_failed']
    assert report['pinned']['region'] == PINNED_REGION
    assert report['pinned']['rva'] == 0 and report['pinned']['locator'] == 'kernel.attest.image_elf'
    assert report['phase_a']['outcome'] == KL.OUTCOME_VERIFIED
    assert report['phase_a']['provider_entries'] == 0
    assert report['phase_b']['outcome'] == KL.OUTCOME_READ
    assert report['phase_b']['provider_entries'] == 1
    assert report['accepted_contract_met'] is True
    assert report['blocker'] is None
    assert report['integration_finding']['id'] == 'W12-RVA0-BINDING'
    assert report['integration_finding']['payload_unchanged'] is True


# --- 10. UNRESOLVED is still rejected -------------------------------------------------------
def test_unresolved_states_are_still_rejected():
    unresolved = [name for name, region in regions.regions().items()
                  if region.identity_status == regions.IDENTITY_UNRESOLVED]
    assert unresolved, 'the registry must keep its fail-closed UNRESOLVED entries'
    with pytest.raises(KReadReject) as exc:
        regions.resolve_read(unresolved[0], 0, 8)
    assert exc.value.reason == 'KREAD_UNRESOLVED_REGION'
    # an unresolved field domain accepts nothing, and an unresolved locator is not a fact
    assert any('unresolved' in problem for problem in S.validate_field_value('gvm_id', 1))
    assert S.LOCATOR_VALUE_DOMAINS.get('unresolved') is None


# --- 11. STRUCTURAL_ONLY is still rejected for a strict read --------------------------------
def test_structural_only_is_still_rejected_for_a_strict_read():
    with pytest.raises(KReadReject) as exc:
        regions.resolve_read('aperture_global', 0, 8)
    assert exc.value.reason == 'KREAD_STRICT_IDENTITY_REQUIRED'
    # the explicit structural-only observation stays the one readable form
    assert regions.resolve_read('aperture_global', 0, 8, structural_only=True).rva == 37567992


# --- 12. a stale boot binding is still rejected ---------------------------------------------
def test_stale_boot_binding_is_still_rejected():
    # profile facts persist across a reboot, a runtime binding does not: this capability
    # belongs to the current boot, the binding presented is from an earlier one.
    current = boot_binding()
    stale = BootBinding(boot_id='BOOT-' + '0' * 16, profile_sha256=PROFILE_SHA)
    decision = KC.decide(REQUEST, registry=regions, profile=PROFILE, boot_binding=stale,
                         context=CONTEXT, capability=capability(boot_id=current.boot_id),
                         recovery=False, provider=provider())
    assert decision.outcome == 'REJECTED'
    assert KC.KREAD_STALE_BOOT_ID in decision.reasons
    assert decision.provider_entry is False
    assert decision.stopped_at == 'boot_binding'
    # and the bound (current) boot still grants, so the difference is exactly the stale binding
    assert decide().outcome == 'GRANTED'


# --- 13. a wrong profile is still rejected --------------------------------------------------
def test_wrong_profile_is_still_rejected():
    fixture = dict(PROFILE, fixture=True)
    decision = decide(profile=fixture)
    assert decision.outcome == 'REJECTED'
    assert KC.KREAD_WRONG_PROFILE in decision.reasons
    assert decision.provider_entry is False
    # a profile that is not the stored one is refused by the same rule
    tampered = json.loads(json.dumps(PROFILE))
    tampered['target']['firmware_build_id'] = 'TAMPERED'
    assert KC.decide(REQUEST, registry=regions, profile=tampered, boot_binding=boot_binding(),
                     context=CONTEXT, capability=capability(boot_id=boot_binding().boot_id),
                     recovery=False, provider=provider()).provider_entry is False
