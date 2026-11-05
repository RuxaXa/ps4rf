"""W12 verification tests: the separate flow, the bootstrap path, and every mutant.

The capability path may not verify itself (W4/F1 run separation), so this file drives the
verification module with a matching read plus one mutation per row: byte count, output
SHA-256, a re-used run, a missing separation declaration, a stale boot, a wrong profile, a
request that smuggled an address, and a MOCK authority. Every mutant must leave the
requirement at ``DEFERRED`` with the exact problem text. The bootstrap verification (owner
review item 1) is shown completing while the generic ``kernel.read`` is still ``DEFERRED``.
Offline, deterministic, no console, no network.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:                      # pragma: no cover - import bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from tools.hostctl import bootpriv                                        # noqa: E402
from tools.hostctl import kreadverify as KV                               # noqa: E402
from tools.primitive_iface import gate as w4_gate                         # noqa: E402
from tools.profiles import bootid, kread                                  # noqa: E402
from tools.profiles import kread_capability as KC                         # noqa: E402
from tools.profiles import regions, schema as profile_schema              # noqa: E402
from tools.profiles.binding import BootBinding                            # noqa: E402

PROFILE = json.loads((REPO_ROOT / 'profiles' / 'fw1352' / 'profile-13.52.json').read_text())
PROFILE_SHA256 = profile_schema.canonical_profile_sha256(PROFILE)
BOOT_ID = bootid.derive_boot_id(PROFILE_SHA256, bootid.BootTime(1789910256, 860896),
                                profile=PROFILE)['boot_id']
BOOT_BINDING = BootBinding.from_profile(PROFILE, BOOT_ID)
SESSION_ID = 'SES-' + '0' * 16
READ_RUN = 'RUN-' + '1' * 32
VERIFY_RUN = 'RUN-' + '2' * 32
PROVIDER_NAME = 'ps4rfd-kread-privileged'
RUNTIME_KBASE = 0xffffffff998f4000
RETURNED_BYTES = bytes(range(16))
RETURNED_SHA256 = hashlib.sha256(RETURNED_BYTES).hexdigest()

REGION = sorted(name for name, region in regions.regions().items()
                if region.identity_status == regions.IDENTITY_STRICT and region.length >= 16)[0]
_REGION = regions.get_region(REGION)
assert _REGION is not None                                              # frozen registry fact
REGION_RVA = int(_REGION.rva)
UNRESOLVED_REGION = next(name for name, region in regions.regions().items()
                         if region.identity_status == regions.IDENTITY_UNRESOLVED)
STRUCTURAL_REGION = next(name for name, region in regions.regions().items()
                         if region.identity_status == regions.IDENTITY_STRUCTURAL_ONLY)


def _request(**over) -> dict:
    request = {'operation': 'kernel.read', 'region': REGION, 'offset': 0, 'length': 16}
    request.update(over)
    return request


def _verification(**over) -> dict:
    verification = {'run_id': VERIFY_RUN, 'operation': 'verify.kernel.read', 'outcome': 'PASS',
                    'capability': 'kernel.read', 'provider': PROVIDER_NAME,
                    'provider_type': 'NATIVE', 'session_id': SESSION_ID, 'boot_id': BOOT_ID,
                    'separate_from_read': True}
    verification.update(over)
    return verification


def _capability(**over) -> dict:
    record = {'name': 'kernel.read', 'availability': 'AVAILABLE', 'assurance': 'PROVEN',
              'context': 'JAILBROKEN_PROCESS', 'provider': PROVIDER_NAME,
              'provider_type': 'NATIVE', 'scope': 'SESSION', 'session_id': SESSION_ID,
              'boot_id': BOOT_ID, 'verification': _verification(),
              'evidence_ref': {'run_id': VERIFY_RUN, 'sha256': 'b' * 64},
              'approval': {'approved': True, 'state': 'APPROVED', 'id': 'CMR-test-1'}}
    record.update(over)
    return record


def _provider(**over) -> dict:
    provider = {'name': PROVIDER_NAME, 'provider_type': 'NATIVE', 'state': 'WIRED',
                'live_approved': True}
    provider.update(over)
    return provider


def _decide(request: dict | None = None, **over) -> KC.GateDecision:
    kwargs = dict(registry=regions, profile=PROFILE, boot_binding=BOOT_BINDING,
                  context='JAILBROKEN_PROCESS', capability=_capability(), recovery=False,
                  provider=_provider())
    kwargs.update(over)
    return KC.decide(_request() if request is None else request, **kwargs)


def _evidence(**over) -> dict:
    """The read evidence of one GRANTED generic read, then mutated by the caller."""
    request = _request()
    decision = _decide(request)
    assert decision.provider_entry is True
    evidence = KC.read_evidence(request, decision, run_id=READ_RUN,
                                bytes_hex=RETURNED_BYTES.hex(), runtime_kbase=RUNTIME_KBASE,
                                verification=_verification())
    evidence.update(over)
    return evidence


EXPECTED = {'region': REGION, 'bytes_hex': RETURNED_BYTES.hex(), 'sha256': RETURNED_SHA256,
            'length': 16, 'provider': PROVIDER_NAME, 'runtime_base': RUNTIME_KBASE}


def _verify(request: dict | None = None, evidence: dict | None = None, **over) -> dict:
    kwargs = dict(profile=PROFILE, boot_binding=BOOT_BINDING, expected=dict(EXPECTED))
    kwargs.update(over)
    return KV.verify_read_evidence(_request() if request is None else request,
                                   _evidence() if evidence is None else evidence, **kwargs)


def _not_verified(report: dict, problem: str) -> None:
    assert report['verified'] is False
    assert report['outcome'] == KV.OUTCOME_NOT_VERIFIED
    assert report['outcome'] != 'PROVEN'
    assert report['requirement_before'] == KV.REQUIREMENT_DEFERRED
    assert report['requirement_after'] == KV.REQUIREMENT_DEFERRED
    assert problem in report['problems'], report['problems']


# --- the matching read (positive) -------------------------------------------------------
def test_matching_read_with_a_separate_verification_run_makes_the_requirement_eligible():
    report = _verify()
    assert report['verified'] is True
    assert report['outcome'] == KV.OUTCOME_PROVEN
    assert report['problems'] == []
    assert report['requirement_before'] == KV.REQUIREMENT_DEFERRED
    assert report['requirement_after'] == KV.REQUIREMENT_ELIGIBLE
    assert report['run_separate'] is True
    assert report['verification_path'] == 'GENERIC'
    assert report['request_contained_address'] is False
    assert report['resolved_address_in_evidence'] == REGION_RVA
    assert report['resolved_rva_in_evidence'] == REGION_RVA
    assert report['resolved_runtime_va_in_evidence'] == RUNTIME_KBASE + REGION_RVA
    assert report['resolved_region'] == REGION
    assert report['resolved_offset'] == 0
    assert report['resolved_length'] == 16
    assert report['requested_length'] == 16
    assert report['observed_length'] == 16
    assert report['lengths_matched'] is True
    assert all(check['ok'] for check in report['checks'])


def test_evidence_returns_bytes_that_hash_to_the_claimed_output_sha256():
    """What the read covered is verified: the bytes hash to the claimed hash, length exact."""
    evidence = _evidence()
    assert hashlib.sha256(bytes.fromhex(evidence['bytes_hex'])).hexdigest() \
        == evidence['output_sha256'] == RETURNED_SHA256
    assert evidence['observed_length'] == evidence['requested_length'] == 16


# --- the bootstrap path (owner review item 1): no circular dependency -------------------
def test_bootstrap_verification_completes_while_the_generic_read_is_still_deferred():
    # the fixed window is genuinely compile/profile-bound and comes from the registry
    assert KV.BOOTSTRAP_REGION == 'image_elf'
    assert KV.BOOTSTRAP_RVA == regions.get_region('image_elf').rva == 0x0
    assert KV.BOOTSTRAP_LENGTH == regions.get_region('image_elf').length == 16
    # boottime has no promoted W5 locator: it stays deferred for the generic provider and is never
    # the live bootstrap region
    assert KV.BOOTSTRAP_REGION != 'boottime'

    # the generic kernel.read with no verification record is DEFERRED before any bootstrap
    before = _decide(capability=_capability(verification=None))
    assert before.outcome == KC.DEFERRED and before.reasons == ['KREAD_NATIVE_OBSERVED_ONLY']
    assert before.provider_entry is False

    # the bootstrap read: the fixed region, resolved through the registry, arrives as a read
    # of the same evidence schema - and needs no granted generic kernel.read
    bootstrap_request = {'operation': 'kernel.read', 'region': KV.BOOTSTRAP_REGION,
                         'offset': KV.BOOTSTRAP_OFFSET, 'length': KV.BOOTSTRAP_LENGTH}
    resolved = regions.resolve_read(KV.BOOTSTRAP_REGION, KV.BOOTSTRAP_OFFSET, KV.BOOTSTRAP_LENGTH)
    assert resolved.address == KV.BOOTSTRAP_RVA
    bootstrap_bytes = bytes.fromhex('5c21ec69' * 4)          # image_elf is 16 bytes
    bootstrap_evidence = KC.fixed_read_evidence(
        bootstrap_request, resolved, run_id='RUN-' + '3' * 32, bytes_hex=bootstrap_bytes.hex(),
        runtime_kbase=RUNTIME_KBASE, profile_sha256=PROFILE_SHA256, boot_id=BOOT_ID,
        provider={'name': PROVIDER_NAME, 'provider_type': 'NATIVE'},
        verification=_verification())
    report = KV.verify_bootstrap_evidence(bootstrap_request, bootstrap_evidence, profile=PROFILE,
                                          boot_binding=BOOT_BINDING)
    assert report['verified'] is True
    assert report['outcome'] == KV.OUTCOME_PROVEN
    assert report['verification_path'] == 'BOOTSTRAP'
    assert report['requirement_before'] == KV.REQUIREMENT_DEFERRED
    assert report['requirement_after'] == KV.REQUIREMENT_ELIGIBLE

    # the generic read was still DEFERRED while the bootstrap ran: no circular dependency
    during = _decide(capability=_capability(verification=None))
    assert during.outcome == KC.DEFERRED and during.provider_entry is False

    # and only after the passing bootstrap verification may the generic bounded read proceed
    after = _decide()
    assert after.outcome == KC.GRANTED and after.provider_entry is True
    without_approval = _decide(provider=_provider(live_approved=False))
    assert without_approval.reasons == ['KREAD_LIVE_APPROVAL_REQUIRED']
    assert without_approval.provider_entry is False


def test_capability_gate_refuses_a_verification_declared_not_separate():
    # pre-live item 7: run separation is a pre-provider-entry assertion, not only a verify-side one
    d = _decide(capability=_capability(verification=_verification(separate_from_read=False)))
    assert d.outcome == KC.DEFERRED and d.reasons == ['KREAD_VERIFICATION_NOT_SEPARATE']
    assert d.provider_entry is False


def test_bootstrap_verification_refuses_a_window_that_is_not_the_fixed_one():
    request = {'operation': 'kernel.read', 'region': 'image_elf', 'offset': 0, 'length': 16}
    evidence = _evidence(requested_region='image_elf', requested_offset=0, requested_length=16,
                         resolved_rva=KV.BOOTSTRAP_RVA,
                         resolved_runtime_va=RUNTIME_KBASE + KV.BOOTSTRAP_RVA,
                         bytes_hex='5c21ec69' * 4,
                         output_sha256=hashlib.sha256(bytes.fromhex('5c21ec69' * 4)).hexdigest(),
                         observed_length=16)
    good = KV.verify_bootstrap_evidence(request, evidence, profile=PROFILE,
                                        boot_binding=BOOT_BINDING)
    assert good['verified'] is True
    drifted = dict(evidence, resolved_rva=KV.BOOTSTRAP_RVA + 8,
                   resolved_runtime_va=RUNTIME_KBASE + KV.BOOTSTRAP_RVA + 8)
    report = KV.verify_bootstrap_evidence(request, drifted, profile=PROFILE,
                                          boot_binding=BOOT_BINDING)
    _not_verified(report, 'BOOTSTRAP_LOCATOR_MISMATCH: the evidence resolved_rva '
                          f'{KV.BOOTSTRAP_RVA + 8:#x} != the compile-bound locator '
                          f'{KV.BOOTSTRAP_RVA:#x}')
    wrong_len = dict(evidence, requested_length=8, observed_length=8, bytes_hex='5c21ec69' * 2,
                     output_sha256=hashlib.sha256(bytes.fromhex('5c21ec69' * 2)).hexdigest())
    _not_verified(KV.verify_bootstrap_evidence(request, wrong_len, profile=PROFILE,
                                               boot_binding=BOOT_BINDING),
                  'BOOTSTRAP_LENGTH_MISMATCH: the evidence length 8 != the fixed bounded '
                  'expected length 16')


# --- the negative matrix ----------------------------------------------------------------
def test_mismatched_byte_count_is_not_verified():
    short = bytes(range(8))
    evidence = _evidence(bytes_hex=short.hex(), output_sha256=hashlib.sha256(short).hexdigest(),
                         observed_length=8)
    _not_verified(_verify(evidence=evidence),
                  'BYTE_COUNT_MISMATCH: the read returned 8 bytes but the requested length is 16')


def test_mismatched_output_sha256_is_not_verified():
    forged = '0' * 64
    _not_verified(_verify(evidence=_evidence(output_sha256=forged)),
                  'OUTPUT_SHA256_MISMATCH: the returned bytes hash to '
                  f'{RETURNED_SHA256} != the claimed {forged}')


def test_forged_verification_from_the_trigger_run_is_not_verified():
    """Field-perfect evidence whose verification run is the read run itself (W4/F1)."""
    evidence = _evidence(verification=_verification(run_id=READ_RUN))
    report = _verify(evidence=evidence)
    _not_verified(report, 'RUN_NOT_SEPARATE: verification run '
                          f'{READ_RUN} is the read run {READ_RUN}; a separate run is '
                          'required (W4/F1)')
    assert report['run_separate'] is False


def test_verification_without_the_separation_declaration_is_not_verified():
    evidence = _evidence(verification=_verification(separate_from_read=None))
    _not_verified(_verify(evidence=evidence),
                  'RUN_NOT_SEPARATE: the verification does not declare '
                  'separate_from_read=true (W4/F1)')


def test_missing_verification_declaration_is_not_verified():
    evidence = _evidence(verification=None)
    _not_verified(_verify(evidence=evidence),
                  'RUN_SEPARATION_UNDECLARED: the evidence carries no separate verification '
                  'run declaration')


def test_stale_boot_id_is_not_verified():
    stale = 'BOOT-' + '0' * 16
    evidence = _evidence(boot_id=stale)
    report = _verify(evidence=evidence)
    _not_verified(report,
                  f'STALE_BOOT_ID: the evidence references {stale} != current boot {BOOT_ID}')
    stale_binding = BootBinding(boot_id=stale, profile_sha256=PROFILE_SHA256)
    _not_verified(_verify(boot_binding=stale_binding),
                  f'STALE_BOOT_ID: the evidence references {BOOT_ID} != current boot {stale}')


def test_a_wrong_profile_is_not_verified():
    _not_verified(_verify(evidence=_evidence(profile_sha256='f' * 64)),
                  'PROFILE_SHA256_MISMATCH: the evidence references '
                  f'{"f" * 64} != current profile {PROFILE_SHA256}')
    foreign = BootBinding(boot_id=BOOT_ID, profile_sha256='f' * 64)
    _not_verified(_verify(boot_binding=foreign),
                  'PROFILE_SHA256_MISMATCH: the boot binding references '
                  f'{"f" * 64} != current profile {PROFILE_SHA256}')


def test_a_request_that_carried_a_raw_address_is_not_verified():
    request = _request(addr=RUNTIME_KBASE + REGION_RVA)
    report = _verify(request=request, evidence=_evidence())
    assert report['request_contained_address'] is True
    _not_verified(report, "REQUEST_CONTAINED_ADDRESS: the request carries address-ish field(s) "
                          "['addr']")


def test_evidence_from_a_mock_provider_is_not_verified():
    evidence = _evidence(provider={'name': 'mock-provider', 'provider_type': 'MOCK'})
    report = _verify(evidence=evidence)
    _not_verified(report, "PROVIDER_MISMATCH: provider type 'MOCK' is not allowed for "
                          "kernel.read (allowed: ['EXPLOIT', 'OPERATOR', 'NATIVE'])")
    assert "PROVIDER_MISMATCH: a MOCK provider can never be the authority for a privileged " \
           "read (W4 policy F11)" in report['problems']


def test_an_unknown_or_unresolved_region_is_not_verified():
    unknown = _evidence(requested_region='not_a_region')
    _not_verified(_verify(evidence=unknown),
                  "REGION_UNKNOWN: 'not_a_region' is not a registered W12 read region")
    unresolved = dict(_evidence(), requested_region=UNRESOLVED_REGION)
    _not_verified(_verify(request=_request(region=UNRESOLVED_REGION), evidence=unresolved,
                          expected={'region': UNRESOLVED_REGION, 'length': 16}),
                  f'REGION_UNRESOLVED: {UNRESOLVED_REGION!r} carries no identity source and '
                  'admits no read')


def test_a_structural_only_region_presented_as_strict_is_not_verified():
    region = regions.get_region(STRUCTURAL_REGION)
    evidence = dict(_evidence(), requested_region=STRUCTURAL_REGION, requested_length=16,
                    resolved_rva=int(region.rva),
                    resolved_runtime_va=RUNTIME_KBASE + int(region.rva))
    report = _verify(request=_request(region=STRUCTURAL_REGION),
                     evidence=evidence,
                     expected={'region': STRUCTURAL_REGION, 'length': 16,
                               'runtime_base': RUNTIME_KBASE})
    _not_verified(report, f'REGION_NOT_STRICT: {STRUCTURAL_REGION!r} is '
                          f'{regions.IDENTITY_STRUCTURAL_ONLY} and cannot establish a STRICT '
                          f'identity')
    assert any(check['check'] == 'region_is_known_strict' and not check['ok']
               for check in report['checks'])


def test_a_resolved_address_that_does_not_match_the_region_is_not_verified():
    _not_verified(_verify(evidence=_evidence(resolved_rva=REGION_RVA + 4)),
                  f'RESOLVED_RVA_MISMATCH: evidence {REGION_RVA + 4:#x} != region rva + offset '
                  f'{REGION_RVA:#x}')
    _not_verified(_verify(evidence=_evidence(resolved_rva=None)),
                  'RESOLVED_RVA_MISSING: the evidence records no resolved internal address')


def test_a_runtime_va_that_does_not_match_the_expected_base_is_not_verified():
    _not_verified(_verify(evidence=_evidence(resolved_runtime_va=RUNTIME_KBASE)),
                  f'RESOLVED_RUNTIME_VA_MISMATCH: evidence {RUNTIME_KBASE:#x} != runtime base + '
                  f'resolved_rva {RUNTIME_KBASE + REGION_RVA:#x}')


def test_the_expected_bytes_hash_and_length_are_checked():
    report = _verify(expected=dict(EXPECTED, bytes_hex='ab' * 16,
                                   sha256=hashlib.sha256(b'\xab' * 16).hexdigest()))
    _not_verified(report, 'EXPECTED_BYTES_MISMATCH: the returned bytes differ from the '
                          'expected bytes')
    report = _verify(expected=dict(EXPECTED, sha256='0' * 64))
    _not_verified(report, f'EXPECTED_SHA256_MISMATCH: the returned bytes hash to '
                          f'{RETURNED_SHA256} != expected {"0" * 64}')
    report = _verify(expected=dict(EXPECTED, length=8))
    _not_verified(report, 'EXPECTED_LENGTH_MISMATCH: requested length 16 != expected 8')


def test_a_requested_length_that_disagrees_with_the_evidence_is_not_verified():
    evidence = dict(_evidence(), requested_length=32)
    _not_verified(_verify(evidence=evidence),
                  'REQUESTED_LENGTH_MISMATCH: request 16 != evidence 32')


def test_an_offset_that_disagrees_with_the_evidence_is_not_verified():
    evidence = dict(_evidence(), requested_offset=8)
    _not_verified(_verify(evidence=evidence), 'OFFSET_MISMATCH: request 0 != evidence 8')


# --- no duplicated semantics (owner review item 6) --------------------------------------
def test_verification_reuses_the_frozen_request_model_registry_and_policy():
    from tools.dispatch import evidence as w7_evidence
    assert KV.kread is kread
    assert KV.regions is regions
    assert KV.REQ_BY_OP is w4_gate.REQ_BY_OP
    assert KV.canonical_profile_sha256 is profile_schema.canonical_profile_sha256
    assert KV.BootBinding is BootBinding
    assert KV.BOOTSTRAP_RVA == regions.get_region(KV.BOOTSTRAP_REGION).rva == 0x0
    assert KV.BOOTSTRAP_LENGTH == regions.get_region(KV.BOOTSTRAP_REGION).length == 16
    assert w7_evidence.REASON_TO_STEP['EVIDENCE_MISSING'] == 'w4_gate'
    source = pathlib.Path(KV.__file__).read_text()
    assert 'def parse_kread_request' not in source          # no local request model
    assert 'def resolve_read' not in source                 # no local registry
    assert 'def checked_add' not in source                  # no local bounds arithmetic
