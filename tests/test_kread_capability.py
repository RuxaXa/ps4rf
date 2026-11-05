"""W12 capability-path tests: the frozen chain, the exact reasons, the single provider entry.

One test per negative row of the wave matrix plus the positive flow. The module under test is a
pure decision function, so everything here is offline and deterministic: no console, no
network, no port 9090, no provider invocation. The fixtures drive the real wave artefacts (the
promoted fw1352 profile, its derived boot id, the W12 region registry) through the real W4/W5/W7
modules.
"""

from __future__ import annotations

import ast
import hashlib
import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:                      # pragma: no cover - import bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from tools.dispatch import matrix as router_matrix                                # noqa: E402
from tools.primitive_iface import gate as w4_gate                                 # noqa: E402
from tools.profiles import bootid, kread                                          # noqa: E402
from tools.profiles import kread_capability as KC                                 # noqa: E402
from tools.profiles import regions, schema as profile_schema, w4_adapter          # noqa: E402
from tools.profiles.binding import BootBinding                                    # noqa: E402

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

REGION = sorted(name for name, region in regions.regions().items()
                if region.identity_status == regions.IDENTITY_STRICT and region.length >= 16)[0]
_REGION = regions.get_region(REGION)
assert _REGION is not None                                              # frozen registry fact
REGION_RVA = _REGION.rva
REGION_LENGTH = _REGION.length
UNRESOLVED_REGION = next(name for name, region in regions.regions().items()
                         if region.identity_status == regions.IDENTITY_UNRESOLVED)
STRUCTURAL_REGION = next(name for name, region in regions.regions().items()
                         if region.identity_status == regions.IDENTITY_STRUCTURAL_ONLY)


def _request(**over) -> dict:
    request = {'operation': 'kernel.read', 'region': REGION, 'offset': 0, 'length': 16}
    request.update(over)
    return request


def _provider(**over) -> dict:
    provider = {'name': PROVIDER_NAME, 'provider_type': 'NATIVE', 'state': 'WIRED',
                'live_approved': True}
    provider.update(over)
    return provider


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


def _decide(request: dict | None = None, **over) -> KC.GateDecision:
    kwargs = dict(registry=regions, profile=PROFILE, boot_binding=BOOT_BINDING,
                  context='JAILBROKEN_PROCESS', capability=_capability(), recovery=False,
                  provider=_provider())
    kwargs.update(over)
    return KC.decide(_request() if request is None else request, **kwargs)


def _gate_context(**over) -> w4_gate.GateContext:
    """The same state the capability path hands the W4 gate, built directly for parity checks."""
    verdict = profile_schema.profile_preconditions(PROFILE, boot_binding=BOOT_BINDING,
                                                   current_boot_id=BOOT_ID)
    fields: dict = dict(capability_records=(_capability(),),
                        verification_records=(_verification(),),
                        evidence_refs=({'run_id': VERIFY_RUN, 'sha256': 'b' * 64},),
                        profile_binding=w4_adapter.profile_binding_for_gate('kernel.read',
                                                                            verdict),
                        session_id=SESSION_ID, boot_id=BOOT_ID, session_state='ACTIVE',
                        provider=PROVIDER_NAME, provider_type='NATIVE', wired=True,
                        approval={'approved': True, 'state': 'APPROVED', 'id': 'CMR-test-1'})
    fields.update(over)
    return w4_gate.GateContext(**fields)  # type: ignore[arg-type]


def _refused(decision: KC.GateDecision, reason: str, stage: str, outcome: str) -> None:
    assert decision.outcome == outcome
    assert decision.stopped_at == stage
    assert decision.reasons == [reason]
    assert decision.provider_entry is False


# --- the negative matrix: one test per row ----------------------------------------------
def test_unknown_region_is_refused_by_the_registry():
    _refused(_decide(_request(region='not_a_region')), 'KREAD_UNKNOWN_REGION', KC.STAGE_REGISTRY,
             KC.REJECTED)


def test_negative_offset_is_refused():
    _refused(_decide(_request(offset=-1)), 'KREAD_NEGATIVE_OFFSET', KC.STAGE_REGISTRY,
             KC.REJECTED)


def test_offset_overflow_is_refused():
    _refused(_decide(_request(offset=kread.U64_MAX)), 'KREAD_OFFSET_OVERFLOW',
             KC.STAGE_REGISTRY, KC.REJECTED)


def test_zero_length_is_refused():
    _refused(_decide(_request(length=0)), 'KREAD_LENGTH_ZERO', KC.STAGE_REGISTRY, KC.REJECTED)


def test_length_above_the_maximum_is_refused():
    _refused(_decide(_request(length=regions.MAX_READ_LEN + 1)), 'KREAD_LENGTH_EXCEEDS_MAX',
             KC.STAGE_REGISTRY, KC.REJECTED)


def test_cross_region_read_is_refused():
    _refused(_decide(_request(offset=REGION_LENGTH - 8, length=16)), 'KREAD_CROSS_REGION',
             KC.STAGE_REGISTRY, KC.REJECTED)
    # offset exactly at the region end, and offset + length one byte over the end
    _refused(_decide(_request(offset=REGION_LENGTH, length=16)), 'KREAD_CROSS_REGION',
             KC.STAGE_REGISTRY, KC.REJECTED)
    _refused(_decide(_request(offset=1, length=16)), 'KREAD_CROSS_REGION', KC.STAGE_REGISTRY,
             KC.REJECTED)


def test_an_unresolved_region_is_never_readable():
    _refused(_decide(_request(region=UNRESOLVED_REGION)), 'KREAD_UNRESOLVED_REGION',
             KC.STAGE_REGISTRY, KC.REJECTED)


def test_a_structural_only_region_is_not_readable_through_the_generic_path():
    """`aperture_global` stays STRUCTURAL_ONLY: it is not a trusted identity read region."""
    region = regions.get_region(STRUCTURAL_REGION)
    assert region.identity_status == regions.IDENTITY_STRUCTURAL_ONLY
    _refused(_decide(_request(region=STRUCTURAL_REGION, length=16)),
             'KREAD_STRICT_IDENTITY_REQUIRED', KC.STAGE_REGISTRY, KC.REJECTED)


@pytest.mark.parametrize('key', sorted(kread.RAW_ADDRESS_KEYS))
@pytest.mark.parametrize('style', ['lower', 'upper', 'title'])
def test_host_supplied_raw_address_fields_are_schema_rejects(key, style):
    """The request model owns this refusal: a raw address never reaches the registry."""
    spelled = getattr(key, style)()
    _refused(_decide(_request(**{spelled: RUNTIME_KBASE})), 'KREAD_SCHEMA_RAW_ADDRESS',
             KC.STAGE_REQUEST, KC.REJECTED)


def test_stale_boot_id_is_refused_before_any_provider_entry():
    """A binding from another boot stops the chain: no provider/kernel entry is recorded."""
    stale = BootBinding(boot_id='BOOT-' + '0' * 16, profile_sha256=PROFILE_SHA256)
    decision = _decide(boot_binding=stale)
    _refused(decision, 'KREAD_STALE_BOOT_ID', KC.STAGE_BOOT, KC.REJECTED)
    assert decision.effective_grant['boot_id'] == BOOT_ID


def test_wrong_profile_is_refused_before_any_provider_entry():
    fixture = dict(PROFILE, fixture=True)
    _refused(_decide(profile=fixture), 'KREAD_WRONG_PROFILE', KC.STAGE_W5, KC.REJECTED)
    foreign = BootBinding(boot_id=BOOT_ID, profile_sha256='f' * 64)
    _refused(_decide(boot_binding=foreign), 'KREAD_WRONG_PROFILE', KC.STAGE_W5, KC.REJECTED)
    _refused(_decide(capability=_capability(profile_sha256='f' * 64)), 'KREAD_WRONG_PROFILE',
             KC.STAGE_W5, KC.REJECTED)


def test_missing_verification_for_a_native_provider_is_deferred_observed_only():
    """F7, unchanged: a NATIVE provider alone never yields PROVEN."""
    decision = _decide(capability=_capability(verification=None))
    _refused(decision, 'KREAD_NATIVE_OBSERVED_ONLY', KC.STAGE_GRANT, KC.DEFERRED)
    assert decision.effective_grant['assurance'] == 'OBSERVED'


def test_missing_verification_for_a_non_native_provider_is_deferred():
    """Requesting the evidence-required level without any evidence record defers."""
    decision = _decide(capability=_capability(verification=None, provider_type='EXPLOIT'),
                       provider=_provider(provider_type='EXPLOIT'))
    _refused(decision, 'KREAD_VERIFICATION_MISSING', KC.STAGE_GRANT, KC.DEFERRED)


def test_a_verification_that_is_not_a_pass_is_deferred():
    decision = _decide(capability=_capability(verification=_verification(outcome='FAIL')))
    _refused(decision, 'KREAD_VERIFICATION_MISSING', KC.STAGE_GRANT, KC.DEFERRED)


def test_an_assurance_below_the_privileged_ceiling_is_deferred():
    """The W4 authority table demands PROVEN for the kernel namespace."""
    decision = _decide(capability=_capability(assurance='OBSERVED'))
    _refused(decision, 'ASSURANCE_TOO_LOW', KC.STAGE_GRANT, KC.DEFERRED)
    assert decision.effective_grant['assurance'] == 'OBSERVED'


def test_mock_proven_is_rejected_by_the_w4_provider_policy():
    """F11: MOCK never carries a privileged capability, even claiming PROVEN."""
    decision = _decide(capability=_capability(provider_type='MOCK'),
                       provider=_provider(provider_type='MOCK'))
    _refused(decision, 'KREAD_MOCK_PROVEN', KC.STAGE_GRANT, KC.REJECTED)


def test_recovery_required_after_capability_accept_stops_before_the_provider_entry():
    """Recovery arriving after the capability resolved still precedes any provider entry."""
    decision = _decide(recovery=True)
    _refused(decision, 'KREAD_RECOVERY_REQUIRED', KC.STAGE_RESOURCE, KC.REJECTED)
    # parity: the W4 gate is the central recovery gate and refuses the same state
    assert w4_gate.RECOVERY_REQUIRED in w4_gate.gate_for(
        'kernel.read', _gate_context(session_state='RECOVERY_REQUIRED')).reasons


def test_an_eligible_provider_without_live_approval_does_not_enter_the_provider():
    """ELIGIBLE is not execution: the live provider needs the explicit live-approval flag."""
    eligible = w4_gate.gate_for('kernel.read', _gate_context())
    assert eligible.decision == 'ELIGIBLE' and eligible.reasons == ()
    decision = _decide(provider=_provider(live_approved=False))
    _refused(decision, 'KREAD_LIVE_APPROVAL_REQUIRED', KC.STAGE_ROUTER, KC.DEFERRED)
    assert decision.provider_entry is False


def test_an_unwired_provider_is_deferred_by_the_w7_router():
    decision = _decide(provider=_provider(state='DEFERRED'))
    _refused(decision, w4_gate.NOT_WIRED, KC.STAGE_ROUTER, KC.DEFERRED)


# --- the positive flow ------------------------------------------------------------------
def test_positive_flow_grants_once_and_the_evidence_carries_the_resolved_address_only():
    request = _request()
    decision = _decide(request)
    assert decision.outcome == KC.GRANTED
    assert decision.stopped_at is None
    assert decision.reasons == []
    assert decision.provider_entry is True
    assert decision.effective_grant['granted'] is True
    assert decision.effective_grant['assurance'] == 'PROVEN'
    assert decision.effective_grant['profile_sha256'] == PROFILE_SHA256
    assert decision.effective_grant['boot_id'] == BOOT_ID
    assert decision.effective_grant['live_approved'] is True
    assert decision.resolved.rva + decision.resolved.offset == REGION_RVA

    evidence = KC.read_evidence(request, decision, run_id=READ_RUN,
                                bytes_hex=RETURNED_BYTES.hex(), runtime_kbase=RUNTIME_KBASE,
                                verification=_verification())
    assert evidence['schema'] == KC.EVIDENCE_SCHEMA
    assert evidence['operation'] == 'kernel.read'
    assert evidence['requested_region'] == REGION
    assert evidence['requested_offset'] == 0
    assert evidence['requested_length'] == 16
    assert evidence['resolved_rva'] == REGION_RVA
    assert evidence['resolved_rva'] != 0
    assert evidence['resolved_runtime_va'] == RUNTIME_KBASE + evidence['resolved_rva']
    assert evidence['observed_length'] == 16
    assert evidence['output_sha256'] == hashlib.sha256(RETURNED_BYTES).hexdigest()
    assert evidence['profile_sha256'] == PROFILE_SHA256
    assert evidence['boot_id'] == BOOT_ID
    assert evidence['read'] == {'single_callback': True, 'writes_to_kernel': False,
                                'host_supplied_address': False}
    # the resolved address exists only on the evidence side
    for key in ('resolved_rva', 'resolved_runtime_va', 'addr', 'address', 'va'):
        assert key not in request


def test_request_object_contains_no_address_anywhere():
    """Owner review item 3: the request carries region/offset/length and nothing address-like."""
    request = _request()
    assert sorted(request) == ['length', 'offset', 'operation', 'region']
    assert set(request) == set(KC.REQUEST_KEYS)
    for key in request:
        assert not kread.is_raw_address_key(key)
    assert all(isinstance(value, (str, int)) and not isinstance(value, bool)
               for value in request.values())
    assert not any(isinstance(value, (dict, list, tuple)) for value in request.values())


def test_read_evidence_refuses_a_sha256_claim_that_contradicts_the_returned_bytes():
    decision = _decide()
    with pytest.raises(ValueError, match='claimed output sha256'):
        KC.read_evidence(_request(), decision, run_id=READ_RUN, bytes_hex=RETURNED_BYTES.hex(),
                         runtime_kbase=RUNTIME_KBASE, output_sha256='0' * 64)
    with pytest.raises(ValueError, match='GRANTED decision'):
        refused = _decide(provider=_provider(state='DEFERRED'))
        assert refused.provider_entry is False
        KC.read_evidence(_request(), refused, run_id=READ_RUN,
                         bytes_hex=RETURNED_BYTES.hex(), runtime_kbase=RUNTIME_KBASE)
    # W12-RVA0-BINDING: the runtime resolution is checked arithmetic and names its refusal
    # (a u64 max base + rva is an overflow, not a canonicality problem).
    with pytest.raises(ValueError, match='KREAD_RUNTIME_OVERFLOW'):
        KC.read_evidence(_request(), decision, run_id=READ_RUN, bytes_hex=RETURNED_BYTES.hex(),
                         runtime_kbase=kread.U64_MAX)
    with pytest.raises(ValueError, match='KREAD_NON_CANONICAL_ADDRESS'):
        KC.read_evidence(_request(), decision, run_id=READ_RUN, bytes_hex=RETURNED_BYTES.hex(),
                         runtime_kbase=1 << 47)
    with pytest.raises(ValueError, match='KREAD_ZERO_RUNTIME_ADDRESS'):
        KC.read_evidence(_request(), decision, run_id=READ_RUN, bytes_hex=RETURNED_BYTES.hex(),
                         runtime_kbase=0)


# --- no duplicated semantics (owner review item 6) --------------------------------------
def test_gate_and_router_semantics_route_through_the_canonical_modules():
    """Parity: the W12 path calls the existing W4/W5/W7 modules and re-implements none."""
    assert KC.gate_for is w4_gate.gate_for
    assert KC.GateContext is w4_gate.GateContext
    assert KC.REQ_BY_OP is w4_gate.REQ_BY_OP
    assert KC.router_matrix is router_matrix
    assert KC.W7_REASON_TO_STEP is __import__('tools.dispatch.evidence',
                                              fromlist=['REASON_TO_STEP']).REASON_TO_STEP
    assert KC.w4_adapter is w4_adapter
    assert KC.profile_preconditions is profile_schema.profile_preconditions
    assert KC.regions is regions
    assert KC.kread is kread
    route = router_matrix.route_for('kernel.read')
    assert route['gated'] is True
    assert route['route'] == router_matrix.ROUTE_DEFERRED_PRIVILEGE
    assert set(KC.ADDRESSISH_KEYS) >= set(kread.RAW_ADDRESS_KEYS)


def test_the_provider_entry_is_set_by_exactly_one_statement():
    """`provider_entry` is the single entry point: one construction, only on GRANTED."""
    tree = ast.parse(pathlib.Path(KC.__file__).read_text())
    constructions = [node for node in ast.walk(tree)
                     if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                     and node.func.id == 'GateDecision']

    def sets(call, wanted):
        return any(kw.arg == 'provider_entry' and isinstance(kw.value, ast.Constant)
                   and kw.value.value is wanted for kw in call.keywords)

    true_calls = [call for call in constructions if sets(call, True)]
    false_calls = [call for call in constructions if sets(call, False)]
    assert len(constructions) == 2                      # the grant plus the refusal helper
    assert len(true_calls) == 1 and len(false_calls) == 1
    assert any(kw.arg == 'outcome' and getattr(kw.value, 'id', None) == 'GRANTED'
               for kw in true_calls[0].keywords)
    assert any(kw.arg == 'outcome' and getattr(kw.value, 'id', None) == 'outcome'
               for kw in false_calls[0].keywords)
    for row in (lambda: _decide(_request(region='not_a_region')), lambda: _decide(recovery=True),
                lambda: _decide(provider=_provider(live_approved=False))):
        assert row().provider_entry is False
