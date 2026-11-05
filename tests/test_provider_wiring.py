"""P4/W7 provider wiring: the central dispatch path, its refusals and its regressions.

Every scenario of the W7 work order is a test here. The productive path is
``Dispatcher.dispatch``; the only place a provider handler can be entered is
``Dispatcher._enter_provider`` (asserted structurally). All 14 privileged operations and
the host-chain operation stay ``OPERATION_DEFERRED`` even when every other prerequisite is
satisfied - W7 builds the way, not the primitive.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys
import threading

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from core.models.common import ProviderType  # noqa: E402
from core.models.capability import default_authority  # noqa: E402
from core.rpc.registry import default_registry  # noqa: E402
from tools.dispatch import evidence as EV  # noqa: E402
from tools.dispatch import matrix as MX  # noqa: E402
from tools.dispatch import providers as PR  # noqa: E402
from tools.dispatch import resources as RS  # noqa: E402
from tools.dispatch.dispatch import Dispatcher  # noqa: E402
from tools.primitive_iface import schema as W3  # noqa: E402
from tools.primitive_iface.gate import HOST_CHAIN_REQUIREMENTS, REQ_BY_OP  # noqa: E402
from tools.profiles import binding as W5B  # noqa: E402
from tools.primitive_iface import schema as SCHEMA

SID = 'SES-0123456789ABCDEF'
BID = 'BOOT-0123456789ABCDEF'
RUN = 'RUN-' + 'a' * 32
PROVIDER = 'native-provider'
TEST_PROVIDER = 'test-provider'
FIXTURE = REPO_ROOT / 'tests' / 'fixtures' / 'profiles' / 'concrete-fixture.json'
HOST = HOST_CHAIN_REQUIREMENTS[0]
SAMPLE = 'kernel.read'


def _fixture() -> dict:
    return json.loads(FIXTURE.read_text())


def _record(req, **overrides) -> dict:
    record = {
        'name': req.capability,
        'namespace': req.namespace,
        'verified_by_operation': req.verification_op,
        'availability': 'AVAILABLE',
        'assurance': req.min_assurance,
        'context': req.allowed_contexts[0],
        'provider': PROVIDER,
        'provider_type': 'NATIVE',
        'scope': 'SESSION',
        'session_id': SID,
        'boot_id': BID,
    }
    record.update(overrides)
    return record


def _verification(req, **overrides) -> dict:
    record = {
        'run_id': RUN,
        'operation': req.verification_op,
        'outcome': 'PASS',
        'capability': req.capability,
        'provider': PROVIDER,
        'provider_type': 'NATIVE',
        'session_id': SID,
        'boot_id': BID,
    }
    record.update(overrides)
    return record


def satisfied(op: str, **overrides) -> dict:
    """Every prerequisite except the wiring, derived from the W4 requirement."""
    req = REQ_BY_OP.get(op) or HOST
    kwargs: dict = dict(capability_records=(_record(req),),
                        verification_records=(_verification(req),),
                        evidence_refs=({'run_id': RUN, 'sha256': 'b' * 64},),
                        approval={'approved': True, 'state': 'APPROVED', 'id': 'CMR-1'})
    if req.profile_required:
        doc = _fixture()
        kwargs.update(profile=doc, boot_binding=W5B.BootBinding.from_profile(doc, BID),
                      require_evidence_backed=False)
    kwargs.update(overrides)
    return kwargs


def dispatcher(**overrides) -> Dispatcher:
    kwargs: dict = dict(run_id='RUN-' + 'b' * 32, session_id=SID, boot_id=BID,
                        context_label='HOMEBREW')
    kwargs.update(overrides)
    return Dispatcher(**kwargs)


def wired_dispatcher(op: str, provider: PR.Provider) -> tuple[Dispatcher, PR.TestProvider]:
    """A dispatcher whose route for ``op`` is served by an explicit TEST provider.

    Returns the dispatcher and the provider instance actually used, so a test can count
    its entries.
    """
    req = REQ_BY_OP.get(op) or HOST
    route = MX.route_for(op)['route']
    if provider.routes != (route,):
        provider = PR.TestProvider(provider.behaviour, routes=(route,))
    providers = {name: value for name, value in PR.default_providers().items()
                 if not value.handles(route)}
    providers[provider.name] = provider
    # the test provider impersonates the routed native provider: the capability and
    # verification records name the production provider type the requirement allows.
    impersonated = 'NATIVE'
    kwargs = satisfied(op, capability_records=(_record(req, provider=provider.name,
                                                       provider_type=impersonated),),
                       verification_records=(_verification(req, provider=provider.name,
                                                           provider_type=impersonated),),
                       providers=providers)
    return dispatcher(**kwargs), provider


def call(disp: Dispatcher, op: str, arguments: dict | None = None, *,
         before_entry=None, request_id: str = 'REQ-' + '1' * 32) -> dict:
    message = {'header': {'request_id': request_id},
               'body': {'operation': op, 'arguments': dict(arguments or {}), 'seq': 1}}
    return disp.dispatch(message, before_entry=before_entry)


def code_of(response: dict) -> str:
    return (response.get('error') or {}).get('code') or response.get('status')


def valid_arguments(op: str) -> dict:
    """Satisfy the frozen W3 argument schema of one operation."""
    values = {'int': 1, 'str': 'x', 'bool': True, 'ref': 'stub:0123456789ABCDEF',
              'hex32': 'a' * 64, 'array': [], 'object': {}}
    return {field.name: values[field.type] for field in W3.OPS_BY_NAME[op].args
            if field.required}


# --- 22. matrix parity ----------------------------------------------------------------
def test_every_registered_operation_is_routed_exactly_once():
    rows = MX.provider_matrix()
    assert len(rows) == len(SCHEMA.OPS)
    assert len({row['op'] for row in rows}) == len(SCHEMA.OPS)
    assert {row['op'] for row in rows} == set(W3.OPS_BY_NAME)
    for row in rows:
        assert row['route'] in MX.ROUTES
        assert row['provider']
        assert row['provider_state'] in PR.PROVIDER_STATES


def test_router_matrix_matches_w3_w4_and_w5_matrices():
    assert MX.parity_errors() == []
    counts: dict[str, int] = {}
    for row in MX.provider_matrix():
        counts[row['route']] = counts.get(row['route'], 0) + 1
    from tools.primitive_iface import schema as _S
    # W17F: every route class derives from its authoritative operation status (no class counts).
    _status_class = {_S.STATUS_STUB: 'stub', _S.STATUS_MOCK: 'mock_only',
                     _S.STATUS_DEFER_PRIVILEGE: 'deferred_privilege',
                     _S.STATUS_DEFER_CHAIN: 'deferred_host_chain'}
    _expected_counts = {v: 0 for v in _status_class.values()}
    _seen = []
    for _o in _S.OPS:
        _cls = _status_class.get(getattr(_o, 'status', None))
        if _cls:
            _expected_counts[_cls] += 1
            _seen.append(_o.op)
    _dupes = sorted({n for n in _seen if _seen.count(n) > 1})
    assert not _dupes, f'duplicate operations across status classes: {_dupes}'
    assert counts == _expected_counts, \
        f'router class counts {counts} != status-derived {_expected_counts}'
    # W17F: the router gated view is the union of the privileged- and host-chain-gated operations,
    # derived from the authoritative status semantics -- and cross-checked independently against the
    # route classification so gated_ops() and provider_matrix() cannot validate only each other.
    from tools.primitive_iface import schema as _S
    _expected_gated = {_o.op for _o in _S.OPS
                       if _o.status in (_S.STATUS_DEFER_PRIVILEGE, _S.STATUS_DEFER_CHAIN)}
    _gated = list(MX.gated_ops())
    _gdupes = sorted({n for n in _gated if _gated.count(n) > 1})
    assert not _gdupes, f'duplicate gated operations: {_gdupes}'
    assert set(_gated) == _expected_gated, (
        'gated operations differ from the status-derived set: missing '
        f'{sorted(_expected_gated - set(_gated))}, unexpected {sorted(set(_gated) - _expected_gated)}')
    _routed = {r['op'] for r in MX.provider_matrix()
               if r['route'] in (MX.ROUTE_DEFERRED_PRIVILEGE, MX.ROUTE_DEFERRED_HOST_CHAIN)}
    assert _routed == _expected_gated, (
        'gated route classes differ from the status-derived set: missing '
        f'{sorted(_expected_gated - _routed)}, unexpected {sorted(_routed - _expected_gated)}')


def test_router_matrix_self_test_is_clean():
    assert MX._self_test() == []


# --- 23.1-23.3 basic dispatch behaviour ----------------------------------------------
def test_unknown_operation_is_refused_fail_closed():
    disp = dispatcher()
    response = call(disp, 'kernel.exploit.all')
    assert code_of(response) == 'OPERATION_UNSUPPORTED'
    record = disp.evidence_records()[-1]
    assert record['stopped_at'] == 'operation_registry'
    assert record['provider_entry'] is False


def test_stub_operation_succeeds_through_the_router():
    direct = PR.StubProviderAdapter()
    disp = dispatcher()
    response = call(disp, 'session.ping')
    assert code_of(response) == 'OK'
    assert response['result']['pong'] is True
    direct_response = direct.enter(PR.InvocationContext(
        run_id='RUN-x', request_id='REQ-' + '2' * 32, operation='session.ping', arguments={},
        seq=1, provider_name='ps4rfd-stub', provider_type=None, profile_sha256=None,
        profile_binding=None, boot_id=BID, session_id=SID, context_label='HOMEBREW',
        capability=None, effective_assurance=None, resources=RS.RequestResourceView(
            disp.resources, request_id='REQ-' + '2' * 32),
        evidence=disp.evidence, route='stub', wired=True))
    assert direct_response.ok is True
    assert response['result'] == direct_response.result, 'stub semantics must be unchanged'
    record = disp.evidence_records()[-1]
    assert record['provider_entry'] is True and record['stopped_at'] is None
    assert record['selected_provider'] == 'ps4rfd-stub'


def test_mutating_stub_operation_allocates_through_the_central_manager():
    disp = dispatcher()
    response = call(disp, 'memory.alloc', {'size': 4096}, request_id='REQ-' + '3' * 32)
    assert code_of(response) == 'OK'
    record = disp.evidence_records()[-1]
    assert record['resource_changes'], 'resource changes must show up in evidence'
    assert all(re.fullmatch(r'[a-z][a-z0-9_]*:[0-9A-F]{16}', change['ref'])
               for change in record['resource_changes']), record['resource_changes']
    assert record['cleanup']['state'] in W3.CLEANUP_STATES
    assert record['cleanup'].get('reported_by') == 'provider', \
        'the W3 stub keeps its own bookkeeping; the record says so'


# --- 23.4 privileged operations stay deferred ----------------------------------------
@pytest.mark.parametrize('op', sorted(REQ_BY_OP))
def test_deferred_privilege_stays_deferred(op):
    disp = dispatcher()
    response = call(disp, op, valid_arguments(op))
    assert code_of(response) == 'OPERATION_DEFERRED'
    assert disp.evidence_records()[-1]['provider_entry'] is False


def test_privileged_operation_with_every_prerequisite_except_wiring_is_still_deferred():
    for op in (SAMPLE, 'gpuvm.map', 'keymgr.claim'):
        disp = dispatcher(**satisfied(op))
        response = call(disp, op, valid_arguments(op))
        assert code_of(response) == 'OPERATION_DEFERRED', op
        record = disp.evidence_records()[-1]
        assert record['provider_entry'] is False
        assert record['stopped_at'] == 'provider_router', op
        assert record['w4_reasons'] == ['NOT_WIRED'], op


def test_host_chain_operation_is_deferred_and_not_classified_as_native_privileged():
    route = MX.route_for('verify.userland.exec')
    assert route['route'] == MX.ROUTE_DEFERRED_HOST_CHAIN
    disp = dispatcher(**satisfied('verify.userland.exec'))
    response = call(disp, 'verify.userland.exec', {'probe': 'selftest'})
    assert code_of(response) == 'OPERATION_DEFERRED'
    assert disp.evidence_records()[-1]['selected_provider'] == 'host-chain-provider'
    assert disp.evidence_records()[-1]['provider_entry'] is False


# --- 23.5-23.7 refusals that must prevent provider entry -----------------------------
def test_w4_failure_prevents_provider_entry():
    disp = dispatcher(**satisfied(SAMPLE, capability_records=()))
    response = call(disp, SAMPLE, {'region_index': 1, 'offset': 0, 'length': 16})
    record = disp.evidence_records()[-1]
    assert code_of(response) == 'OPERATION_DEFERRED'
    assert 'CAPABILITY_MISSING' in record['w4_reasons']
    assert record['stopped_at'] == 'capability_resolution'
    assert record['provider_entry'] is False


def test_w5_profile_mismatch_prevents_provider_entry():
    other = json.loads((REPO_ROOT / 'tests' / 'fixtures' / 'profiles' /
                        'fw900-fixture.json').read_text())
    disp = dispatcher(**satisfied(SAMPLE, profile=other,
                                  boot_binding=W5B.BootBinding.from_profile(other, BID)))
    response = call(disp, SAMPLE, {'region_index': 1, 'offset': 0, 'length': 16})
    record = disp.evidence_records()[-1]
    assert code_of(response) == 'OPERATION_DEFERRED'
    assert 'PROFILE_UNBOUND' in record['w4_reasons']
    assert 'NOT_WIRED' in record['w4_reasons']
    assert record['stopped_at'] == 'w5_profile_binding'
    assert record['provider_entry'] is False


def test_recovery_state_prevents_provider_entry():
    disp = dispatcher()
    disp.poison('test')
    response = call(disp, 'memory.alloc', {'size': 64})
    record = disp.evidence_records()[-1]
    assert code_of(response) == 'SESSION_RECOVERY_REQUIRED'
    assert record['stopped_at'] == 'resource_policy'
    assert record['provider_entry'] is False


def test_recovery_poison_before_entry_keeps_the_provider_untouched():
    # a mutating operation that is not recovery_safe: the frozen rule refuses it
    provider = PR.TestProvider('success')
    disp, provider = wired_dispatcher('gpuvm.map', provider)
    arguments = valid_arguments('gpuvm.map')
    response = call(disp, 'gpuvm.map', arguments,
                    before_entry=lambda op, req: disp.poison('poison before entry'))
    record = disp.evidence_records()[-1]
    assert code_of(response) == 'SESSION_RECOVERY_REQUIRED'
    assert record['stopped_at'] == 'resource_policy'
    assert provider.entries == 0, 'the provider must not be entered'
    assert record['provider_entry'] is False
    assert 'RECOVERY_REQUIRED' not in record['w4_reasons'], \
        'the central check stops the request before the gate is even consulted'


def test_mock_privileged_prevents_provider_entry_f11():
    req = REQ_BY_OP[SAMPLE]
    disp = dispatcher(**satisfied(SAMPLE,
                                  capability_records=(_record(req, provider_type='MOCK',
                                                              provider='mock-provider'),),
                                  verification_records=(_verification(req, provider_type='MOCK'),)))
    response = call(disp, SAMPLE, {'region_index': 1, 'offset': 0, 'length': 16})
    record = disp.evidence_records()[-1]
    assert code_of(response) == 'OPERATION_DEFERRED'
    assert 'PROVIDER_NOT_ALLOWED' in record['w4_reasons']
    assert record['stopped_at'] == 'effective_grant'
    assert record['provider_entry'] is False


# --- 18. authority integration -------------------------------------------------------
def test_native_available_observed_cannot_satisfy_a_privileged_proven_requirement():
    req = REQ_BY_OP[SAMPLE]
    assert req.min_assurance == 'PROVEN'
    disp = dispatcher(**satisfied(SAMPLE,
                                  capability_records=(_record(req, assurance='OBSERVED'),)))
    response = call(disp, SAMPLE, {'region_index': 1, 'offset': 0, 'length': 16})
    record = disp.evidence_records()[-1]
    assert code_of(response) == 'OPERATION_DEFERRED'
    assert 'ASSURANCE_TOO_LOW' in record['w4_reasons']
    assert record['stopped_at'] == 'effective_grant'
    assert record['provider_entry'] is False


def test_native_provider_without_verification_evidence_is_deferred():
    disp = dispatcher(**satisfied(SAMPLE, verification_records=(),
                                  evidence_refs=()))
    response = call(disp, SAMPLE, {'region_index': 1, 'offset': 0, 'length': 16})
    record = disp.evidence_records()[-1]
    assert code_of(response) == 'OPERATION_DEFERRED'
    assert 'EVIDENCE_MISSING' in record['w4_reasons']
    assert record['stopped_at'] == 'w4_gate'
    assert record['provider_entry'] is False


def test_verification_evidence_cannot_bypass_the_profile_gate():
    other = json.loads((REPO_ROOT / 'tests' / 'fixtures' / 'profiles' /
                        'fw900-fixture.json').read_text())
    disp = dispatcher(**satisfied(SAMPLE, profile=other,
                                  boot_binding=W5B.BootBinding.from_profile(other, BID)))
    response = call(disp, SAMPLE, {'region_index': 1, 'offset': 0, 'length': 16})
    record = disp.evidence_records()[-1]
    assert code_of(response) == 'OPERATION_DEFERRED'
    assert 'PROFILE_UNBOUND' in record['w4_reasons']
    assert record['stopped_at'] == 'w5_profile_binding'
    assert record['provider_entry'] is False


def test_profile_match_cannot_bypass_the_verification_requirement():
    disp = dispatcher(**satisfied(SAMPLE, verification_records=(),
                                  evidence_refs=(), wired_ops=(SAMPLE,)))
    response = call(disp, SAMPLE, {'region_index': 1, 'offset': 0, 'length': 16})
    record = disp.evidence_records()[-1]
    assert code_of(response) == 'OPERATION_DEFERRED'
    assert 'EVIDENCE_MISSING' in record['w4_reasons']
    assert record['provider_entry'] is False


def test_fully_wired_test_provider_enters_exactly_once():
    provider = PR.TestProvider('success')  # routes: host chain, as wired_dispatcher expects
    disp, provider = wired_dispatcher(HOST.op, provider)
    response = call(disp, HOST.op, {'probe': 'selftest'})
    record = disp.evidence_records()[-1]
    assert code_of(response) == 'OK'
    assert provider.entries == 1
    assert record['provider_entry'] is True
    assert record['selected_provider'] == TEST_PROVIDER
    assert response['result']['verified'] is False, 'a test provider claims no verification'


def test_wired_flag_alone_does_not_enter_a_deferred_provider():
    provider = PR.TestProvider('success')
    disp, provider = wired_dispatcher(SAMPLE, provider)
    provider.state = 'DEFERRED'          # wired flag set, provider nonetheless deferred
    response = call(disp, SAMPLE, {'region_index': 1, 'offset': 0, 'length': 16})
    record = disp.evidence_records()[-1]
    assert code_of(response) == 'OPERATION_DEFERRED'
    assert record['stopped_at'] == 'provider_router'
    assert record['provider_entry'] is False
    assert provider.entries == 0, 'a deferred provider is never entered'


# --- 19. provider faults -------------------------------------------------------------
@pytest.mark.parametrize('behaviour,expected', [
    ('failure', 'RESOURCE_STATE_INVALID'),
    ('raise', 'INTERNAL_ERROR'),
])
def test_provider_faults_are_mapped_to_frozen_error_codes(behaviour, expected):
    provider = PR.TestProvider(behaviour)
    disp, provider = wired_dispatcher(HOST.op, provider)
    response = call(disp, HOST.op, {'probe': 'selftest'})
    assert code_of(response) == expected
    assert expected in W3.ERROR_CODES
    record = disp.evidence_records()[-1]
    assert record['provider_entry'] is True
    assert 'Traceback' not in json.dumps(response)
    if behaviour == 'raise':
        assert record['error_detail'] and 'scripted provider fault' in record['error_detail']


def test_provider_resource_failure_is_cleaned_and_recorded():
    provider = PR.TestProvider('allocate_then_fail')
    disp, provider = wired_dispatcher(HOST.op, provider)
    response = call(disp, HOST.op, {'probe': 'selftest'})
    record = disp.evidence_records()[-1]
    assert code_of(response) == 'RESOURCE_LIMIT'
    assert record['cleanup']['state'] == 'COMPLETE', 'the held ref is released centrally'
    assert record['cleanup']['request_owned'], 'the allocated ref must be attributed'
    assert record['resource_changes'][0]['event'] == 'ACQUIRED'
    assert disp.session_state == 'ACTIVE', 'a successful cleanup needs no recovery'


def test_cleanup_failure_marks_the_session_for_recovery():
    provider = PR.TestProvider('cleanup_fail')
    disp, provider = wired_dispatcher(HOST.op, provider)
    response = call(disp, HOST.op, {'probe': 'selftest'})
    record = disp.evidence_records()[-1]
    assert code_of(response) == 'OK'
    assert record['cleanup']['state'] == 'PARTIAL'
    assert disp.session_state == 'RECOVERY_REQUIRED'
    follow_up = call(disp, 'memory.alloc', {'size': 64}, request_id='REQ-' + '4' * 32)
    assert code_of(follow_up) == 'SESSION_RECOVERY_REQUIRED'
    assert disp.evidence.for_request('REQ-' + '4' * 32)[-1]['provider_entry'] is False


def test_provider_receives_validated_arguments_only():
    provider = PR.TestProvider('success')
    disp, provider = wired_dispatcher(HOST.op, provider)
    response = call(disp, HOST.op, {'probe': 12345})       # wrong type: T is a string
    assert code_of(response) == 'ARGUMENT_INVALID'
    assert provider.entries == 0
    record = disp.evidence_records()[-1]
    assert record['stopped_at'] == 'rpc_validation'
    assert record['provider_entry'] is False


# --- 20. concurrency -----------------------------------------------------------------
def test_concurrent_requests_stay_isolated():
    provider = PR.TestProvider('success')
    provider.release.clear()
    disp, provider = wired_dispatcher(HOST.op, provider)
    provider.release.clear()
    results: dict[str, str] = {}
    tail: dict[str, str] = {}

    def work(index: int) -> None:
        request_id = f'REQ-{index:032x}'
        response = call(disp, HOST.op, {'probe': f'p{index}'}, request_id=request_id)
        results[request_id] = code_of(response)
        records = disp.evidence.for_request(request_id)
        tail[request_id] = records[-1]['request_id']

    threads = [threading.Thread(target=work, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    provider.release.set()
    for thread in threads:
        thread.join(timeout=10)
    assert len(results) == 6 and set(results.values()) == {'OK'}
    assert all(request_id == tail[request_id] for request_id in results), \
        'evidence records must stay with their own request'
    assert provider.entries == 6
    assert len({record['request_id'] for record in disp.evidence_records()}) == 6


def test_max_inflight_is_enforced():
    provider = PR.TestProvider('hang')
    provider.release.clear()
    disp, provider = wired_dispatcher(HOST.op, provider)
    provider.release.clear()
    disp._semaphore = threading.BoundedSemaphore(2)      # documented test override
    responses: list[str] = []

    def work(index: int) -> None:
        responses.append(code_of(call(disp, HOST.op, {'probe': f'p{index}'},
                                      request_id=f'REQ-{index:032x}')))

    threads = [threading.Thread(target=work, args=(i,)) for i in range(5)]
    for thread in threads:
        thread.start()
    import time
    time.sleep(0.2)
    provider.release.set()
    for thread in threads:
        thread.join(timeout=10)
    assert 'TOO_MANY_INFLIGHT' in responses
    assert len(disp.evidence.for_request('REQ-' + f'{4:032x}')) <= 1


def test_foreign_resource_ref_cannot_be_adopted():
    central = RS.ResourceManager()
    first = RS.RequestResourceView(central, request_id='REQ-' + '5' * 32)
    second = RS.RequestResourceView(central, request_id='REQ-' + '6' * 32)
    ref = first.acquire('native')
    assert second.release(ref) is False
    assert second.attach_cleanup(ref, lambda: True) is None or second.violations()
    assert second.violations(), 'the attempt must be recorded'


# --- 17. profile integration ---------------------------------------------------------
def test_reboot_invalidates_the_previous_boot_binding():
    doc = _fixture()
    new_boot = 'BOOT-' + 'f' * 16
    disp = dispatcher(boot_id=new_boot, **satisfied(
        SAMPLE, capability_records=(_record(REQ_BY_OP[SAMPLE], boot_id=new_boot),),
        verification_records=(_verification(REQ_BY_OP[SAMPLE], boot_id=new_boot),),
        boot_binding=W5B.BootBinding.from_profile(doc, BID)))
    response = call(disp, SAMPLE, {'region_index': 1, 'offset': 0, 'length': 16})
    record = disp.evidence_records()[-1]
    assert code_of(response) == 'OPERATION_DEFERRED'
    assert 'PROFILE_UNBOUND' in record['w4_reasons']
    assert record['stopped_at'] == 'w5_profile_binding'
    assert record['provider_entry'] is False
    # a fresh binding for the current boot restores the profile part (nothing else)
    disp2 = dispatcher(boot_id=new_boot, **satisfied(
        SAMPLE, capability_records=(_record(REQ_BY_OP[SAMPLE], boot_id=new_boot),),
        verification_records=(_verification(REQ_BY_OP[SAMPLE], boot_id=new_boot),),
        boot_binding=W5B.BootBinding.from_profile(doc, new_boot)))
    record2 = disp2.evidence_records()
    call(disp2, SAMPLE, {'region_index': 1, 'offset': 0, 'length': 16})
    record2 = disp2.evidence_records()[-1]
    assert 'PROFILE_UNBOUND' not in record2['w4_reasons']
    assert record2['stopped_at'] == 'provider_router'
    assert record2['provider_entry'] is False, 'a new binding still does not wire a provider'


# --- 16. W6 findings are metadata ----------------------------------------------------
def test_w6_candidate_has_zero_authorization_effect():
    candidate = {'schema': 'ps4rf.differential.candidate.v1', 'status': 'OBSERVATION',
                 'finding': {'classification': 'MOVED', 'subject': 'kernel.read'},
                 'impact': {'w4': 'NONE'}}
    baseline = dispatcher(**satisfied(SAMPLE, metadata={}))
    with_candidate = dispatcher(**satisfied(SAMPLE,
                                            metadata={'w6_candidates': [candidate]}))
    base_response = call(baseline, SAMPLE, {'region_index': 1, 'offset': 0, 'length': 16})
    cand_response = call(with_candidate, SAMPLE, {'region_index': 1, 'offset': 0, 'length': 16})
    assert code_of(base_response) == code_of(cand_response) == 'OPERATION_DEFERRED'
    assert (baseline.evidence_records()[-1]['w4_reasons']
            == with_candidate.evidence_records()[-1]['w4_reasons'] == ['NOT_WIRED'])
    assert with_candidate.evidence_records()[-1]['metadata'] == {'w6_candidates': [candidate]}
    assert with_candidate.evidence_records()[-1]['provider_entry'] is False


# --- 21. F7 to F11 regressions -------------------------------------------------------
def test_f7_native_provider_type_exists_and_is_conservative():
    assert ProviderType.NATIVE.value == 'NATIVE'
    authority = default_authority()
    native_rules = [r for r in authority.rules if r.provider_type is ProviderType.NATIVE]
    assert len(native_rules) == 1
    rule = native_rules[0]
    assert rule.max_assurance.value == 'OBSERVED', 'a native provider alone can never be PROVEN'
    assert rule is authority.rule_for(PROVIDER, ProviderType.NATIVE, PROVIDER)
    assert authority.min_assurance_for_grant['kernel'].value == 'PROVEN'
    assert {r.provider_type for r in authority.rules if r.max_assurance.value == 'PROVEN'}         == {ProviderType.EXPLOIT, ProviderType.MOCK, ProviderType.OPERATOR}


def test_f8_kernel_read_class_stays_mutating_in_the_core():
    registry = default_registry()
    for op in ('kernel.read', 'kernel.snapshot', 'kernel.dump.full'):
        assert registry.spec(op).mutating is True, op
        assert W3.OPS_BY_NAME[op].mutating is True, op


def test_f9_native_memory_alloc_still_requires_size():
    field = next(field for field in W3.OPS_BY_NAME['memory.alloc'].args
                 if field.name == 'size')
    assert field.required is True
    disp = dispatcher()
    response = call(disp, 'memory.alloc', {})
    assert code_of(response) == 'ARGUMENT_INVALID'
    assert disp.evidence_records()[-1]['provider_entry'] is False


def test_f10_sync_flags_match_the_frozen_core_registry():
    registry = default_registry()
    for op, spec in W3.OPS_BY_NAME.items():
        if not spec.family == 'sync':
            continue
        core = registry.spec(op)
        assert (spec.mutating, spec.recovery_safe) == (core.mutating, core.recovery_safe), op


def test_f11_mock_proven_can_never_reach_a_privileged_provider():
    req = REQ_BY_OP['gpuvm.map']
    disp = dispatcher(**satisfied(req.op, capability_records=(
        _record(req, provider_type='MOCK', provider='mock-provider'),),
        verification_records=(_verification(req, provider_type='MOCK'),)))
    response = call(disp, req.op, valid_arguments(req.op))
    record = disp.evidence_records()[-1]
    assert code_of(response) == 'OPERATION_DEFERRED'
    assert 'PROVIDER_NOT_ALLOWED' in record['w4_reasons']
    assert record['provider_entry'] is False


# --- 10. no alternate provider entry path --------------------------------------------
def test_the_only_provider_entry_site_is_enter_provider():
    package = REPO_ROOT / 'tools' / 'dispatch'
    calls = []
    for path in sorted(package.glob('*.py')):
        text = path.read_text()
        for match in re.finditer(r'(\w+)\.enter\(', text):
            line_no = text[:match.start()].count('\n') + 1
            calls.append((path.name, line_no, match.group(0)))
    assert calls, 'the entry site must exist'
    assert {name for name, _, _ in calls} == {'dispatch.py'}, calls
    assert len(calls) == 1, f'exactly one call site expected, found {calls}'
    dispatch_text = (package / 'dispatch.py').read_text()
    assert dispatch_text.count('return provider.enter(ctx)') == 1
    assert 'def _enter_provider' in dispatch_text


def test_evidence_fields_are_complete_for_every_dispatch():
    disp = dispatcher()
    call(disp, 'session.ping', request_id='REQ-' + '7' * 32)
    call(disp, SAMPLE, {'region_index': 1, 'offset': 0, 'length': 16}, request_id='REQ-' + '8' * 32)
    call(disp, 'nope.nope', request_id='REQ-' + '9' * 32)
    records = disp.evidence_records()
    assert len(records) == 3
    for record in records:
        for field in EV.FIELDS:
            assert field in record, field
        assert record['run_id'] == disp.run_id
        assert record['session_id'] == SID
        if record['result'] != 'OK':
            assert record['stopped_at'] in EV.STOP_STEPS
            assert record['provider_entry'] is False
    known_steps = [record['stopped_at'] for record in records if record['stopped_at']]
    assert known_steps == ['capability_resolution', 'operation_registry']


def test_every_provider_type_comes_from_the_frozen_enum():
    values = {member.value for member in ProviderType}
    for provider in PR.default_providers().values():
        assert provider.provider_type is None or provider.provider_type in values, provider.name
    assert PR.TestProvider('success').provider_type in values


def test_dispatch_self_test_is_clean():
    from tools.dispatch import self_test as package_self_test
    assert package_self_test() == []


def test_trace_scenarios_are_byte_deterministic():
    from tools.dispatch import cli as W7CLI
    first = json.dumps(W7CLI.scenarios(), indent=1, sort_keys=True)
    second = json.dumps(W7CLI.scenarios(), indent=1, sort_keys=True)
    assert first == second, 'the trace set must be reproducible byte for byte'
    traces = {trace['name']: trace for trace in W7CLI.scenarios()}
    assert all(trace['refs_normalized'] is True for trace in traces.values())
    assert {trace['name'] for trace in traces.values()} == {
        'positive-stub-ping', 'positive-stub-memory-alloc', 'negative-unknown-operation',
        'negative-privileged-no-prerequisite', 'negative-mock-proven-privileged',
        'negative-profile-missing', 'negative-reboot-stale-binding',
        'negative-w6-candidate-metadata', 'negative-recovery-before-entry',
        'positive-fully-wired-test-provider'}
