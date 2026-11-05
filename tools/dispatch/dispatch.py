#!/usr/bin/env python3
"""PS4RF P4/W7 central dispatch: the one productive path from REQUEST to RESPONSE.

The normative chain, implemented here and nowhere else::

    REQUEST
      -> RPC validation            (frozen wire envelopes + W3 argument validation)
      -> OperationRegistry         (frozen registry; unknown operation is refused)
      -> Capability resolution     (capability record: presence, availability, context,
                                    session/boot binding)
      -> effective_grant           (assurance vs frozen authority ceiling/provider policy)
      -> W4 capability gate        (the frozen gate decides; ELIGIBLE alone authorizes nothing)
      -> W5 profile binding        (profile match, evidence-backed, boot-valid)
      -> Provider router           (exactly one provider per route; DEFERRED stays refused)
      -> Primitive interface       (provider receives a validated context only)
      -> Resource / recovery policy(central ResourceManager, cleanup result into evidence)
      -> Response + evidence       (structured result or mapped error, never a traceback)

There is exactly one place where a provider handler can be entered
(:meth:`Dispatcher._enter_provider`). Tests may call handlers directly for unit coverage,
but the productive RPC path goes through :meth:`Dispatcher.dispatch` only; a test asserts
that this is the only call site in the package.

Privileged operations can never take a shortcut: the W4 gate must be satisfied *and* the
provider must be wired *and* the provider state must be WIRED. In W7 all 14 privileged
operations and the host-chain operation stay ``DEFERRED``, so even a perfect gate result
answers ``OPERATION_DEFERRED`` with ``provider_entry = false``.

Usage::

    python tools/dispatch/dispatch.py --self-test
"""

from __future__ import annotations

import pathlib
import sys
import threading

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from core.resources.manager import ResourceManager  # noqa: E402
from core.rpc.registry import default_registry  # noqa: E402
from tools.dispatch import matrix as MX  # noqa: E402
from tools.dispatch.evidence import (  # noqa: E402
    REASON_TO_STEP, EvidenceSink, record,
)
from tools.dispatch.providers import (  # noqa: E402
    InvocationContext, Provider, ProviderEntryRefused, ProviderResult, default_providers,
    provider_for_route,
)
from tools.dispatch.resources import RequestResourceView  # noqa: E402
from tools.primitive_iface.gate import GateContext, gate_for  # noqa: E402
from tools.primitive_iface.schema import ERROR_CODES, OPS_BY_NAME  # noqa: E402
from tools.profiles import w4_adapter as W5  # noqa: E402
from tools.primitive_iface.validate import (  # noqa: E402
    InterfaceError, error_response, ok_response, validate_arguments,
    validate_request_envelope, validate_response_envelope,
)

RECOVERY_CODE = 'SESSION_RECOVERY_REQUIRED'
DEFERRED_CODE = 'OPERATION_DEFERRED'


class DispatchRefusal(RuntimeError):
    """Internal control flow: a chain step refused the request."""

    def __init__(self, code: str, step: str, reason: str, w4_reasons: tuple[str, ...] = ()):
        super().__init__(f'{step}: {code} ({reason})')
        self.code = code
        self.step = step
        self.reason = reason
        self.w4_reasons = w4_reasons


class Dispatcher:
    """The central dispatcher. One instance is one session/boot context."""

    def __init__(self, *, run_id: str, session_id: str, boot_id: str,
                 context_label: str = 'BROWSER', session_state: str = 'ACTIVE',
                 capability_records: tuple[dict, ...] = (),
                 verification_records: tuple[dict, ...] = (),
                 evidence_refs: tuple[dict, ...] = (),
                 profile: dict | None = None,
                 boot_binding=None,
                 profile_requests: tuple = (),
                 require_evidence_backed: bool = True,
                 profile_binding: dict | None = None,
                 approval: dict | None = None,
                 claims: dict | None = None,
                 metadata: dict | None = None,
                 providers: dict[str, Provider] | None = None,
                 wired_ops: tuple[str, ...] = (),
                 test_provider: Provider | None = None,
                 acting_provider_name: str | None = None,
                 acting_provider_type: str | None = None,
                 resources: ResourceManager | None = None,
                 evidence: EvidenceSink | None = None,
                 max_inflight: int = 8) -> None:
        self.run_id = run_id
        self.session_id = session_id
        self.boot_id = boot_id
        self.context_label = context_label
        self._state = session_state
        self.capability_records = tuple(capability_records)
        self.verification_records = tuple(verification_records)
        self.evidence_refs = tuple(evidence_refs)
        self.profile = profile
        self.boot_binding = boot_binding
        self.profile_requests = tuple(profile_requests)
        self.require_evidence_backed = require_evidence_backed
        self.profile_binding = profile_binding  # explicit override, tests only
        self.approval = approval
        self.claims = dict(claims or {})
        # analysis metadata (e.g. W6 findings): recorded in evidence only, never a gate input
        self.metadata = dict(metadata or {})
        self.providers = dict(providers) if providers is not None else default_providers()
        if test_provider is not None:  # explicit, documented test wiring only
            self.providers[test_provider.name] = test_provider
        self.wired_ops = set(wired_ops)
        self.acting_provider_name = acting_provider_name
        self.acting_provider_type = acting_provider_type
        self.resources = resources or ResourceManager()
        self.evidence = evidence or EvidenceSink()
        self._lock = threading.RLock()
        self._inflight = 0
        self._max_inflight = max_inflight
        self._semaphore = threading.BoundedSemaphore(max_inflight)

    # --- session state -------------------------------------------------------------
    @property
    def session_state(self) -> str:
        with self._lock:
            return self._state

    def poison(self, reason: str = 'provider cleanup incomplete') -> None:
        """Enter RECOVERY_REQUIRED (mirrors the frozen recovery transition)."""
        with self._lock:
            self._state = 'RECOVERY_REQUIRED'
            self._poison_reason = reason

    # --- W5 integration -------------------------------------------------------------
    def profile_binding_for(self, op: str) -> dict | None:
        """The profile part of the gate input, derived by W5 and nothing else.

        A raw ``profile_binding`` override is used when given (test injection); otherwise
        the W5 adapter evaluates the submitted profile document against the current boot
        and returns the binding the W4 gate consumes. W5 supplies the profile part only -
        it can never make an operation executable.
        """
        if self.profile_binding is not None:
            return self.profile_binding
        if self.profile is None and self.boot_binding is None:
            return None
        verdict = W5.profile_preconditions(
            self.profile, requests=self.profile_requests,
            boot_binding=self.boot_binding, current_boot_id=self.boot_id)
        return W5.profile_binding_for_gate(op, verdict,
                                           require_evidence_backed=self.require_evidence_backed)

    # --- evidence helpers ----------------------------------------------------------
    def evidence_records(self) -> list[dict]:
        return self.evidence.records()

    # --- the single provider entry site -------------------------------------------
    def _enter_provider(self, ctx: InvocationContext) -> ProviderResult:
        """THE only place a provider handler is invoked on the productive path."""
        provider = self.providers[ctx.provider_name]
        if not ctx.wired or provider.state != 'WIRED':
            raise ProviderEntryRefused(ctx.operation, provider.state)
        return provider.enter(ctx)

    # --- the normative chain -------------------------------------------------------
    def dispatch(self, request: dict, *, before_entry=None) -> dict:
        """Run one request through the chain. Returns a validated response envelope."""
        request_id = None
        operation = None
        try:
            request_id = (request.get('header') or {}).get('request_id')
        except AttributeError:
            request_id = None
        if not self._semaphore.acquire(blocking=False):
            return self._refuse_inflight(request_id, operation)
        try:
            with self._lock:
                self._inflight += 1
            return self._dispatch_locked(request, before_entry=before_entry)
        finally:
            with self._lock:
                self._inflight -= 1
            self._semaphore.release()

    def _dispatch_locked(self, request: dict, *, before_entry=None) -> dict:
        entry_common = {'run_id': self.run_id, 'request_id': None, 'operation': None,
                        'selected_provider': None, 'boot_id': self.boot_id,
                        'session_id': self.session_id, 'context': self.context_label,
                        'metadata': self.metadata}

        # 1. RPC validation -----------------------------------------------------
        try:
            operation = validate_request_envelope(request)
            body = request['body']
            arguments = dict(body.get('arguments') or {})
            request_id = request['header']['request_id']
            seq = body.get('seq')
        except InterfaceError as exc:
            request_id = (request.get('header') or {}).get('request_id')
            step = 'operation_registry' if exc.code == 'OPERATION_UNSUPPORTED' else 'rpc_validation'
            self.evidence.add(record(**{**entry_common, 'request_id': request_id,
                                        'operation': None, 'selected_provider': 'none',
                                        'result': 'ERROR', 'error': exc.code,
                                        'error_detail': exc.detail,
                                        'stopped_at': step}))
            return error_response(request_id, exc.code)
        except (KeyError, TypeError, AttributeError) as exc:
            self.evidence.add(record(**{**entry_common, 'selected_provider': 'none',
                                        'result': 'ERROR', 'error': 'ARGUMENT_INVALID',
                                        'error_detail': f'malformed request envelope: {type(exc).__name__}',
                                        'stopped_at': 'rpc_validation'}))
            return error_response(request_id, 'ARGUMENT_INVALID')

        entry_common.update({'request_id': request_id, 'operation': operation})
        profile_sha = None

        def refuse(code: str, step: str, reason: str, *, provider: str = 'none',
                   provider_type: str | None = None, capability: str | None = None,
                   assurance: str | None = None, w4_reasons: tuple[str, ...] = (),
                   w4_decision: str | None = None, provider_entry: bool = False,
                   error_detail: str | None = None, resource_changes: list | None = None,
                   cleanup: dict | None = None) -> dict:
            self.evidence.add(record(**{**entry_common, 'selected_provider': provider,
                                        'provider_type': provider_type,
                                        'capability': capability,
                                        'effective_assurance': assurance,
                                        'w4_decision': w4_decision, 'w4_reasons': w4_reasons,
                                        'profile_sha256': profile_sha,
                                        'provider_entry': provider_entry,
                                        'resource_changes': resource_changes,
                                        'cleanup': cleanup,
                                        'error_detail': error_detail,
                                        'stopped_at': step, 'result': 'REFUSED', 'error': code}))
            return error_response(request_id, code)

        # 2. operation registry -------------------------------------------------
        registry = default_registry()
        if not registry.has(operation) or operation not in OPS_BY_NAME:
            return refuse('OPERATION_UNSUPPORTED', 'operation_registry',
                          'operation is not in the frozen registry')
        spec = registry.spec(operation)
        interface = OPS_BY_NAME[operation]

        # 3. route resolution ---------------------------------------------------
        try:
            route = MX.route_for(operation)
        except MX.UnknownOperation as exc:
            return refuse('OPERATION_UNSUPPORTED', 'provider_router', str(exc))
        provider = provider_for_route(self.providers, route['route'])
        acting_name = self.acting_provider_name or provider.name
        acting_type = self.acting_provider_type or provider.provider_type
        wired = operation in self.wired_ops or provider.state == 'WIRED'

        # 4. recovery policy (central, before any provider entry) ---------------
        if self.session_state != 'ACTIVE' and spec.mutating and not spec.recovery_safe:
            return refuse(RECOVERY_CODE, 'resource_policy',
                          f'session state is {self.session_state}', provider=acting_name,
                          provider_type=acting_type)

        # 5.-8. gated routes: capability -> grant -> W4 gate -> W5 binding --------
        w4_reasons: tuple[str, ...] = ()
        w4_decision = None
        capability = interface.capability
        assurance = None
        if route['gated']:
            binding = self.profile_binding_for(operation)
            profile_sha = (binding or {}).get('sha256')
            gate_ctx = GateContext(
                capability_records=self.capability_records,
                verification_records=self.verification_records,
                evidence_refs=self.evidence_refs,
                profile_binding=binding,
                session_id=self.session_id,
                boot_id=self.boot_id,
                session_state=self.session_state,
                provider=acting_name,
                provider_type=acting_type,
                wired=wired,
                approval=self.approval,
                claims=self.claims,
            )
            decision = gate_for(operation, gate_ctx)
            w4_reasons = decision.reasons
            w4_decision = decision.decision
            for record_entry in self.capability_records:
                if record_entry.get('name') == capability or (
                        capability is None and record_entry.get('namespace') == interface.family):
                    assurance = record_entry.get('assurance')
                    break
            if w4_reasons:
                step = REASON_TO_STEP.get(w4_reasons[0], 'w4_gate')
                code = RECOVERY_CODE if w4_reasons[0] == 'RECOVERY_REQUIRED' else DEFERRED_CODE
                return refuse(code, step, w4_reasons[0], provider=acting_name,
                              provider_type=acting_type, capability=capability,
                              assurance=assurance, w4_reasons=w4_reasons,
                              w4_decision=w4_decision)

        # 9. provider router: DEFERRED providers are never entered --------------
        if not wired or provider.state != 'WIRED':
            return refuse(DEFERRED_CODE, 'provider_router',
                          f'provider state is {provider.state}', provider=acting_name,
                          provider_type=acting_type, capability=capability,
                          assurance=assurance, w4_reasons=w4_reasons,
                          w4_decision=w4_decision)
        if callable(before_entry):
            before_entry(operation, request_id)   # test hook: runs before entry only
            if self.session_state != 'ACTIVE' and spec.mutating and not spec.recovery_safe:
                return refuse(RECOVERY_CODE, 'resource_policy',
                              'recovery poison arrived before provider entry',
                              provider=acting_name, provider_type=acting_type,
                              capability=capability, assurance=assurance,
                              w4_reasons=w4_reasons, w4_decision=w4_decision)

        # 10. primitive interface: validated context in, structured result out ---
        view = RequestResourceView(self.resources, request_id=request_id)
        ctx = InvocationContext(
            run_id=self.run_id, request_id=request_id, operation=operation,
            arguments=dict(arguments), seq=seq, provider_name=provider.name,
            provider_type=provider.provider_type, profile_sha256=profile_sha,
            profile_binding=self.profile_binding, boot_id=self.boot_id,
            session_id=self.session_id, context_label=self.context_label,
            capability=capability, effective_assurance=assurance,
            resources=view, evidence=self.evidence, route=route['route'], wired=wired)
        try:
            result = self._enter_provider(ctx)
        except ProviderEntryRefused as exc:
            return refuse(DEFERRED_CODE, 'provider_router', str(exc), provider=acting_name,
                          provider_type=acting_type, capability=capability, assurance=assurance,
                          w4_reasons=w4_reasons, w4_decision=w4_decision)
        except InterfaceError as exc:
            return refuse(exc.code, 'primitive_interface', exc.detail, provider=provider.name,
                          provider_type=provider.provider_type, capability=capability,
                          assurance=assurance, provider_entry=True,
                          error_detail=exc.detail)
        except Exception as exc:  # noqa: BLE001 - no raw exception may reach the wire
            detail = f'{type(exc).__name__}: {exc}'[:200]
            return refuse('INTERNAL_ERROR', 'primitive_interface',
                          f'provider raised ({type(exc).__name__})', provider=provider.name,
                          provider_type=provider.provider_type, capability=capability,
                          assurance=assurance, w4_reasons=w4_reasons,
                          w4_decision=w4_decision, provider_entry=True, error_detail=detail)

        # 11. resource / recovery policy ---------------------------------------
        report = view.cleanup_all()
        provider_cleanup = result.cleanup or {}
        if view.owned():
            # a provider that ran against this request's resource view
            cleanup = {'state': report.state, 'resources': report.resources,
                       'request_owned': view.owned(), 'request_released': view.released()}
        else:
            # a provider that keeps its own bookkeeping (the frozen W3 stub adapter)
            cleanup = {'state': provider_cleanup.get('state', 'NOT_ATTEMPTED'),
                       'resources': list(provider_cleanup.get('resources') or []),
                       'request_owned': [], 'request_released': [],
                       'reported_by': 'provider'}
        if view.violations():
            cleanup['violations'] = view.violations()
        failed = [r for r in cleanup['resources']
                  if str(r.get('cleanup_result')) in ('CLEANUP_FAILED', 'UNCERTAIN')]
        if cleanup['state'] == 'PARTIAL' or failed:
            # frozen recovery semantics: resources that could not be cleaned demand recovery
            self.poison('provider cleanup incomplete')
        cleanup['session_state'] = self.session_state
        changes = view.changes() or list(result.resource_changes or [])
        if not result.ok:
            code = result.error_code if result.error_code in ERROR_CODES else 'INTERNAL_ERROR'
            self.evidence.add(record(**{**entry_common, 'selected_provider': provider.name,
                                        'provider_type': provider.provider_type,
                                        'capability': capability, 'effective_assurance': assurance,
                                        'w4_decision': w4_decision, 'w4_reasons': w4_reasons,
                                        'profile_sha256': profile_sha,
                                        'provider_entry': True, 'stopped_at': 'resource_policy',
                                        'result': 'ERROR', 'error': code,
                                        'resource_changes': changes,
                                        'cleanup': cleanup}))
            return error_response(request_id, code,
                                  cleanup=cleanup if (view.owned() or changes) else None)

        # 12. response + evidence ----------------------------------------------
        response = ok_response(operation, request_id, result.result,
                               cleanup if (view.owned() or changes) else None)
        try:
            validate_response_envelope(operation, response)
        except InterfaceError as exc:
            return refuse(exc.code, 'response', 'provider produced an invalid envelope',
                          provider=provider.name, provider_type=provider.provider_type,
                          capability=capability, assurance=assurance)
        self.evidence.add(record(**{**entry_common, 'selected_provider': provider.name,
                                    'provider_type': provider.provider_type,
                                    'capability': capability, 'effective_assurance': assurance,
                                    'w4_decision': w4_decision, 'w4_reasons': w4_reasons,
                                    'profile_sha256': profile_sha,
                                    'provider_entry': True, 'stopped_at': None,
                                    'result': 'OK', 'error': None,
                                    'resource_changes': changes,
                                    'cleanup': cleanup}))
        return response

    def _refuse_inflight(self, request_id, operation) -> dict:
        self.evidence.add(record(run_id=self.run_id, request_id=request_id, operation=operation,
                                 selected_provider='none', boot_id=self.boot_id,
                                 session_id=self.session_id, context=self.context_label,
                                 stopped_at='provider_router', result='REFUSED',
                                 error='TOO_MANY_INFLIGHT', metadata=self.metadata))
        return error_response(request_id, 'TOO_MANY_INFLIGHT')

    # convenience for tests and traces
    def dispatch_operation(self, operation: str, arguments: dict | None = None,
                           request_id: str = 'REQ-' + '0' * 32, seq: int | None = None) -> dict:
        message = {'header': {'request_id': request_id},
                   'body': {'operation': operation, 'arguments': dict(arguments or {}),
                            'seq': seq if seq is not None else 1}}
        return self.dispatch(message)


def _self_test() -> list[str]:
    checks: list[str] = []
    disp = Dispatcher(run_id='RUN-1', session_id='SES-' + 'A' * 16, boot_id='BOOT-' + 'B' * 16)
    ok = disp.dispatch_operation('session.ping')
    if ok.get('status') != 'OK':
        checks.append(f'a stub operation must succeed through the router, got {ok}')
    records = disp.evidence_records()
    if not records or records[-1]['provider_entry'] is not True:
        checks.append('a successful dispatch must record provider_entry=true')

    disp2 = Dispatcher(run_id='RUN-2', session_id='SES-' + 'A' * 16, boot_id='BOOT-' + 'B' * 16)
    refused = disp2.dispatch_operation('kernel.read',
                                         {'region_index': 1, 'offset': 0, 'length': 16})
    if (refused.get('error') or {}).get('code') != 'OPERATION_DEFERRED':
        checks.append(f'a privileged operation must stay deferred, got {refused}')
    rec = disp2.evidence_records()[-1]
    if rec['provider_entry'] is not False or rec['stopped_at'] not in (
            'provider_router', 'capability_resolution', 'w5_profile_binding'):
        checks.append(f'refusal evidence must name the stopping step, got {rec["stopped_at"]}')

    disp3 = Dispatcher(run_id='RUN-3', session_id='SES-' + 'A' * 16, boot_id='BOOT-' + 'B' * 16)
    unknown = disp3.dispatch_operation('kernel.exploit.all')
    if (unknown.get('error') or {}).get('code') != 'OPERATION_UNSUPPORTED':
        checks.append('an unknown operation must be refused')
    return checks


def self_test() -> list[str]:
    return _self_test()


def main(argv: list[str]) -> int:
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: dispatch.py --self-test')
        return 2
    failures = _self_test()
    if failures:
        print(f'dispatch self-test: {len(failures)} FAILED')
        for item in failures:
            print(f'  - {item}')
        return 1
    print('dispatch self-test: OK (single entry site, stub wired, privileged deferred, '
          'unknown refused, evidence complete)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
