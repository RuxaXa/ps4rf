#!/usr/bin/env python3
"""PS4RF P4/W7 provider interface: validated context in, structured result out.

A provider handler never parses JSON, never decides capabilities, never picks a profile
and never makes an authority decision: it receives an :class:`InvocationContext` whose
arguments were validated by the W3 interface, whose profile binding was resolved by W5
and whose authorization was decided by the W4 gate + effective grant. It talks to
resources only through the central :class:`~core.resources.manager.ResourceManager`
handed to it in that context, and it returns a :class:`ProviderResult` - never a raw
exception, and never a hand-built wire response.

Resource references are namespaced per provider (``<provider>:<id>``), so no provider can
adopt a resource of another provider or request context.

Usage::

    python tools/dispatch/providers.py --self-test
"""

from __future__ import annotations

import pathlib
import sys
import threading
from dataclasses import dataclass, field

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from core.resources.manager import ResourceManager  # noqa: E402
from tools.dispatch.evidence import EvidenceSink  # noqa: E402
from tools.primitive_iface.stub import StubProvider  # noqa: E402

PROVIDER_STATES = ('WIRED', 'DEFERRED', 'TEST_ONLY')


@dataclass(frozen=True)
class InvocationContext:
    """Everything a provider may use. Nothing here needs a second decision."""
    run_id: str
    request_id: str
    operation: str
    arguments: dict
    seq: int | None
    provider_name: str
    provider_type: str | None
    profile_sha256: str | None
    profile_binding: dict | None
    boot_id: str
    session_id: str
    context_label: str
    capability: str | None
    effective_assurance: str | None
    resources: ResourceManager
    evidence: EvidenceSink
    route: str
    wired: bool


@dataclass
class ProviderResult:
    ok: bool
    result: dict = field(default_factory=dict)
    error_code: str | None = None
    resource_changes: list = field(default_factory=list)
    cleanup: dict | None = None
    entered: bool = True


class ProviderEntryRefused(RuntimeError):
    """A DEFERRED provider was entered - never a normal outcome."""

    def __init__(self, operation: str, state: str):
        super().__init__(f'{operation}: provider is {state}; entry is not allowed')
        self.operation = operation
        self.state = state


class Provider:
    """Base class: name, provider type, state, one entry point."""
    name = 'provider'
    provider_type: str | None = None
    state = 'DEFERRED'
    routes: tuple[str, ...] = ()
    resource_kind = 'generic'

    def handles(self, route: str) -> bool:
        return route in self.routes

    def enter(self, ctx: InvocationContext) -> ProviderResult:  # pragma: no cover - abstract
        raise NotImplementedError


class StubProviderAdapter(Provider):
    """The 16 stub operations, unchanged: delegates to the frozen W3 stub semantics."""
    name = 'ps4rfd-stub'
    provider_type = None
    state = 'WIRED'
    routes = ('stub',)
    resource_kind = 'stub'

    def __init__(self) -> None:
        self.stub = StubProvider()

    def enter(self, ctx: InvocationContext) -> ProviderResult:
        response = self.stub.call(ctx.operation, dict(ctx.arguments), ctx.request_id, ctx.seq)
        held = [{'ref': ref, 'event': 'HELD'} for ref in self.stub._held()]  # noqa: SLF001
        if isinstance(response, dict) and 'status' in response and 'error' in response:
            code = (response.get('error') or {}).get('code') or 'PROVIDER_ERROR'
            return ProviderResult(ok=False, error_code=code,
                                  cleanup=response.get('cleanup'),
                                  resource_changes=held)
        payload = response.get('result', {}) if isinstance(response, dict) else {}
        cleanup = response.get('cleanup') if isinstance(response, dict) else None
        if cleanup is not None:
            cleanup = dict(cleanup, reported_by='provider')
        return ProviderResult(ok=True, result=payload, cleanup=cleanup,
                              resource_changes=held)


class MockOnlyProvider(Provider):
    """The 4 mock-only operations: test-only, answering OPERATION_DEFERRED (as frozen)."""
    name = 'mock-provider'
    provider_type = 'MOCK'
    state = 'TEST_ONLY'
    routes = ('mock_only',)
    resource_kind = 'mock'

    def enter(self, ctx: InvocationContext) -> ProviderResult:
        return ProviderResult(ok=False, error_code='OPERATION_DEFERRED')


class NativeDeferredProvider(Provider):
    """The 14 privileged operations: registered, DEFERRED, never entered in W7."""
    name = 'native-provider'
    provider_type = 'NATIVE'
    state = 'DEFERRED'
    routes = ('deferred_privilege',)
    resource_kind = 'native'

    def enter(self, ctx: InvocationContext) -> ProviderResult:
        raise ProviderEntryRefused(ctx.operation, self.state)


class HostChainProvider(Provider):
    """The single deferred-host-chain operation: registered, DEFERRED in W7."""
    name = 'host-chain-provider'
    provider_type = 'NATIVE'
    state = 'DEFERRED'
    routes = ('deferred_host_chain',)
    resource_kind = 'userland'

    def enter(self, ctx: InvocationContext) -> ProviderResult:
        raise ProviderEntryRefused(ctx.operation, self.state)


class TestProvider(Provider):
    """Scripted provider for tests and traces. Never part of ``default_providers()``.

    It answers the way a wired provider would, but it never claims a verification result
    it did not produce: ``verified`` stays false and the observed payload names the source
    as the test provider, so a trace can never be mistaken for real evidence.
    """
    name = 'test-provider'
    provider_type = 'RUNTIME_PROBE'
    state = 'WIRED'
    routes = ('deferred_host_chain',)
    resource_kind = 'test'
    test_only = True

    RESULTS = ('success', 'failure', 'raise', 'allocate_then_fail', 'cleanup_fail', 'hang')

    def __init__(self, behaviour: str = 'success',
                 routes: tuple[str, ...] = ('deferred_host_chain',)) -> None:
        if behaviour not in self.RESULTS:
            raise ValueError(f'unknown test behaviour {behaviour!r}')
        self.behaviour = behaviour
        self.routes = routes
        self.entries = 0
        self._lock = threading.Lock()
        self.release = threading.Event()
        self.release.set()

    def enter(self, ctx: InvocationContext) -> ProviderResult:
        with self._lock:
            self.entries += 1
        if self.behaviour == 'hang':
            self.release.wait(timeout=5)
            return ProviderResult(ok=False, error_code='RESOURCE_STATE_INVALID')
        if self.behaviour == 'raise':
            raise RuntimeError('scripted provider fault (test provider)')
        if self.behaviour == 'allocate_then_fail':
            ctx.resources.acquire(self.resource_kind)          # deliberately held
            return ProviderResult(ok=False, error_code='RESOURCE_LIMIT')
        if self.behaviour == 'cleanup_fail':
            ref = ctx.resources.acquire(self.resource_kind, force_cleanup_failure=True)
            return ProviderResult(ok=True, result=self._result(ctx),
                                  cleanup={'state': 'PARTIAL', 'resources': [{'ref': ref}]})
        if self.behaviour == 'failure':
            return ProviderResult(ok=False, error_code='RESOURCE_STATE_INVALID')
        return ProviderResult(ok=True, result=self._result(ctx))

    def _result(self, ctx: InvocationContext) -> dict:
        return {'observed': {'operation': ctx.operation, 'probe': ctx.arguments.get('probe'),
                             'source': 'TEST_PROVIDER', 'scripted': True},
                'verified': False}


def default_providers() -> dict[str, Provider]:
    return {provider.name: provider for provider in
            (StubProviderAdapter(), MockOnlyProvider(), NativeDeferredProvider(), HostChainProvider())}


def provider_for_route(providers: dict[str, Provider], route: str) -> Provider:
    for provider in providers.values():
        if provider.handles(route):
            return provider
    raise KeyError(f'no provider handles route {route!r}')


def _self_test() -> list[str]:
    checks: list[str] = []
    providers = default_providers()
    if provider_for_route(providers, 'stub').state != 'WIRED':
        checks.append('the stub route must be wired')
    for route in ('deferred_privilege', 'deferred_host_chain'):
        if provider_for_route(providers, route).state != 'DEFERRED':
            checks.append(f'{route} must stay DEFERRED in W7')
    ctx = InvocationContext(
        run_id='RUN-1', request_id='REQ-1', operation='kernel.read', arguments={}, seq=1,
        provider_name='native-provider', provider_type='NATIVE', profile_sha256=None,
        profile_binding=None, boot_id='BOOT-1', session_id='SES-1', context_label='ORBIS',
        capability='kernel.read', effective_assurance='OBSERVED', resources=ResourceManager(),
        evidence=EvidenceSink(), route='deferred_privilege', wired=False)
    try:
        provider_for_route(providers, 'deferred_privilege').enter(ctx)
    except ProviderEntryRefused:
        pass
    else:
        checks.append('entering a DEFERRED provider must raise')
    for provider in providers.values():
        if provider.state not in PROVIDER_STATES:
            checks.append(f'{provider.name}: unknown state {provider.state}')
    return checks


def main(argv: list[str]) -> int:
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: providers.py --self-test')
        return 2
    failures = _self_test()
    if failures:
        print(f'providers self-test: {len(failures)} FAILED')
        for item in failures:
            print(f'  - {item}')
        return 1
    print('providers self-test: OK (stub wired, privileged/host-chain DEFERRED, entry refused)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
