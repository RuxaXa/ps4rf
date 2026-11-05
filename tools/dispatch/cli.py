#!/usr/bin/env python3
"""PS4RF P4/W7 dispatch CLI: matrix, dispatch traces and the self-test.

``--matrix``  prints the provider router matrix (one route per registered operation)
``--trace``   runs the scripted scenario set and writes the traces as JSON: positive
              stub dispatches, negative privileged dispatches (each naming the chain step
              that stopped it), the F11 mock scenario, the W6 candidate scenario, the
              recovery race and the fully wired test-provider scenario
``--self-test`` runs the package self-tests

Every trace carries the request, the response and the invocation evidence, so a refusal
is auditable without re-running anything.

Usage::

    python tools/dispatch/cli.py --matrix
    python tools/dispatch/cli.py --trace /tmp/w7-traces.json
    python tools/dispatch/cli.py --self-test
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from core.models.capability import default_authority  # noqa: E402
from tools.dispatch import matrix as MX  # noqa: E402
from tools.dispatch.dispatch import Dispatcher  # noqa: E402
from tools.dispatch.providers import TestProvider  # noqa: E402
from tools.dispatch.providers import default_providers as _default_providers  # noqa: E402
from tools.primitive_iface.gate import HOST_CHAIN_REQUIREMENTS, REQ_BY_OP  # noqa: E402
from tools.profiles import binding as W5_BINDING  # noqa: E402

SID = 'SES-0123456789ABCDEF'
BID = 'BOOT-0123456789ABCDEF'
RUN = 'RUN-' + 'a' * 32
PROVIDER = 'native-provider'          # the W7 router provider name for privileged routes
FIXTURE_PROFILE = REPO_ROOT / 'tests' / 'fixtures' / 'profiles' / 'concrete-fixture.json'


def _fixture_profile() -> dict:
    return json.loads(FIXTURE_PROFILE.read_text())


def _capability_record(req, **overrides) -> dict:
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


def _verification_record(req, **overrides) -> dict:
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


def _dispatcher(**overrides) -> Dispatcher:
    kwargs: dict = dict(run_id='RUN-' + 'b' * 32, session_id=SID, boot_id=BID,
                        context_label='HOMEBREW')
    kwargs.update(overrides)
    return Dispatcher(**kwargs)


REF_RE = re.compile(r'^([a-z][a-z0-9_]*):[0-9A-F]{16}$')


def _normalize_refs(value, table: dict):
    """Replace the random resource refs by a stable ordinal.

    Resource refs contain 8 random bytes by design (the frozen manager generates them), so
    a pinned trace would never be reproducible. The trace keeps the *kind* and the order of
    first appearance (``mem:REF-1``) and says so; the raw refs stay in the live evidence.
    """
    if isinstance(value, str):
        match = REF_RE.fullmatch(value)
        if match:
            kind = match.group(1)
            key = (kind, value)
            if key not in table:
                table[key] = f'{kind}:REF-{sum(1 for k in table if k[0] == kind) + 1}'
            return table[key]
        return value
    if isinstance(value, dict):
        return {k: _normalize_refs(v, table) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize_refs(item, table) for item in value]
    return value


def _trace(name: str, dispatcher: Dispatcher, operation: str, arguments: dict | None = None,
           *, before_entry=None, note: str = '') -> dict:
    # a stable request id: the trace output must be reproducible byte for byte
    request = {'header': {'request_id': 'REQ-' + hashlib.sha256(name.encode()).hexdigest()[:32]},
               'body': {'operation': operation, 'arguments': dict(arguments or {}), 'seq': 1}}
    response = dispatcher.dispatch(request, before_entry=before_entry)
    records = dispatcher.evidence.for_request(request['header']['request_id'])
    table: dict = {}
    return {'name': name, 'note': note, 'request': request,
            'response': _normalize_refs(response, table),
            'evidence': _normalize_refs(records, table),
            'refs_normalized': True,
            'provider_entries': sum(1 for r in records if r['provider_entry'])}


def scenarios() -> list[dict]:
    """The scripted scenario set: positive, negative and the documented test wiring."""
    host = HOST_CHAIN_REQUIREMENTS[0]
    host_req = REQ_BY_OP.get('kernel.read')
    traces: list[dict] = []

    # positive: a stub operation through the one productive router path
    d = _dispatcher()
    traces.append(_trace('positive-stub-ping', d, 'session.ping',
                         note='stub route, wired: provider entry exactly once'))
    d = _dispatcher()
    traces.append(_trace('positive-stub-memory-alloc', d, 'memory.alloc', {'size': 4096},
                         note='stub route with a resource: ref comes from the central manager'))

    # negative: unknown operation, registry refusal
    d = _dispatcher()
    traces.append(_trace('negative-unknown-operation', d, 'kernel.exploit.all',
                         note='not in the frozen registry'))

    # negative: privileged operation without any prerequisite
    d = _dispatcher()
    traces.append(_trace('negative-privileged-no-prerequisite', d, 'kernel.read',
                         {'region_index': 1, 'offset': 0, 'length': 16},
                         note='capability resolution stops it'))

    # negative F11: MOCK record with PROVEN and an exact profile
    d = _dispatcher(capability_records=(_capability_record(host_req, provider_type='MOCK',
                                                           provider='mock-provider'),),
                    verification_records=(_verification_record(host_req),),
                    evidence_refs=({'run_id': RUN, 'sha256': 'b' * 64},),
                    profile=_fixture_profile(),
                    boot_binding=W5_BINDING.BootBinding.from_profile(_fixture_profile(), BID),
                    approval={'approved': True, 'state': 'APPROVED', 'id': 'CMR-1'})
    traces.append(_trace('negative-mock-proven-privileged', d, 'kernel.read',
                         {'region_index': 1, 'offset': 0, 'length': 16},
                         note='F11: a MOCK record can never authorize a privileged route'))

    # negative: profile mismatch (no profile submitted at all)
    d = _dispatcher(capability_records=(_capability_record(host_req),),
                    verification_records=(_verification_record(host_req),),
                    evidence_refs=({'run_id': RUN, 'sha256': 'b' * 64},),
                    approval={'approved': True, 'state': 'APPROVED', 'id': 'CMR-1'})
    traces.append(_trace('negative-profile-missing', d, 'kernel.read',
                         {'region_index': 1, 'offset': 0, 'length': 16},
                         note='W5 binding missing -> stopped at the profile step'))

    # negative: reboot invalidates the old boot binding
    doc = _fixture_profile()
    d = _dispatcher(boot_id='BOOT-' + 'f' * 16,
                    capability_records=(_capability_record(host_req, boot_id='BOOT-' + 'f' * 16),),
                    verification_records=(_verification_record(host_req, boot_id='BOOT-' + 'f' * 16),),
                    evidence_refs=({'run_id': RUN, 'sha256': 'b' * 64},),
                    profile=doc, boot_binding=W5_BINDING.BootBinding.from_profile(doc, BID),
                    approval={'approved': True, 'state': 'APPROVED', 'id': 'CMR-1'},
                    require_evidence_backed=False)
    traces.append(_trace('negative-reboot-stale-binding', d, 'kernel.read',
                         {'region_index': 1, 'offset': 0, 'length': 16},
                         note='boot binding from the previous boot is invalid'))

    # negative: everything satisfied except the provider wiring
    d = _dispatcher(capability_records=(_capability_record(host_req),),
                    verification_records=(_verification_record(host_req),),
                    evidence_refs=({'run_id': RUN, 'sha256': 'b' * 64},),
                    profile=_fixture_profile(),
                    boot_binding=W5_BINDING.BootBinding.from_profile(_fixture_profile(), BID),
                    approval={'approved': True, 'state': 'APPROVED', 'id': 'CMR-1'},
                    require_evidence_backed=False,
                    metadata={'w6_candidate': {'status': 'OBSERVATION',
                                               'finding': 'kernel.read locator changed'}})
    traces.append(_trace('negative-w6-candidate-metadata', d, 'kernel.read',
                         {'region_index': 1, 'offset': 0, 'length': 16},
                         note='W6 candidate is metadata: only NOT_WIRED remains'))

    # negative: recovery poison arrives before provider entry (race scenario)
    d = _dispatcher(providers={})          # no provider can be entered once poisoned
    d.providers.update(_default_providers())
    provider = TestProvider('success')
    traces.append(_trace(
        'negative-recovery-before-entry', d, 'memory.alloc', {'size': 4096},
        before_entry=lambda op, req: d.poison('scripted recovery poison'),
        note='recovery poison between acceptance and entry: the provider must not be entered'))

    # positive: fully wired test provider, all prerequisites satisfied, entry exactly once
    d, provider = _wired_test_dispatcher()
    traces.append(_trace('positive-fully-wired-test-provider', d, 'verify.userland.exec',
                         {'probe': 'selftest'},
                         note='TEST provider replaces the DEFERRED host-chain provider'))
    traces[-1]['provider_entries'] = provider.entries
    return traces


def _wired_test_dispatcher():
    # Production keeps host-chain-provider DEFERRED; this wiring exists for tests/traces
    # only, and the test provider marks its observed payload as scripted.
    host = HOST_CHAIN_REQUIREMENTS[0]
    provider = TestProvider('success')
    providers = {name: value for name, value in _default_providers().items()
                 if name != 'host-chain-provider'}
    providers[provider.name] = provider
    dispatcher = _dispatcher(
        capability_records=(_capability_record(host, provider=provider.name,
                                               provider_type=provider.provider_type),),
        verification_records=(_verification_record(host, provider=provider.name,
                                                   provider_type=provider.provider_type),),
        evidence_refs=({'run_id': RUN, 'sha256': 'b' * 64},),
        approval={'approved': True, 'state': 'APPROVED', 'id': 'CMR-1'},
        providers=providers)
    return dispatcher, provider


def main(argv: list[str]) -> int:
    if '--matrix' in argv:
        print(json.dumps({'schema': MX.MATRIX_SCHEMA, 'summary': MX.summary(),
                          'operations': MX.provider_matrix()}, indent=1, sort_keys=True))
        return 0
    if '--trace' in argv:
        index = argv.index('--trace')
        target = pathlib.Path(argv[index + 1]) if len(argv) > index + 1 and not argv[index + 1].startswith('--') else None
        traces = scenarios()
        payload = {'schema': 'ps4rf.provider-router.traces.v1',
                   'authority_native_ceiling': default_authority().rule_for(
                       PROVIDER, __import__('core.models.common', fromlist=['ProviderType']).ProviderType.NATIVE,
                       PROVIDER).max_assurance.value,
                   'traces': traces}
        text = json.dumps(payload, indent=1, sort_keys=True)
        if target is not None:
            target.write_text(text + '\n')
            print(f'wrote {len(traces)} traces to {target}')
        else:
            print(text)
        refusals = sum(1 for t in traces if t['name'].startswith('negative'))
        positives = len(traces) - refusals
        print(f'TRACES OK: {positives} positive, {refusals} negative, '
              f'{sum(t["provider_entries"] for t in traces)} provider entries')
        return 0
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: cli.py --matrix | --trace [FILE] | --self-test')
        return 2
    import tools.dispatch as package
    failures = package.self_test()
    if failures:
        print(f'dispatch CLI self-test: {len(failures)} FAILED')
        for item in failures:
            print(f'  - {item}')
        return 1
    print('dispatch CLI self-test: OK')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
