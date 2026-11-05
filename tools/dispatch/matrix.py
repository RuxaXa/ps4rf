#!/usr/bin/env python3
"""PS4RF P4/W7 provider router matrix: exactly one route per registered operation.

Every operation of the frozen registry gets exactly one route, and the routes are
cross-checked against every earlier matrix so no operation can silently disappear or be
routed twice:

* ``default_registry()`` (the frozen core: 36 operations; 35 at the freeze, +1 under wire
  catalogue revision R4, W14 §15)
* the W3 primitive interface table (status: stub / mock-only / deferred-privilege /
  deferred-host-chain)
* the W4 capability matrix (gated operations, requirements, provider types)
* the W5 profile matrix (profile requirement per operation)

Routes: ``stub`` (wired), ``mock_only`` (test-only, answers ``OPERATION_DEFERRED`` like
the frozen stub does), ``deferred_privilege`` (registered, provider state DEFERRED),
``deferred_host_chain`` (registered, provider state DEFERRED, verification-evidence path).

There is **no implicit fallback**: an unknown operation is refused, and an operation
without a route is a hard error (never a default provider).

Usage::

    python tools/dispatch/matrix.py --matrix
    python tools/dispatch/matrix.py --self-test
"""

from __future__ import annotations

import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from core.rpc.registry import default_registry  # noqa: E402
from tools.primitive_iface.gate import HOST_CHAIN_REQUIREMENTS, REQ_BY_OP  # noqa: E402

ALL_REQ_BY_OP = {**REQ_BY_OP, **{req.op: req for req in HOST_CHAIN_REQUIREMENTS}}
from tools.primitive_iface.schema import OPS_BY_NAME  # noqa: E402
from tools.profiles.schema import operation_matrix  # noqa: E402

MATRIX_SCHEMA = 'ps4rf.provider-router.matrix.v1'

ROUTE_STUB = 'stub'
ROUTE_MOCK_ONLY = 'mock_only'
ROUTE_DEFERRED_PRIVILEGE = 'deferred_privilege'
ROUTE_DEFERRED_HOST_CHAIN = 'deferred_host_chain'
# W14 (resident ps4rfd): the target agent gains ONE wired privileged provider -- the bounded
# kernel.read provider (region_index/offset/length -> compile-time region table -> the W12
# bounded read). The HOST route is unchanged: the host still defers this operation to the
# target side, runs its own chain (capability -> W4 -> W5/boot -> section 70 approval ->
# research release) and records the target's provider entry. Only the generated TARGET
# catalog uses this route, so the host provider table keeps exactly its four routes.
ROUTE_PRIVILEGED_PROVIDER = 'privileged_provider'

ROUTES = (ROUTE_STUB, ROUTE_MOCK_ONLY, ROUTE_DEFERRED_PRIVILEGE, ROUTE_DEFERRED_HOST_CHAIN)

# operation -> target-side route. Empty by default; every entry here must name the operation,
# the route and the reason, and the target catalog generator asserts the resulting row.
TARGET_ROUTE_OVERRIDES = {
    'kernel.read': ROUTE_PRIVILEGED_PROVIDER,
    'kernel.snapshot.recipe': ROUTE_PRIVILEGED_PROVIDER,
    'ioctl.invoke': ROUTE_PRIVILEGED_PROVIDER,
}

STATUS_TO_ROUTE = {
    'stub': ROUTE_STUB,
    'mock-only': ROUTE_MOCK_ONLY,
    'deferred-privilege': ROUTE_DEFERRED_PRIVILEGE,
    'deferred-host-chain': ROUTE_DEFERRED_HOST_CHAIN,
}

PROVIDER_BY_ROUTE = {
    ROUTE_STUB: 'ps4rfd-stub',
    ROUTE_MOCK_ONLY: 'mock-provider',
    ROUTE_DEFERRED_PRIVILEGE: 'native-provider',
    ROUTE_DEFERRED_HOST_CHAIN: 'host-chain-provider',
}

# production provider state: only the stub route is wired in W7
STATE_BY_ROUTE = {
    ROUTE_STUB: 'WIRED',
    ROUTE_MOCK_ONLY: 'TEST_ONLY',
    ROUTE_DEFERRED_PRIVILEGE: 'DEFERRED',
    ROUTE_DEFERRED_HOST_CHAIN: 'DEFERRED',
}

GATED_ROUTES = (ROUTE_DEFERRED_PRIVILEGE, ROUTE_DEFERRED_HOST_CHAIN)

HOST_CHAIN_OPS = tuple(req.op for req in HOST_CHAIN_REQUIREMENTS)


class UnknownOperation(KeyError):
    """Fail-closed refusal for an operation outside the frozen registry."""


def provider_matrix() -> list[dict]:
    """The W7 matrix: one entry per registered operation, sorted by name."""
    registry = default_registry()
    rows = []
    for op in sorted(OPS_BY_NAME):
        spec = OPS_BY_NAME[op]
        route = STATUS_TO_ROUTE[spec.status]
        try:
            registry_spec = registry.spec(op)
            registered = True
            requires_capability = registry_spec.requires_capability
            mutating = registry_spec.mutating
            recovery_safe = registry_spec.recovery_safe
        except KeyError:
            registered = False
            requires_capability = mutating = recovery_safe = None
        req = ALL_REQ_BY_OP.get(op)
        rows.append({
            'op': op,
            'registered': registered,
            'route': route,
            'provider': PROVIDER_BY_ROUTE[route],
            'provider_state': STATE_BY_ROUTE[route],
            'gated': route in GATED_ROUTES,
            'w3_status': spec.status,
            'requires_capability': requires_capability,
            'mutating': mutating,
            'recovery_safe': recovery_safe,
            'capability': None if req is None else req.capability,
            'min_assurance': None if req is None else req.min_assurance,
            'allowed_providers': None if req is None else list(req.allowed_providers),
            'profile_required': None if req is None else bool(req.profile_required),
            'resource_kind': None if req is None else req.resource_kind,
        })
    return rows


def route_for(op: str) -> dict:
    """The single route for one operation. Unknown operations are refused."""
    registry = default_registry()
    if not registry.has(op):
        raise UnknownOperation(op)
    spec = registry.spec(op)
    if op not in OPS_BY_NAME:
        raise UnknownOperation(f'{op} is registered but has no W3 interface entry')
    w3 = OPS_BY_NAME[op]
    if w3.op != spec.name:
        raise UnknownOperation(f'{op}: registry and interface disagree')
    route = STATUS_TO_ROUTE[w3.status]
    return {'op': op, 'route': route, 'provider': PROVIDER_BY_ROUTE[route],
            'provider_state': STATE_BY_ROUTE[route], 'gated': route in GATED_ROUTES,
            'w3_status': w3.status, 'requires_capability': spec.requires_capability,
            'mutating': spec.mutating, 'recovery_safe': spec.recovery_safe}


def gated_ops() -> tuple[str, ...]:
    return tuple(op for op in sorted(OPS_BY_NAME)
                 if STATUS_TO_ROUTE[OPS_BY_NAME[op].status] in GATED_ROUTES)


def parity_errors() -> list[str]:
    """Cross-check every matrix: nothing may vanish, nothing may be routed twice."""
    errors: list[str] = []
    registry = default_registry()
    registry_ops = {op for op in OPS_BY_NAME if registry.has(op)}
    rows = provider_matrix()
    routed = [row['op'] for row in rows]
    if len(routed) != len(set(routed)):
        errors.append('an operation is routed twice')
    if set(routed) != set(OPS_BY_NAME):
        errors.append('the router matrix and the W3 interface table disagree')
    unregistered = sorted(op for op in OPS_BY_NAME if not registry.has(op))
    if unregistered:
        errors.append(f'operations missing from the frozen registry: {unregistered}')
    for op in sorted(OPS_BY_NAME):
        if not registry.has(op):
            continue
        spec = registry.spec(op)
        if OPS_BY_NAME[op].status == 'deferred-privilege' and op not in REQ_BY_OP:
            errors.append(f'{op}: deferred-privilege without a W4 requirement')
    w4_gated = set(REQ_BY_OP) | set(HOST_CHAIN_OPS)
    if set(gated_ops()) != w4_gated:
        errors.append('the W7 gated set and the W4 matrix disagree')
    w5_rows = {row['op']: row for row in operation_matrix()}
    deferred_privilege = {op for op, spec in OPS_BY_NAME.items() if spec.status == 'deferred-privilege'}
    if set(w5_rows) != deferred_privilege:
        errors.append('the W5 profile matrix and the W3 deferred-privilege set disagree')
    for row in rows:
        if row['gated']:
            if row['op'] in w5_rows:
                if w5_rows[row['op']]['profile_required'] != row['profile_required']:
                    errors.append(f'{row["op"]}: profile requirement differs between W5 and W7')
            elif row['op'] in HOST_CHAIN_OPS:
                if row['profile_required'] is None:
                    errors.append(f'{row["op"]}: W4 requirement missing for the host-chain route')
            else:
                errors.append(f'{row["op"]}: gated operation without a W5 profile policy')
        elif row['profile_required']:
            errors.append(f'{row["op"]}: ungated operation must not require a profile')
    # W17F: semantic SET parity instead of a magic count. The authoritative registry is the
    # reference; the W4 matrix rows and the SCHEMA surface must both agree with it exactly, with
    # no duplicates and no unexplained extras.
    from tools.primitive_iface.schema import OPS_BY_NAME as _SCHEMA_OPS
    registered_names = [row['op'] for row in rows]
    registry_names = [n if isinstance(n, str) else getattr(n, 'op', n)
                      for n in registry_ops]
    expected_names = set(registry_names)
    for _label, _names in (('registered', registered_names), ('registry', registry_names),
                           ('schema', list(_SCHEMA_OPS))):
        _dupes = sorted({n for n in _names if _names.count(n) > 1})
        if _dupes:
            errors.append(f'duplicate {_label} operation names: {_dupes}')
    if set(registered_names) != expected_names:
        errors.append('registered operations differ from the authoritative registry: missing '
                      f'{sorted(expected_names - set(registered_names))}, unexpected '
                      f'{sorted(set(registered_names) - expected_names)}')
    if set(_SCHEMA_OPS) != expected_names:
        errors.append('schema operations differ from the authoritative registry: missing '
                      f'{sorted(expected_names - set(_SCHEMA_OPS))}, unexpected '
                      f'{sorted(set(_SCHEMA_OPS) - expected_names)}')
    return errors


def summary() -> dict:
    rows = provider_matrix()
    counts: dict[str, int] = {}
    for row in rows:
        counts[row['route']] = counts.get(row['route'], 0) + 1
    return {'schema': MATRIX_SCHEMA, 'operations': len(rows), 'routes': counts,
            'providers': sorted({row['provider'] for row in rows}),
            'wired': sorted(op for op, r in ((row['op'], row['route']) for row in rows)
                            if STATE_BY_ROUTE[r] == 'WIRED')}


def _self_test() -> list[str]:
    errors = parity_errors()
    rows = provider_matrix()
    from tools.primitive_iface.schema import OPS as _OPS_SURFACE
    _surface = {getattr(_o, 'op', _o) for _o in _OPS_SURFACE}
    _names = [r['op'] for r in rows] if rows and isinstance(rows[0], dict) else list(rows)
    _dupes = sorted({n for n in _names if _names.count(n) > 1})
    if _dupes:
        errors.append(f'matrix: duplicate operation names: {_dupes}')
    if set(_names) != _surface:
        errors.append('matrix: matrix must cover exactly the interface surface: missing '
                      f'{sorted(_surface - set(_names))}, unexpected {sorted(set(_names) - _surface)}')
    if sum(1 for r in rows if r['route'] == ROUTE_STUB) != 17:
        errors.append('expected 17 stub routes')
    # W17F: semantic parity instead of the historical count.
    from tools.primitive_iface import gate as _GATE
    _gated = set(_GATE.privilege_gated_ops())
    _deferred = sorted(r['op'] for r in rows if r['route'] == ROUTE_DEFERRED_PRIVILEGE)
    _ddupes = sorted({n for n in _deferred if _deferred.count(n) > 1})
    if _ddupes:
        errors.append(f'matrix: duplicate deferred-privilege operations: {_ddupes}')
    if set(_deferred) != _gated:
        errors.append('matrix: deferred-privilege routes must equal the privilege-gated set: missing '
                      f'{sorted(_gated - set(_deferred))}, unexpected {sorted(set(_deferred) - _gated)}')
    if sum(1 for r in rows if r['route'] == ROUTE_DEFERRED_HOST_CHAIN) != 1:
        errors.append('expected 1 deferred-host-chain route')
    if sum(1 for r in rows if r['route'] == ROUTE_MOCK_ONLY) != 4:
        errors.append('expected 4 mock-only routes')
    try:
        route_for('kernel.exploit.everything')
    except UnknownOperation:
        pass
    else:
        errors.append('an unknown operation must be refused')
    if route_for('kernel.read')['provider_state'] != 'DEFERRED':
        errors.append('privileged routes must stay DEFERRED in W7')
    if route_for('session.ping')['provider_state'] != 'WIRED':
        errors.append('stub routes must be wired')
    return errors


def main(argv: list[str]) -> int:
    if '--matrix' in argv:
        print(json.dumps({'schema': MATRIX_SCHEMA, 'summary': summary(),
                          'operations': provider_matrix()}, indent=1, sort_keys=True))
        return 0
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: matrix.py --matrix | --self-test')
        return 2
    errors = _self_test()
    counts = summary()['routes']
    print(f'provider router matrix: {summary()["operations"]} operations '
          f'({", ".join(f"{k}={v}" for k, v in sorted(counts.items()))})')
    if errors:
        print(f'ROUTER MATRIX INCONSISTENT ({len(errors)})')
        for err in errors:
            print(f'  - {err}')
        return 1
    print('ROUTER MATRIX OK: one route per operation, W3/W4/W5 parity, unknown ops refused')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
