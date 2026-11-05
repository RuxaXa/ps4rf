#!/usr/bin/env python3
"""Generate the native target operation table from the frozen core (P4/W8).

The target agent must not carry a second, hand-maintained operation list: the table
below is derived from the two frozen sources and is byte-checked in the gate.

* operation set, ``mutating``, ``recovery_safe`` -- ``core/rpc/registry.py`` (frozen core)
* family, capability binding, interface status -- ``tools/primitive_iface/schema.py`` (W3 freeze)
* route and provider state -- ``tools/dispatch/matrix.py`` (W7 provider router matrix)

Target disposition (W8 scope): an operation is ``wired`` on the target only when it is a
W3 ``stub`` operation *and* part of the approved W8 live scope (session, telemetry, the
agent's own memory and the agent-local sync objects). Everything else stays
``deferred``: privileged and host-chain operations because their provider state is
DEFERRED, the mock-only operations because the fault-injection mock is not part of the
native provider surface, and ``experiment.load`` because it is a host-side research
intake, not a console primitive. A deferred operation never reaches a provider handler;
it is answered with ``OPERATION_DEFERRED`` and ``provider_entry = false``.

Usage::

    python native/target/gen_optable.py --write     # (re)generate ps4rf_optable_data.h
    python native/target/gen_optable.py --check     # verify the checked-in file
    python native/target/gen_optable.py --self-test
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.rpc.registry import default_registry  # noqa: E402
from tools.primitive_iface.schema import OPS_BY_NAME  # noqa: E402
from tools.dispatch import matrix as MATRIX  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / 'ps4rf_optable_data.h'

# The W8 live scope: exactly the operations the owner approved for the first controlled
# live step. An operation outside this set is never wired on the target agent.
TARGET_WIRED_OPS = (
    'session.ping',
    'session.status',
    'telemetry.read',
    'memory.alloc',
    'memory.free',
    'sync.gate.create',
    'sync.gate.arrive',
    'sync.gate.wait',
    'sync.gate.status',
    'sync.gate.release',
    'sync.gate.destroy',
    'sync.barrier.create',
    'sync.barrier.wait',
    'sync.barrier.release',
    'sync.barrier.destroy',
    # W14 §15 (wire catalogue revision R4): the authenticated admin shutdown. Wired because the
    # *resident* daemon has to serve it -- and only the resident mode does: the provider refuses it
    # outside that mode, so the single-session profiles keep exactly the served set they had.
    # Non-privileged by construction: it changes no kernel state, triggers no reboot, reaches no
    # loader and installs no persistence.
    'session.shutdown',
)

ROUTE_IDS = {
    MATRIX.ROUTE_STUB: 'PS4RF_ROUTE_STUB',
    MATRIX.ROUTE_MOCK_ONLY: 'PS4RF_ROUTE_MOCK_ONLY',
    MATRIX.ROUTE_DEFERRED_PRIVILEGE: 'PS4RF_ROUTE_DEFERRED_PRIVILEGE',
    MATRIX.ROUTE_DEFERRED_HOST_CHAIN: 'PS4RF_ROUTE_DEFERRED_HOST_CHAIN',
    MATRIX.ROUTE_PRIVILEGED_PROVIDER: 'PS4RF_ROUTE_PRIVILEGED_PROVIDER',
}

# The one wired privileged provider (W14): the bounded kernel.read provider. The operation keeps
# its host route (deferred privilege) and is routed through the target dispatcher; the provider
# entry is the single W12 bounded read, gated by the host chain and one release per read.
PRIVILEGED_WIRED_OPS = tuple(sorted(MATRIX.TARGET_ROUTE_OVERRIDES))
TYPE_IDS = {
    'int': 'PS4RF_T_INT',
    'str': 'PS4RF_T_STR',
    'bool': 'PS4RF_T_BOOL',
    'ref': 'PS4RF_T_REF',
    'hex32': 'PS4RF_T_HEX32',
    'array': 'PS4RF_T_ARRAY',
    'object': 'PS4RF_T_OBJECT',
}

# A wired operation may only carry a capability that the *agent itself* owns: the W8
# live scope covers the agent's own memory, so `memory.alloc` / `memory.free` are
# allowed with their own capability name. Privileged namespaces (kernel, gpuvm,
# keymgr, ccp, samu, verify) must never be wired on the target.
WIRED_ALLOWED_CAPABILITIES = ('', 'memory.alloc', 'memory.free', 'kernel.read',
                             # W17F: real capability of the bounded native ioctl provider
                             'ioctl.invoke')
# W14: the only wired privileged provider. Exactly one operation may be wired on a privileged
# route, it must be the named override, and the agent's session loop must not name it (the gate
# checks that separately) -- so "wired" cannot spread by accident.
PRIVILEGED_WIRED_CAPABILITIES = ('kernel.read', 'ioctl.invoke')

DEFER_REASON = {
    MATRIX.ROUTE_STUB: 'wired on the host router; not part of the approved W8 live scope on the target',
    MATRIX.ROUTE_MOCK_ONLY: 'mock-only fault injection; not part of the native provider surface',
    MATRIX.ROUTE_DEFERRED_PRIVILEGE: 'provider state DEFERRED; W8 wires no privileged provider',
    MATRIX.ROUTE_DEFERRED_HOST_CHAIN: 'provider state DEFERRED; needs the host verification->grant chain',
    MATRIX.ROUTE_PRIVILEGED_PROVIDER: 'wired privileged provider (W14): bounded kernel.read, one '
                                     'release per provider entry, host chain still mandatory',
}


def rows() -> list[dict]:
    """The frozen, canonical operation rows (sorted by name)."""
    registry = default_registry()
    out: list[dict] = []
    for entry in MATRIX.provider_matrix():
        op = entry['op']
        spec = OPS_BY_NAME[op]
        assert registry.has(op), f'{op} missing from the frozen registry'
        assert entry['capability'] == (spec.capability or None) or not entry['gated'], op
        wired = op in TARGET_WIRED_OPS or op in PRIVILEGED_WIRED_OPS
        route = MATRIX.TARGET_ROUTE_OVERRIDES.get(op, entry['route'])
        assert route in (MATRIX.ROUTE_STUB, MATRIX.ROUTE_PRIVILEGED_PROVIDER) or not wired, \
            f'{op}: only stub or privileged-provider operations may be wired'
        assert route == entry['route'] or op in PRIVILEGED_WIRED_OPS, \
            f'{op}: a route override is only allowed for a named privileged operation'
        out.append({
            'name': op,
            'family': spec.family,
            'capability': spec.capability or '',
            'route': MATRIX.TARGET_ROUTE_OVERRIDES.get(op, entry['route']),
            'target': 'wired' if wired else 'deferred',
            'mutating': bool(spec.mutating),
            'recovery_safe': bool(spec.recovery_safe),
            'reason': '' if wired else DEFER_REASON[entry['route']],
            'args': [{'name': fl.name, 'type': fl.type, 'required': bool(fl.required)} for fl in spec.args],
        })
    out.sort(key=lambda r: r['name'])
    return out


def table_digest(rs: list[dict]) -> str:
    canon = json.dumps(rs, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(canon).hexdigest()


def render(rs: list[dict]) -> str:
    wired = [r for r in rs if r['target'] == 'wired']
    counts = {route: sum(1 for r in rs if r['route'] == route) for route in MATRIX.ROUTES}
    gen_sha = hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
    lines: list[str] = []
    add = lines.append
    add('/* GENERATED FILE -- do not edit.  native/target/gen_optable.py')
    add(' *')
    add(' * sources   : core/rpc/registry.py (frozen core) + tools/primitive_iface/schema.py (W3)')
    add(' *              + tools/dispatch/matrix.py (W7 provider router)')
    add(' * generator : native/target/gen_optable.py sha256 ' + gen_sha)
    add(f" * operations: {len(rs)}  target wired: {len(wired)}  target deferred: {len(rs) - len(wired)}")
    add(' * routes    : ' + ' '.join(f'{k}={v}' for k, v in counts.items()))
    add(' * table_sha256: ' + table_digest(rs))
    add(' */')
    add('#ifndef PS4RF_OPTABLE_DATA_H')
    add('#define PS4RF_OPTABLE_DATA_H')
    add('')
    add('#include "jcs.h"')
    add('')
    add(f'#define PS4RF_OP_TABLE_COUNT {len(rs)}u')
    add(f'#define PS4RF_OP_WIRED_COUNT {len(wired)}u')
    add(f'#define PS4RF_OP_DEFERRED_COUNT {len(rs) - len(wired)}u')
    add('#define PS4RF_OP_TABLE_SHA256 "' + table_digest(rs) + '"')
    add('#define PS4RF_OP_ROUTE_COUNTS "' + ' '.join(f'{k}={v}' for k, v in counts.items()) + '"')
    add('#define PS4RF_ARG_ROW_COUNT ' + str(sum(len(r['args']) for r in rs)) + 'u')
    add('')
    add('enum {')
    add('    PS4RF_ROUTE_STUB = 0,')
    add('    PS4RF_ROUTE_MOCK_ONLY = 1,')
    add('    PS4RF_ROUTE_DEFERRED_PRIVILEGE = 2,')
    add('    PS4RF_ROUTE_DEFERRED_HOST_CHAIN = 3,')
    add('    /* W14: wired privileged provider -- entered only after the full router validation */')
    add('    PS4RF_ROUTE_PRIVILEGED_PROVIDER = 4')
    add('};')
    add('enum { PS4RF_TARGET_WIRED = 0, PS4RF_TARGET_DEFERRED = 1 };')
    add('enum {')
    add('    PS4RF_T_INT = 1, PS4RF_T_STR = 2, PS4RF_T_BOOL = 3, PS4RF_T_REF = 4,')
    add('    PS4RF_T_HEX32 = 5, PS4RF_T_ARRAY = 6, PS4RF_T_OBJECT = 7')
    add('};')
    add('')
    add('/* Fixed-size character arrays instead of pointers on purpose: a table of string')
    add(' * pointers would emit ELF relocations, and the loader applies none. The frozen')
    add(' * tables therefore live in .rodata as plain bytes. */')
    add('typedef struct {')
    add('    char name[48];')
    add('    char family[16];')
    add('    char capability[24];')
    add('    char defer_reason[96];')
    add('    unsigned char route;')
    add('    unsigned char target;')
    add('    unsigned char mutating;')
    add('    unsigned char recovery_safe;')
    add('} ps4rf_op_row;')
    add('')
    add('typedef struct { char name[24]; unsigned char type; unsigned char required; } ps4rf_arg_row;')
    add('')
    add('static const ps4rf_op_row PS4RF_OP_TABLE[PS4RF_OP_TABLE_COUNT] = {')
    for r in rs:
        add('    {"%s", "%s", "%s", "%s", %s, %s, %u, %u},' % (
            r['name'], r['family'], r['capability'], r['reason'], ROUTE_IDS[r['route']],
            'PS4RF_TARGET_WIRED' if r['target'] == 'wired' else 'PS4RF_TARGET_DEFERRED',
            1 if r['mutating'] else 0, 1 if r['recovery_safe'] else 0))
    add('};')
    add('')
    add('static const ps4rf_arg_row PS4RF_ARG_TABLE[PS4RF_ARG_ROW_COUNT] = {')
    for r in rs:
        for a in r['args']:
            add('    {"%s", %s, %u},  /* %s */' % (a['name'], TYPE_IDS[a['type']], 1 if a['required'] else 0, r['name']))
    add('};')
    add('')
    add('/* Argument slice [first, first+count) of PS4RF_ARG_TABLE for each operation. */')
    first = 0
    for r in rs:
        add('#define PS4RF_ARG_FIRST_%s %du' % (r['name'].replace('.', '_').upper(), first))
        add('#define PS4RF_ARG_COUNT_%s %du' % (r['name'].replace('.', '_').upper(), len(r['args'])))
        first += len(r['args'])
    add('')
    add('/* Argument check for one operation, driven by the frozen argument slices: every')
    add(' * required argument present, no unknown argument, every present argument of the')
    add(' * frozen type. Identical rules to tools/primitive_iface/validate.py. */')
    add('int ps4rf_arg_type_ok(const jval *v, unsigned char type);   /* native/target/ps4rf_router.c */')
    add('')
    add('#if defined(__GNUC__)')
    add('#define PS4RF_GEN_UNUSED __attribute__((unused))')
    add('#else')
    add('#define PS4RF_GEN_UNUSED')
    add('#endif')
    add('static PS4RF_GEN_UNUSED int ps4rf_args_slice_ok(unsigned first, unsigned n, const jval *args)')
    add('{')
    add('    unsigned k;')
    add('    if (args == NULL || jval_kind(args) != JVAL_OBJECT) return 0;')
    add('    /* the argument slices are small; the count fit is checked by the caller */')
    add('    for (k = 0u; k < n; k++) {')
    add('        const ps4rf_arg_row *ar = &PS4RF_ARG_TABLE[first + k];')
    add('        const jval *v = jval_get(args, ar->name);')
    add('        if (v == NULL) {')
    add('            if (ar->required) return 0;')
    add('            continue;')
    add('        }')
    add('        if (!ps4rf_arg_type_ok(v, ar->type)) return 0;')
    add('    }')
    add('    for (k = 0u; k < (unsigned)jval_count(args); k++) {')
    add('        const char *key = jval_key_at(args, k);')
    add('        unsigned q;')
    add('        unsigned found = 0u;')
    add('        if (key == NULL) return 0;')
    add('        for (q = 0u; q < n; q++) {')
    add('            const char *an = PS4RF_ARG_TABLE[first + q].name;')
    add('            unsigned t = 0u;')
    add('            while (an[t] != \'\\0\' && key[t] != \'\\0\' && an[t] == key[t]) t++;')
    add('            if (an[t] == \'\\0\' && key[t] == \'\\0\') { found = 1u; break; }')
    add('        }')
    add('        if (!found) return 0;')
    add('    }')
    add('    return 1;')
    add('}')
    add('')
    add('static PS4RF_GEN_UNUSED int ps4rf_optable_args_ok(unsigned row_index, const jval *args)')
    add('{')
    add('    switch (row_index) {')
    for idx, r_ in enumerate(rs):
        m = r_['name'].replace('.', '_').upper()
        add('    case %du: return ps4rf_args_slice_ok(PS4RF_ARG_FIRST_%s, PS4RF_ARG_COUNT_%s, args);' % (idx, m, m))
    add('    default: return 0;')
    add('    }')
    add('}')
    add('')
    add('#endif /* PS4RF_OPTABLE_DATA_H */')
    return '\n'.join(lines) + '\n'


def _self_test() -> list[str]:
    problems: list[str] = []
    rs = rows()
    # W17F: semantic parity against the authoritative surface instead of a historical count.
    _names = [r['name'] for r in rs]
    from tools.primitive_iface import schema as _IFACE
    _expected = {getattr(_o, 'op', _o) for _o in _IFACE.OPS}
    if set(_names) != _expected:
        problems.append('operations differ from the interface surface: missing '
                        f'{sorted(_expected - set(_names))}, unexpected '
                        f'{sorted(set(_names) - _expected)}')
    if len({r['name'] for r in rs}) != len(rs):
        problems.append('duplicate operation name')
    wired = [r['name'] for r in rs if r['target'] == 'wired']
    if wired != sorted(tuple(TARGET_WIRED_OPS) + PRIVILEGED_WIRED_OPS):
        problems.append(f'wired set mismatch: {wired}')
    for r in rs:
        if r['target'] == 'wired' and r['route'] not in (MATRIX.ROUTE_STUB,
                                                         MATRIX.ROUTE_PRIVILEGED_PROVIDER):
            problems.append(f"{r['name']}: only stub routes or the named privileged provider may "
                            'be wired')
        if r['route'] == MATRIX.ROUTE_PRIVILEGED_PROVIDER and \
                r['name'] not in PRIVILEGED_WIRED_OPS:
            problems.append(f"{r['name']}: privileged-provider route without a named override")
        if r['target'] == 'deferred' and not r['reason']:
            problems.append(f"{r['name']}: deferred without reason")
        if r['target'] == 'wired' and r['capability'] not in WIRED_ALLOWED_CAPABILITIES:
            problems.append(f"{r['name']}: capability {r['capability']!r} must not be wired on the target")
        if r['target'] == 'deferred' and r['capability'] in WIRED_ALLOWED_CAPABILITIES and \
                r['capability'] not in PRIVILEGED_WIRED_CAPABILITIES and r['capability']:
            problems.append(f"{r['name']}: agent-owned capability should be wired")
    priv = sorted(r['name'] for r in rs if r['route'] == MATRIX.ROUTE_PRIVILEGED_PROVIDER)
    if priv != sorted(PRIVILEGED_WIRED_OPS):
        problems.append(f'privileged provider set mismatch: {priv}')
    for r in rs:
        if r['route'] == MATRIX.ROUTE_PRIVILEGED_PROVIDER and \
                r['capability'] not in PRIVILEGED_WIRED_CAPABILITIES:
            problems.append(f"{r['name']}: privileged provider with capability "
                            f"{r['capability']!r}")
    if MATRIX.parity_errors():
        problems.append(f"router parity: {MATRIX.parity_errors()}")
    return problems


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else '--check'
    if mode == '--self-test':
        problems = _self_test()
        for p in problems:
            print('FAIL', p)
        print(f'gen_optable self-test: {len(problems)} problem(s)')
        return 1 if problems else 0
    body = render(rows())
    if mode == '--write':
        OUT.write_text(body)
        print(f'wrote {OUT.name} ({len(body)} bytes, table_sha256 '
              f'{table_digest(rows())[:16]}...)')
        return 0
    if mode == '--check':
        if not OUT.exists():
            print(f'FAIL missing {OUT}')
            return 1
        if OUT.read_text() != body:
            print(f'FAIL {OUT.name} is out of date; run --write')
            return 1
        problems = _self_test()
        for p in problems:
            print('FAIL', p)
        print(f'{OUT.name}: up to date, self-test {len(problems)} problem(s)')
        return 1 if problems else 0
    print(__doc__)
    return 2


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
