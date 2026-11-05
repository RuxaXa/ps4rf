"""The approved W8 smoke sequence.

Exactly the operations the owner approved for the first controlled live step, in the
approved order, and nothing else. Every step carries its expectation so a live run cannot
silently drift:

* the ten smoke steps of the W8 brief (ping, status, telemetry, alloc, free, gate create,
  two agent-local lanes arrive/wait, explicit release, destroy, final status)
* one negative step: ``kernel.read`` must be refused with ``OPERATION_DEFERRED`` and must
  show ``provider_entry=false`` in the error detail -- the privileged route is never
  entered.

The gate steps are expressed as separate requests because the native agent is single
threaded: a lane's ``wait`` is bounded by its ``timeout_ms`` and returns
``released = false`` while the gate is still closed, which is exactly the frozen
``GateWaitResult.TIMEOUT`` semantics. The post-release wait then proves the release path.

Expected routes come from the frozen W7 provider matrix (``tools.dispatch.matrix``); the
host does not trust its own copy of the routing table for the verdict, it checks the
*observed* outcome against the frozen one.
"""

from __future__ import annotations

import re

from tools.dispatch import matrix as MATRIX

GATE_TIMEOUT_MS = 150          # short, explicit: the gate is closed by design at this point
ALLOC_SIZE = 4096


class Step:
    def __init__(self, name, op, arguments=None, *, expect_status='OK', expect_code=None,
                 expect_detail_contains=None, check=None, note='') -> None:
        self.name = name
        self.op = op
        self.arguments = dict(arguments or {})
        self.expect_status = expect_status
        self.expect_code = expect_code
        self.expect_detail_contains = expect_detail_contains
        self.check = check
        self.note = note


def _resolve(arguments: dict, refs: dict) -> dict:
    """``@step.field`` placeholders refer to a value observed in an earlier response."""
    out = {}
    for key, value in arguments.items():
        if isinstance(value, str) and value.startswith('@'):
            step, _, field = value[1:].partition('.')
            out[key] = refs[step][field]
        else:
            out[key] = value
    return out


def _expect_false(key):
    def check(response, refs):
        result = response.get('result') or {}
        if result.get(key) is not False:
            return f'expected {key}=false, got {result.get(key)!r}'
        return None
    return check


def _expect_true(key):
    def check(response, refs):
        result = response.get('result') or {}
        if result.get(key) is not True:
            return f'expected {key}=true, got {result.get(key)!r}'
        return None
    return check


def _expect_participants(count):
    def check(response, refs):
        result = response.get('result') or {}
        if result.get('participants') != count:
            return f'expected participants={count}, got {result.get("participants")!r}'
        return None
    return check


def sequence_w9() -> list[Step]:
    """The W9 sequence: status, then the agent's own fixed attestation, then status again.

    The privileged step is *not* a request -- the host sends no address, no flag and no
    trigger. The agent runs the single read-only attestation callback after its first
    session.status response and reports the result in one sealed EVENT frame, which the host
    verifies independently (tools/hostctl/attest.py).
    """
    return [
        Step('status_before', 'session.status', {},
             note='session state before the fixed attestation step'),
        Step('status_after', 'session.status', {},
             note='session state after the attestation step (resources must be unchanged)'),
    ]


def sequence() -> list[Step]:
    return [
        Step('ping', 'session.ping', {}, check=_expect_true('pong'),
             note='session liveness on the console'),
        Step('status', 'session.status', {},
             note='frozen session state + held resources before any mutation'),
        Step('telemetry', 'telemetry.read', {},
             note='agent telemetry: session state, inflight, held resources'),
        Step('alloc', 'memory.alloc', {'size': ALLOC_SIZE, 'alignment': 16},
             note="the agent's own memory only"),
        Step('free', 'memory.free', {'ref': '@alloc.ref'},
             note='the exact ref from alloc'),
        Step('gate_create', 'sync.gate.create', {'parties': 2},
             note='gate = manual research window (B12)'),
        Step('arrive1', 'sync.gate.arrive', {'gate': '@gate_create.gate'},
             check=_expect_participants(1), note='lane 1 arrives'),
        Step('arrive2', 'sync.gate.arrive', {'gate': '@gate_create.gate'},
             check=_expect_participants(2), note='lane 2 arrives'),
        Step('wait_closed', 'sync.gate.wait',
             {'gate': '@gate_create.gate', 'timeout_ms': GATE_TIMEOUT_MS},
             check=_expect_false('released'), note='gate is closed here: released=false'),
        Step('release', 'sync.gate.release', {'gate': '@gate_create.gate'},
             check=_expect_true('released'), note='explicit release'),
        Step('wait_released', 'sync.gate.wait',
             {'gate': '@gate_create.gate', 'timeout_ms': GATE_TIMEOUT_MS},
             check=_expect_true('released'), note='release is observable for a lane'),
        Step('destroy', 'sync.gate.destroy', {'gate': '@gate_create.gate'},
             check=_expect_true('destroyed'), note='gate destroyed, ref released'),
        Step('status_final', 'session.status', {}, note='final session state'),
        Step('neg_kernel_read', 'kernel.read',
             {'region_index': 1, 'offset': 0, 'length': 16},
             expect_status='ERROR', expect_code='OPERATION_DEFERRED',
             expect_detail_contains='not implemented by the native stub provider',
             note='W14: kernel.read is wired on the target only as the bounded privileged '
                  'provider. On a build without that provider the wired route still refuses '
                  'fail-closed ("not implemented"), the request carries the W13-C2 bounded region '
                  'triplet, and the refusal under test is the route refusal -- not an argument '
                  'error. The provider itself is exercised by tests/test_w13c2_wire_arguments.py '
                  'against the PS4RF_TARGET_KREAD build.'),
    ]


DEFERRED_CODE = 'OPERATION_DEFERRED'
UNSUPPORTED_CODE = 'OPERATION_UNSUPPORTED'


def expected_route(op: str) -> str:
    return MATRIX.route_for(op)['route']


def expected_provider_state(op: str) -> str:
    return MATRIX.route_for(op)['provider_state']


def provider_entry_observed(op: str, response: dict) -> bool:
    """Derivation of ``provider_entry`` from the wire (documented, checked by the agent's
    own accounting and by the static artefact gate):

    * a successful response can only come from a provider handler -- the router builds
      ``status == OK`` exclusively on the provider path after ``ps4rf_provider_enter``
    * ``OPERATION_DEFERRED`` and ``OPERATION_UNSUPPORTED`` are refusals raised before any
      handler is entered
    * any other error code was raised inside the handler (argument or resource checks of
      the provider), so the handler was entered
    """
    status = response.get('status')
    code = (response.get('error') or {}).get('code')
    if status == 'OK':
        return True
    if code in (DEFERRED_CODE, UNSUPPORTED_CODE):
        return False
    return True


def detail_provider_entry_false(response: dict) -> bool:
    detail = (response.get('error') or {}).get('detail') or ''
    return bool(re.search(r'\bprovider_entry=false\b', detail))
