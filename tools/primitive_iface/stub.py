#!/usr/bin/env python3
"""PS4RF P4/W3 host-side provider stub for the frozen primitive interface v1.

This is the operator-host counterpart of the native provider surface: it implements
the 16 operations that need no privilege escalation (session, telemetry, memory,
sync, experiment intake) with the semantics of the frozen core (it *reuses*
``core.sync.gate.Gate``/``Barrier`` and ``core.resources.manager.ResourceManager``
instead of re-implementing them) and refuses every gated operation fail-closed with
``OPERATION_DEFERRED``. It never talks to a console, a socket or a subprocess.

Deliberately **no** core change: the stub only *calls* frozen core code, so W3 maps
the surface without touching frozen behaviour (W0: no core architecture change
outside a recorded integration finding - findings F7-F10 are recorded in
``docs/P4-PRIMITIVE-INTERFACES.md``).

Usage::

    python tools/primitive_iface/stub.py --self-test

Exit codes: 0 = all checks passed, 1 = check failed, 2 = usage error.
"""

from __future__ import annotations

import pathlib
import sys
import threading
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from core.resources.manager import ResourceManager  # noqa: E402
from core.sync.gate import Barrier, Gate, GateWaitResult, ResourceStateInvalid  # noqa: E402
from tools.primitive_iface.schema import (  # noqa: E402
    OPS_BY_NAME, STATUS_MOCK, STATUS_STUB,
)
from tools.primitive_iface.validate import (  # noqa: E402
    InterfaceError, cleanup_report, error_response, ok_response, validate_arguments,
    validate_bye, validate_request_envelope, validate_response_envelope,
)

SESSION_STATES = ('ACTIVE', 'RECOVERY_REQUIRED', 'CLOSED')
DEFAULT_WAIT_MS = 5000


class StubProvider:
    """Host-side stub of the native provider (W3: interface freeze, no privilege)."""

    def __init__(self, session_state: str = 'ACTIVE', max_alloc: int = 1048576,
                 max_held: int = 64):
        if session_state not in SESSION_STATES:
            raise ValueError(f'unknown session state {session_state!r}')
        self._state = session_state
        self._max_alloc = max_alloc
        self._max_held = max_held
        self._lock = threading.RLock()
        self.resources = ResourceManager()
        self._gates: dict[str, Gate] = {}
        self._barriers: dict[str, Barrier] = {}
        self._arrived: dict[str, set] = {}
        self._arrive_seq = 0
        self._inflight = 0

    # --- helpers ------------------------------------------------------------------
    @property
    def session_state(self) -> str:
        with self._lock:
            return self._state

    def enter_recovery(self) -> None:
        """Mirror the mock's recovery transition (K9: a hanging call cannot be cleaned)."""
        with self._lock:
            self._state = 'RECOVERY_REQUIRED'

    def _held(self) -> list[str]:
        return sorted(self.resources._held)  # noqa: SLF001 - frozen core has no accessor

    def _ok(self, op: str, request_id, result: dict, cleanup: dict | None = None) -> dict:
        if not request_id:
            response: dict = {'status': 'OK', 'result': result}
            if cleanup:
                response['cleanup'] = cleanup
            return response
        return ok_response(op, request_id, result, cleanup)

    def _err(self, request_id, code: str) -> dict:
        if not request_id:
            return {'status': 'ERROR', 'error': {'code': code}}
        return error_response(request_id, code)

    def _require_active(self) -> None:
        if self._state != 'ACTIVE':
            raise InterfaceError('SESSION_RECOVERY_REQUIRED', 'session is not ACTIVE')

    def _gate(self, ref, table):
        obj = table.get(ref)
        if obj is None:
            raise InterfaceError('RESOURCE_STATE_INVALID', f'unknown ref {ref!r}')
        return obj

    # --- the single entry point ---------------------------------------------------
    def call(self, op: str, arguments: dict | None = None, request_id: str | None = None,
             seq: int | None = None) -> dict:
        """Execute one operation, returning a validated response envelope."""
        spec = OPS_BY_NAME.get(op)
        if spec is None:
            return self._err(request_id, 'OPERATION_UNSUPPORTED')
        args = dict(arguments or {})
        with self._lock:
            self._inflight += 1
        try:
            try:
                validate_arguments(op, args)
            except InterfaceError as exc:
                return self._err(request_id, exc.code)
            if spec.status == STATUS_MOCK:
                return self._err(request_id, 'OPERATION_DEFERRED')
            if spec.status != STATUS_STUB:
                return self._err(request_id, 'OPERATION_DEFERRED')
            handler = getattr(self, '_op_' + op.replace('.', '_'))
            try:
                if spec.mutating:
                    self._require_active()
                result, cleanup = handler(args, request_id, seq)
            except InterfaceError as exc:
                return self._err(request_id, exc.code)
            except ResourceStateInvalid as exc:
                return self._err(request_id, 'RESOURCE_STATE_INVALID')
        finally:
            with self._lock:
                self._inflight -= 1
        return self._ok(op, request_id, result, cleanup)

    def call_request(self, message: dict) -> dict:
        """Validate and execute a full REQUEST envelope."""
        rid = message.get('header', {}).get('request_id') if isinstance(message, dict) else None
        try:
            op = validate_request_envelope(message)
        except InterfaceError as exc:
            return self._err(rid, exc.code)
        body = message['body']
        return self.call(op, body.get('arguments') or {}, rid, body.get('seq'))

    # --- handlers -----------------------------------------------------------------
    def _op_session_ping(self, args, rid, seq):
        return (lambda: ({'pong': True, 'seq': seq}, None))()

    def _op_session_status(self, args, rid, seq):
        return {'session_state': self._state, 'mutating_allowed': self._state == 'ACTIVE',
                'held_resources': self._held()}, None

    def _op_session_shutdown(self, args, rid, seq):
        """W14 §15: the authenticated admin shutdown. The mock models the target's provider: the
        session must be ACTIVE, the request must name the capability the catalogue binds to this
        operation, and the answer is the acknowledgement -- ending the lifetime is the agent's job,
        not the provider's (a provider that could end the process would be a second exit path)."""
        if self._state != 'ACTIVE':
            raise InterfaceError('SESSION_RECOVERY_REQUIRED', f'session is {self._state}')
        if args.get('capability') != 'session.admin':
            raise InterfaceError('CAPABILITY_REQUIRED', 'session.admin is required')
        return {'status': 'ACCEPTED'}, None

    def _op_telemetry_read(self, args, rid, seq):
        return {'session_state': self._state, 'inflight': self._inflight,
                'held_resources': self._held()}, None

    def _op_memory_alloc(self, args, rid, seq):
        size = args['size']
        if size < 1:
            raise InterfaceError('ARGUMENT_INVALID', 'size must be >= 1')
        if size > self._max_alloc:
            raise InterfaceError('RESOURCE_LIMIT', f'size {size} > {self._max_alloc}')
        align = args.get('alignment')
        if align is not None and (align < 1 or align & (align - 1)):
            raise InterfaceError('ARGUMENT_INVALID', 'alignment must be a power of two')
        if len(self._held()) >= self._max_held:
            raise InterfaceError('RESOURCE_LIMIT', 'too many held resources')
        ref = self.resources.acquire('mem')
        return {'ref': ref}, cleanup_report('PENDING')

    def _op_memory_free(self, args, rid, seq):
        ref = args['ref']
        if not self.resources.release(ref):
            raise InterfaceError('RESOURCE_STATE_INVALID', f'unknown ref {ref!r}')
        return {'freed': ref}, cleanup_report('COMPLETE')

    def _sync_create(self, table, kind, parties):
        if parties < 1:
            raise InterfaceError('ARGUMENT_INVALID', 'parties must be >= 1')
        if len(table) >= self._max_held:
            raise InterfaceError('RESOURCE_LIMIT', 'too many held resources')
        obj = Barrier(parties) if kind == 'barrier' else Gate(parties)
        ref = self.resources.acquire(kind)

        def cleanup():
            table.pop(ref, None)
            self._arrived.pop(ref, None)
            obj.destroy()
            return True

        self.resources.attach_cleanup(ref, cleanup)
        table[ref] = obj
        self._arrived[ref] = set()
        return ref

    def _op_sync_gate_create(self, args, rid, seq):
        return {'gate': self._sync_create(self._gates, 'gate', args['parties'])}, None

    def _op_sync_barrier_create(self, args, rid, seq):
        return {'barrier': self._sync_create(self._barriers, 'barrier', args['parties'])}, None

    def _op_sync_gate_arrive(self, args, rid, seq):
        ref = args['gate']
        gate = self._gate(ref, self._gates)
        self._arrive_seq += 1
        pid = f'p{self._arrive_seq}'
        count = gate.arrive(pid)
        self._arrived[ref].add(pid)
        return {'registered': True, 'participants': count}, None

    def _op_sync_barrier_wait(self, args, rid, seq):
        ref = args['barrier']
        barrier = self._gate(ref, self._barriers)
        self._arrive_seq += 1
        pid = f'p{self._arrive_seq}'
        barrier.arrive(pid)
        self._arrived[ref].add(pid)
        return self._wait_result(barrier, args)

    def _op_sync_gate_wait(self, args, rid, seq):
        gate = self._gate(args['gate'], self._gates)
        return self._wait_result(gate, args)

    @staticmethod
    def _wait_result(obj, args):
        outcome = obj.wait(args.get('timeout_ms', DEFAULT_WAIT_MS))
        if outcome is GateWaitResult.DESTROYED:
            raise InterfaceError('RESOURCE_DESTROYED', 'waiter released by destroy')
        return {'released': outcome is GateWaitResult.RELEASED}, None

    def _op_sync_gate_status(self, args, rid, seq):
        ref = args['gate']
        st = self._gate(ref, self._gates).status()
        return {'participants': st['arrived_count'], 'released': st['released'],
                'destroyed': st['destroyed']}, None

    def _op_sync_gate_release(self, args, rid, seq):
        gate = self._gate(args['gate'], self._gates)
        if gate.status()['destroyed']:
            raise InterfaceError('RESOURCE_DESTROYED', 'gate is destroyed')
        gate.release()
        return {'released': True}, None

    def _op_sync_barrier_release(self, args, rid, seq):
        return self._op_sync_gate_release({'gate': args['barrier']}, rid, seq)

    def _destroy(self, table, ref):
        obj = self._gate(ref, table)
        obj.destroy()
        # destroy frees the slot: the ref is gone afterwards, waiters saw RESOURCE_DESTROYED
        self.resources._held.pop(ref, None)  # noqa: SLF001
        table.pop(ref, None)
        self._arrived.pop(ref, None)
        return {'destroyed': True}

    def _op_sync_gate_destroy(self, args, rid, seq):
        return self._destroy(self._gates, args['gate']), None

    def _op_sync_barrier_destroy(self, args, rid, seq):
        return self._destroy(self._barriers, args['barrier']), None

    def _op_experiment_load(self, args, rid, seq):
        return {'accepted': args['ir_sha256']}, None

    # --- session teardown ---------------------------------------------------------
    def bye(self, reason: str = 'CLIENT_CLOSE') -> dict:
        """Clean disconnect: report remaining resources (D5 disconnect cleanup)."""
        report = self.resources.cleanup_all()
        message = {'msg': 'BYE', 'reason': reason,
                   'cleanup': {'state': report.state, 'resources': report.resources}}
        validate_bye(message)
        with self._lock:
            self._state = 'CLOSED'
        return message

    def recovery_bye(self) -> dict:
        """Terminate after a hang: cleanup cannot be completed (K9)."""
        leaks = [{'ref': ref, 'final_state': 'LEAKED'} for ref in self._held()]
        for ref in leaks:
            self.resources._held.pop(ref['ref'], None)  # noqa: SLF001
        message = {'msg': 'BYE', 'reason': 'RECOVERY_REQUIRED',
                   'cleanup': {'state': 'PARTIAL' if leaks else 'COMPLETE', 'resources': leaks}}
        validate_bye(message)
        with self._lock:
            self._state = 'RECOVERY_REQUIRED'
        return message


def _self_test() -> int:
    checks = 0
    failures: list[str] = []

    def check(condition: bool, label: str) -> None:
        nonlocal checks
        checks += 1
        if not condition:
            failures.append(label)

    rid = 'REQ-' + '0' * 31 + '9'
    p = StubProvider()
    r = p.call('session.ping', {}, rid, seq=7)
    check(r['status'] == 'OK' and r['result'] == {'pong': True, 'seq': 7}, 'session.ping ok')
    r = p.call('memory.alloc', {'size': 4096}, rid)
    ref = r['result']['ref']
    check(r['status'] == 'OK' and ref.startswith('mem:') and len(ref) == 20, 'memory.alloc ref shape')
    check(r['cleanup']['state'] == 'PENDING', 'memory.alloc cleanup PENDING')
    check(p.call('memory.free', {'ref': ref}, rid)['result'] == {'freed': ref}, 'memory.free ok')
    check(p.call('memory.free', {'ref': ref}, rid)['error']['code'] == 'RESOURCE_STATE_INVALID',
          'double free refused')
    check(p.call('session.status', {}, rid)['result']['mutating_allowed'] is True, 'status ACTIVE')
    check(p.call('memory.alloc', {'size': 0}, rid)['error']['code'] == 'ARGUMENT_INVALID', 'size 0')
    check(p.call('memory.alloc', {'size': 10 ** 9}, rid)['error']['code'] == 'RESOURCE_LIMIT', 'size cap')
    check(p.call('memory.alloc', {'size': 16, 'alignment': 3}, rid)['error']['code'] == 'ARGUMENT_INVALID',
          'bad alignment')
    check(p.call('memory.alloc', {'size': 16, 'nope': 1}, rid)['error']['code'] == 'ARGUMENT_INVALID',
          'unknown argument')

    # gates
    g = p.call('sync.gate.create', {'parties': 2}, rid)['result']['gate']
    check(g.startswith('gate:'), 'gate ref shape')
    check(p.call('sync.gate.arrive', {'gate': g}, rid)['result'] == {'registered': True, 'participants': 1},
          'gate arrive')
    check(p.call('sync.gate.arrive', {'gate': g}, rid)['result']['participants'] == 2, 'second participant')
    st = p.call('sync.gate.status', {'gate': g}, rid)['result']
    check(st == {'participants': 2, 'released': False, 'destroyed': False}, 'gate status')
    check(p.call('sync.gate.wait', {'gate': g, 'timeout_ms': 20}, rid)['result'] == {'released': False},
          'gate wait timeout is not an error')
    out: list = []
    t = threading.Thread(target=lambda: out.append(p.call('sync.gate.wait', {'gate': g}, rid)))
    t.start()
    time.sleep(0.05)
    p.call('sync.gate.release', {'gate': g}, rid)
    t.join(5)
    check(bool(out) and out[0]['result'] == {'released': True}, 'gate release wakes waiter')
    check(p.call('sync.gate.destroy', {'gate': g}, rid)['result'] == {'destroyed': True}, 'gate destroy')
    check(p.call('sync.gate.status', {'gate': g}, rid)['error']['code'] == 'RESOURCE_STATE_INVALID',
          'destroyed gate is gone')

    # destroyed gate must wake waiters with RESOURCE_DESTROYED, never success
    g2 = p.call('sync.gate.create', {'parties': 1}, rid)['result']['gate']
    out2: list = []
    t2 = threading.Thread(target=lambda: out2.append(p.call('sync.gate.wait', {'gate': g2}, rid)))
    t2.start()
    time.sleep(0.05)
    p.call('sync.gate.destroy', {'gate': g2}, rid)
    t2.join(5)
    check(bool(out2) and out2[0]['status'] == 'ERROR' and out2[0]['error']['code'] == 'RESOURCE_DESTROYED',
          'destroy wakes waiters with RESOURCE_DESTROYED')

    # barriers auto-release at the expected participant count
    b = p.call('sync.barrier.create', {'parties': 2}, rid)['result']['barrier']
    outb: list = []
    tb = threading.Thread(target=lambda: outb.append(p.call('sync.barrier.wait', {'barrier': b}, rid)))
    tb.start()
    time.sleep(0.05)
    p.call('sync.barrier.wait', {'barrier': b}, rid)
    tb.join(5)
    check(bool(out and outb) and outb[0]['result'] == {'released': True}, 'barrier releases at parties count')

    # experiment intake
    check(p.call('experiment.load', {'ir_sha256': 'a' * 64}, rid)['result'] == {'accepted': 'a' * 64},
          'experiment.load ok')

    # deferral is fail-closed for every gated operation
    deferred = [o.op for o in OPS_BY_NAME.values() if o.status not in (STATUS_STUB,)]
    for op in sorted(deferred):
        spec = OPS_BY_NAME[op]
        args = {}
        for fl in spec.args:
            args[fl.name] = {'int': 1, 'str': 'x', 'bool': True, 'ref': 'mem:0123456789ABCDEF',
                             'hex32': 'a' * 64, 'array': [], 'object': {}}[fl.type]
        resp = p.call(op, args, rid)
        check(resp['status'] == 'ERROR' and resp['error']['code'] == 'OPERATION_DEFERRED',
              f'{op} refused as OPERATION_DEFERRED')
    check(p.call('no.such.op', {}, rid)['error']['code'] == 'OPERATION_UNSUPPORTED',
          'unknown op refused')

    # recovery gate: mutating ops stop, recovery_safe ops keep working
    leak = p.call('memory.alloc', {'size': 32}, rid)['result']['ref']
    p.enter_recovery()
    check(p.call('memory.alloc', {'size': 32}, rid)['error']['code'] == 'SESSION_RECOVERY_REQUIRED',
          'mutating op refused in recovery')
    check(p.call('session.ping', {}, rid)['status'] == 'OK', 'ping still allowed in recovery')
    check(p.call('telemetry.read', {}, rid)['status'] == 'OK', 'telemetry still allowed in recovery')
    bye = p.recovery_bye()
    check(bye['cleanup']['state'] == 'PARTIAL' and any(r['ref'] == leak for r in bye['cleanup']['resources']),
          'recovery BYE reports leaked resources')

    # clean disconnect reports a complete cleanup
    p2 = StubProvider()
    p2.call('sync.gate.create', {'parties': 1}, rid)
    bye2 = p2.bye()
    check(bye2['cleanup']['state'] == 'COMPLETE' and bye2['reason'] == 'CLIENT_CLOSE', 'clean BYE')

    # request envelope path (the shape pinned by the parity catalog)
    p3 = StubProvider()
    req = {'header': {'request_id': rid}, 'body': {'operation': 'memory.alloc',
                                                  'arguments': {'size': 4096}}}
    check(p3.call_request(req)['status'] == 'OK', 'call_request happy path')
    bad = {'header': {'request_id': 'nope'}, 'body': {'operation': 'memory.alloc', 'arguments': {'size': 1}}}
    check(p3.call_request(bad)['error']['code'] == 'ARGUMENT_INVALID', 'bad request id refused')

    if failures:
        print(f'stub.py self-test: {len(failures)} FAILED of {checks}')
        for label in failures:
            print(f'  - {label}')
        return 1
    print(f'stub.py self-test: {checks} checks passed')
    return 0


def main(argv: list[str]) -> int:
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: stub.py --self-test')
        return 2
    return _self_test()


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
