#!/usr/bin/env python3
"""PS4RF parity vector catalog (P4/W2 prep, offline, deterministic).

Generates ``vectors-v1.json`` next to this file. Three vector classes:

1. ``frames`` — byte-level message frames (canonical plaintext + sealed
   ciphertext) for REQUEST / RESPONSE(OK|ERROR) / BYE, using the same TEST-ONLY
   session material as the crypto catalog. Message *shapes* follow the spec's
   session loop (citations per entry); the encoding/sealing is frozen code.
2. ``registry`` / ``pool`` / ``agent`` — behavioural vectors derived by running
   the frozen implementation (``core/rpc/requests.py``, ``core/rpc/pool.py``,
   ``mock/agent.py``). Outcome = observed result or exception class name.
3. ``hang`` and ``w0_decisions_applied`` — documented semantics that the frozen
   repo does not (yet) express in code, plus the owner decisions (W0/D8, D9,
   D12, D13) this catalog now reflects; both clearly labelled with sources.

Run (from the repo root, venv on PATH):
    PATH="$PWD/.venv/bin:$PATH" python tests/fixtures/parity/gen_parity.py

Determinism: no timestamps, no absolute paths, sorted keys, trailing newline.
All keys/nonces below are TEST-ONLY constants; thread races are avoided by
driving each pool case through explicit events.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys
import threading
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.canonical import canonical_bytes  # noqa: E402
from core.rpc.handshake import (AuthenticationFailed, Direction, DirectionChannel,  # noqa: E402
                                derive_keys, nonce_prefix, transcript_hash)
from core.rpc.pool import BoundedPool, TaskState  # noqa: E402
from core.rpc.requests import RequestIdRegistry  # noqa: E402
from core.rpc.hang import MockHangReleased  # noqa: E402
from core.rpc.wire import (FRAME_TYPE_BYTES, FRAME_TYPE_NAMES, FRAME_HEADER_BYTES,  # noqa: E402
                           RESERVED_FRAME_TYPES, WIRE_SPEC_VERSION, build_header)
from mock.agent import MockAgent  # noqa: E402

OUT_NAME = 'vectors-v1.json'
SCHEMA = 'ps4rf-parity-vectors-v1'
CRYPTO_CATALOG = REPO_ROOT / 'tests' / 'fixtures' / 'crypto' / 'vectors-v1.json'

# TEST-ONLY session material — must stay identical to the crypto catalog.
PSK = bytes(range(32))
AGENT_NONCE = bytes(range(16))
HOST_NONCE = bytes(range(16, 32))
SESSION_ID = 'SES-0123456789ABCDEF'

RID_A = 'REQ-' + '0' * 31 + '1'
RID_B = 'REQ-' + '0' * 31 + '2'
RID_C = 'REQ-' + '0' * 31 + '3'
RID_MEM = 'REQ-0123456789abcdef0123456789abcdef'

WAIT = 5.0
SETTLE = 0.15

# Message shapes (citations are recorded per frame).
REQ_PING = {'header': {'request_id': RID_A},
            'body': {'operation': 'session.ping', 'arguments': {}}}
REQ_ALLOC = {'header': {'request_id': RID_MEM},
             'body': {'operation': 'memory.alloc', 'arguments': {'size': 4096}}}
RESP_OK = {'header': {'in_reply_to': RID_A}, 'status': 'OK', 'result': {}}
RESP_ERR = {'header': {'in_reply_to': RID_MEM}, 'status': 'ERROR',
            'error': {'code': 'TOO_MANY_INFLIGHT'}}
BYE = {'msg': 'BYE', 'reason': 'CLIENT_CLOSE',
       'cleanup': {'state': 'COMPLETE', 'resources': []}}

SHAPE_SRC_LOOP = ('docs/spec-history/Pasted_text(5).txt l.953-967 (session loop: '
                  'header.request_id / header.in_reply_to / {"status","result"})')
SHAPE_SRC_BYE = 'docs/spec-history/Pasted_text(5).txt l.983-987 (BYE + cleanup report)'
SHAPE_SRC_F16 = 'docs/spec-history/Pasted_text(7).txt l.612-623 (F16 direction FSM)'


def _sha(rel: str) -> str:
    return hashlib.sha256((REPO_ROOT / rel).read_bytes()).hexdigest()


def _session() -> dict:
    th = transcript_hash({'msg': 'HELLO'}, {'msg': 'HELLO_ACK'})  # placeholder, recomputed below
    # The real transcript uses the crypto catalog's HELLO/HELLO_ACK objects.
    crypto = json.loads(CRYPTO_CATALOG.read_text())
    hello, ack = crypto['protocol']['objects']['hello'], crypto['protocol']['objects']['hello_ack']
    assert crypto['protocol']['test_only_material']['psk_hex'] == PSK.hex()
    assert crypto['protocol']['test_only_material']['session_id'] == SESSION_ID
    th = transcript_hash(hello, ack)
    keys = derive_keys(PSK, AGENT_NONCE, HOST_NONCE, th)
    return {
        'test_only_material': {'warning': 'TEST-ONLY constants; never valid as production keys.',
                               'psk_hex': PSK.hex(), 'agent_nonce_hex': AGENT_NONCE.hex(),
                               'host_nonce_hex': HOST_NONCE.hex(), 'session_id': SESSION_ID},
        'transcript_sha256': th.hex(),
        'keys': {'k_hs': keys.k_hs.hex(), 'k_agent_to_host': keys.k_agent_to_host.hex(),
                 'k_host_to_agent': keys.k_host_to_agent.hex()},
        'nonce_prefixes': {
            'agent_to_host': nonce_prefix(PSK, AGENT_NONCE, HOST_NONCE, th, Direction.AGENT_TO_HOST).hex(),
            'host_to_agent': nonce_prefix(PSK, AGENT_NONCE, HOST_NONCE, th, Direction.HOST_TO_AGENT).hex()},
        'hello_ack_objects_source': 'tests/fixtures/crypto/vectors-v1.json (shared TEST-ONLY session)',
        '_th_bytes': th,
    }


def _frames(sess: dict) -> list:
    th = sess['_th_bytes']
    keys = derive_keys(PSK, AGENT_NONCE, HOST_NONCE, th)
    p_h2a = nonce_prefix(PSK, AGENT_NONCE, HOST_NONCE, th, Direction.HOST_TO_AGENT)
    p_a2h = nonce_prefix(PSK, AGENT_NONCE, HOST_NONCE, th, Direction.AGENT_TO_HOST)
    ch_in = DirectionChannel(keys.k_host_to_agent, p_h2a, SESSION_ID, Direction.HOST_TO_AGENT,
                             suite='AEAD_CHACHA20_POLY1305', max_frame_bytes=1048576, protocol_version=1)
    ch_out = DirectionChannel(keys.k_agent_to_host, p_a2h, SESSION_ID, Direction.AGENT_TO_HOST,
                              suite='AEAD_CHACHA20_POLY1305', max_frame_bytes=1048576, protocol_version=1)
    frames = []
    plan = [
        ('h2a_request_ping_seq0', ch_in, 'REQUEST', REQ_PING, SHAPE_SRC_LOOP),
        ('h2a_request_alloc_seq1', ch_in, 'REQUEST', REQ_ALLOC, SHAPE_SRC_LOOP),
        ('a2h_response_ok_seq0', ch_out, 'RESPONSE', RESP_OK, SHAPE_SRC_LOOP),
        ('a2h_response_error_seq1', ch_out, 'RESPONSE', RESP_ERR, SHAPE_SRC_LOOP),
        ('a2h_bye_seq2', ch_out, 'BYE', BYE, SHAPE_SRC_BYE),
    ]
    for ident, chan, mtype, obj, src in plan:
        pt = canonical_bytes(obj)
        seq, ct = chan.seal(mtype, pt)
        header = build_header(len(ct), mtype, seq)
        frames.append({'id': ident, 'direction': ('host-to-agent' if chan is ch_in else 'agent-to-host'),
                       'message_type': mtype, 'frame_type_byte': FRAME_TYPE_BYTES[mtype],
                       'sequence': seq, 'object': obj,
                       'canonical_hex': pt.hex(),
                       'nonce_hex': (chan_prefix(chan) + seq.to_bytes(8, 'big')).hex(),
                       'ciphertext_hex': ct.hex(), 'frame_len': len(ct),
                       'header_hex': header.hex(),
                       'wire_hex': (header + ct).hex(),
                       'wire_spec_version': WIRE_SPEC_VERSION,
                       'shape_source': src})
    return frames


def chan_prefix(chan: DirectionChannel) -> bytes:
    return chan._prefix


# --------------------------------------------------------------------------
# channel vectors (frozen core/rpc/handshake.py DirectionChannel)
# --------------------------------------------------------------------------

def _channel_cases(sess: dict) -> dict:
    th = sess['_th_bytes']
    keys = derive_keys(PSK, AGENT_NONCE, HOST_NONCE, th)

    def mk(direction: Direction) -> DirectionChannel:
        prefix = nonce_prefix(PSK, AGENT_NONCE, HOST_NONCE, th, direction)
        key = keys.k_agent_to_host if direction is Direction.AGENT_TO_HOST else keys.k_host_to_agent
        return DirectionChannel(key, prefix, SESSION_ID, direction,
                                suite='AEAD_CHACHA20_POLY1305',
                                max_frame_bytes=1048576, protocol_version=1)

    probe = {'probe': 'channel-open'}
    seq, ct = mk(Direction.AGENT_TO_HOST).seal('RESPONSE', canonical_bytes(probe))
    cases = []

    opened = mk(Direction.AGENT_TO_HOST).open('RESPONSE', seq, ct)
    cases.append({'id': 'open_roundtrip', 'observed': {
        'plaintext_hex': opened.hex(),
        'matches_canonical': opened == canonical_bytes(probe),
        'sequence': seq}})

    def _attempt(label, fn):
        try:
            fn()
            outcome = {'outcome': 'ok'}
        except Exception as exc:  # noqa: BLE001
            outcome = {'outcome': 'raises', 'exception': type(exc).__name__,
                       'qualified': f'{type(exc).__module__}.{type(exc).__name__}'}
        outcome['id'] = label
        return outcome

    cases.append(_attempt('open_wrong_message_type_rejected',
                          lambda: mk(Direction.AGENT_TO_HOST).open('EVENT', seq, ct)))
    cases.append(_attempt('open_sequence_gap_rejected',
                          lambda: mk(Direction.AGENT_TO_HOST).open('RESPONSE', seq + 1, ct)))

    c = mk(Direction.AGENT_TO_HOST)
    c.open('RESPONSE', seq, ct)
    cases.append(_attempt('open_replay_rejected', lambda: c.open('RESPONSE', seq, ct)))

    cases.append(_attempt('cross_direction_open_rejected',
                          lambda: mk(Direction.HOST_TO_AGENT).open('RESPONSE', seq, ct)))

    return {
        'cases': cases,
        'note': ('Authentication failures (bad tag, foreign message type, wrong direction) surface '
                 'as core.rpc.handshake.AuthenticationFailed, a ProtocolError subclass; the '
                 'cryptography library exception InvalidTag never escapes the RPC layer (W0/D9, '
                 'Core/Wire Revision R1). The mapping lives in the shared helper '
                 'core.rpc.handshake.open_authenticated, which mock and native must both follow.'),
    }


# --------------------------------------------------------------------------
# registry vectors (frozen core/rpc/requests.py)
# --------------------------------------------------------------------------

def _registry_cases() -> dict:
    cases = []

    def run(ident, steps):
        r = RequestIdRegistry() if steps.get('new_registry', True) else steps['registry']
        observed = []
        for action, args in steps['actions']:
            try:
                fn = getattr(r, action)
                out = fn(*args)
                observed.append({'action': action, 'outcome': 'ok', 'result': out})
            except Exception as exc:  # noqa: BLE001
                observed.append({'action': action, 'outcome': 'raises', 'exception': type(exc).__name__,
                                 'message': str(exc)})
            if action == 'register':
                observed[-1]['pending_count'] = r.pending_count()
        cases.append({'id': ident, 'observed': observed})

    run('register_and_pending_count', {'actions': [('register', (RID_A,)), ('pending_count', ())]})
    run('bad_ids_rejected', {'actions': [('register', (bad,)) for bad in
                                         ('REQ-' + 'A' * 32, 'REQ-' + '0' * 31, 'XEQ-' + '0' * 32,
                                          'REQ-' + '0' * 33)]})
    run('duplicate_pending_rejected', {'actions': [('register', (RID_A,)), ('register', (RID_A,)),
                                                   ('pending_count', ())]})
    run('respond_once_semantics', {'actions': [('register', (RID_A,)), ('respond_once', (RID_A,)),
                                               ('respond_once', (RID_A,))]})
    run('re_register_after_complete_rejected',
        {'actions': [('register', (RID_A,)), ('complete', (RID_A,)), ('register', (RID_A,))]})

    # completed-cache eviction (LRU, size 2)
    r = RequestIdRegistry(completed_cache_size=2)
    observed = []
    for rid in (RID_A, RID_B, RID_C):
        r.register(rid)
        r.complete(rid)
    for rid in (RID_A, RID_C):
        try:
            r.register(rid)
            observed.append({'action': 'register', 'request_id': rid, 'outcome': 'ok'})
        except Exception as exc:  # noqa: BLE001
            observed.append({'action': 'register', 'request_id': rid, 'outcome': 'raises',
                             'exception': type(exc).__name__})
    cases.append({'id': 'completed_cache_eviction_lru_size2', 'observed': observed})

    return {'pattern': RequestIdRegistry.RE.pattern, 'cases': cases}


# --------------------------------------------------------------------------
# pool vectors (frozen core/rpc/pool.py) — event-driven, no timing races
# --------------------------------------------------------------------------

def _pool_cases() -> list:
    cases = []

    # P1: capacity -> TOO_MANY_INFLIGHT; task stays pending until finish()
    gate, started = threading.Event(), threading.Event()
    p = BoundedPool(1, 1)
    obs = {}
    obs['submit_a'] = p.submit(RID_A, 'memory.alloc', lambda rid, op: (started.set(), gate.wait(WAIT)))
    assert started.wait(WAIT)
    obs['submit_b'] = p.submit(RID_B, 'memory.alloc', lambda rid, op: None)
    obs['available_tokens_while_running'] = p.available_tokens
    gate.set()
    time.sleep(SETTLE)
    obs['has_pending_after_task_returned'] = p.has_pending()
    obs['available_tokens_after_task_returned'] = p.available_tokens
    p.finish(RID_A)
    obs['available_tokens_after_finish'] = p.available_tokens
    obs['has_pending_after_finish'] = p.has_pending()
    p.shutdown(wait_running=True)
    cases.append({'id': 'capacity_and_too_many_inflight', 'observed': obs})

    # P2: poisoned -> POISONED verdict, no token leak
    p = BoundedPool(1, 2)
    obs = {'poison_returns': (lambda t: {'in_flight': t[0], 'queued': t[1]})(p.poison('vector'))}
    obs['submit_after_poison'] = p.submit(RID_A, 'memory.alloc', lambda rid, op: None)
    obs['available_tokens'] = p.available_tokens
    p.shutdown(wait_running=True)
    cases.append({'id': 'poisoned_and_no_token_leak', 'observed': obs})

    # P3: poison reports in-flight + queued; queued task is canceled via callback
    gate, started, done = threading.Event(), threading.Event(), threading.Event()
    canceled = []
    p = BoundedPool(1, 2, on_canceled=lambda rid, op: (canceled.append(rid), done.set()))
    obs = {}
    p.submit(RID_A, 'op.a', lambda rid, op: (started.set(), gate.wait(WAIT)))
    assert started.wait(WAIT)
    p.submit(RID_B, 'op.b', lambda rid, op: None)
    infl, queued = p.poison('vector')
    obs['in_flight'] = infl
    obs['queued'] = queued
    gate.set()
    assert done.wait(WAIT)
    obs['on_canceled_calls'] = canceled
    p.shutdown(wait_running=True)
    cases.append({'id': 'poison_reports_in_flight_and_queued', 'observed': obs})

    # P4: worker crash -> callback + task left pending until finish()
    done = threading.Event()
    crashes = []
    p = BoundedPool(1, 2, on_worker_crash=lambda rid, op, exc: (crashes.append(
        {'request_id': rid, 'operation': op, 'exception': exc}), done.set()))

    def boom(rid, op):
        raise ValueError('vector task failure')
    obs = {'submit': p.submit(RID_C, 'op.c', boom)}
    assert done.wait(WAIT)
    obs['crash_records'] = crashes
    obs['has_pending_after_crash'] = p.has_pending()
    obs['available_tokens_after_crash'] = p.available_tokens
    p.finish(RID_C)
    obs['has_pending_after_finish'] = p.has_pending()
    obs['available_tokens_after_finish'] = p.available_tokens
    p.shutdown(wait_running=True)
    cases.append({'id': 'worker_crash_leaves_task_pending_until_finish', 'observed': obs})

    # P5: shutdown drains the queue and invokes the cancel callback
    gate, started = threading.Event(), threading.Event()
    cb = []
    p = BoundedPool(1, 2)
    p.submit(RID_A, 'op.a', lambda rid, op: (started.set(), gate.wait(WAIT)))
    assert started.wait(WAIT)
    p.submit(RID_B, 'op.b', lambda rid, op: None)
    p.shutdown(cancel_queued=True, wait_running=False,
               cancel_cb=lambda rid, op: cb.append({'request_id': rid, 'operation': op}))
    obs = {'cancel_cb_calls': cb, 'available_tokens_after_drain': p.available_tokens,
           'has_pending_after_drain': p.has_pending()}
    gate.set()
    p.shutdown(wait_running=True)
    cases.append({'id': 'shutdown_drains_queued_and_calls_cancel_cb', 'observed': obs})

    return cases


# --------------------------------------------------------------------------
# agent vectors (frozen mock/agent.py) — with an explicit send hook
# --------------------------------------------------------------------------

def _agent_cases() -> dict:
    cases = []

    a = MockAgent()
    a._reqs.register(RID_A)
    sent = []
    a._respond_now = lambda rid, op, resp: sent.append(
        {'request_id': rid, 'operation': op, 'payload': resp})
    a._on_canceled(RID_A, 'memory.alloc')
    cases.append({'id': 'canceled_request_emits_recovery_required',
                  'observed': {'sent': sent, 'pending_count': a._reqs.pending_count()}})

    a = MockAgent()
    a._transport_dead = True
    a._reqs.register(RID_A)
    sent = []
    a._respond_now = lambda rid, op, resp: sent.append(resp)
    a._on_canceled(RID_A, 'memory.alloc')
    cases.append({'id': 'canceled_request_with_dead_transport_sends_nothing',
                  'observed': {'sent': sent, 'pending_count': a._reqs.pending_count()}})

    a = MockAgent()
    a._on_worker_crash(RID_A, 'op.crash', 'ValueError')
    cases.append({'id': 'worker_crash_records_evidence', 'observed': {'evidence': a._evidence}})

    a = MockAgent()
    a.configure_pool()
    pool_obs = {'workers': len(a._pool._threads), 'max_inflight': a._pool._max_inflight}
    a._pool.shutdown(wait_running=True)
    cases.append({'id': 'default_pool_configuration',
                  'observed': {'agent_cap': MockAgent.AGENT_CAP, **pool_obs}})

    a = MockAgent()
    ref = a.create_gate(2)
    cases.append({'id': 'gate_resource_allocation',
                  'observed': {'ref_pattern': 'gate:<8 random bytes, uppercase hex>',
                               'ref_matches_pattern': bool(re.fullmatch(r'gate:[0-9A-F]{16}', ref)),
                               'registered_in_manager': ref in a.resources._held,
                               'registered_in_agent_map': ref in a._gates}})

    return {'cases': cases}


def build() -> dict:
    sess = _session()
    public_session = {k: v for k, v in sess.items() if not k.startswith('_')}
    return {
        'schema': SCHEMA,
        'frozen_sources': {
            'core/rpc/pool.py': _sha('core/rpc/pool.py'),
            'core/rpc/requests.py': _sha('core/rpc/requests.py'),
            'core/rpc/hang.py': _sha('core/rpc/hang.py'),
            'mock/agent.py': _sha('mock/agent.py'),
            'core/canonical.py': _sha('core/canonical.py'),
            'core/rpc/handshake.py': _sha('core/rpc/handshake.py'),
        },
        'session': public_session,
        'direction_fsm': {
            'host_to_agent': ['REQUEST'],
            'agent_to_host': ['RESPONSE', 'EVENT', 'BYE'],
            'wrong_direction_outcome': 'ProtocolError, session closed immediately (fail-close)',
            'source': SHAPE_SRC_F16,
        },
        'frames': _frames(sess),
        'wire_frame': {
            'wire_spec_version': WIRE_SPEC_VERSION,
            'header_layout': '4-byte big-endian ciphertext length | 1 type byte | 8-byte big-endian sequence',
            'header_bytes': FRAME_HEADER_BYTES,
            'total_frame_bytes': '13 + ciphertext length',
            'length_check': 'before any allocation; n > max_frame_bytes -> FrameLimitExceeded(lib: ProtocolError)',
            'unknown_type_byte': 'UnknownFrameType (ProtocolError): protocol error, session fails '
                                 'closed, no reply attempt',
            'type_byte_vs_aad_mismatch': 'the type byte selects the AAD message type, so a byte that '
                                         'contradicts the sealed type fails authentication -> '
                                         'AuthenticationFailed (W0/D9)',
            'direction_check': 'the session loop rejects message types outside the F16 inbound set -> '
                               'ProtocolError -> connection closed, no reply attempt',
            'source': 'docs/spec-history/Pasted_text(5).txt l.644-656 (recv_frame) + l.661 '
                      '(fail-close matrix); frame type byte table decided by the owner (W0/D12)',
            'type_table_status': 'DEFINED — mapping v1 is in-repo property (W0/D12) and lives in the '
                                 'single shared table core/rpc/wire.py; every implementation (host '
                                 'core, mock, native) must use it',
            'type_table': {f'0x{byte:02x}': name for byte, name in sorted(FRAME_TYPE_NAMES.items())},
            'type_table_inverse_source': 'FRAME_TYPE_NAMES / FRAME_TYPE_BYTES (core/rpc/wire.py)',
            'reserved_types': sorted(RESERVED_FRAME_TYPES),
            'active_types_w2': ['REQUEST', 'RESPONSE', 'BYE'],
            'reserved_semantics': {
                'EVENT': 'reserved message type, no body in v0.1, not sent by the agent (W0/D13)',
                'READY': 'reserved; the host may tolerate it for mock compatibility, native W2 need '
                         'not send it; it gets wire semantics only once shape, encryption status, '
                         'capability content and state transition are specified (W0/D13). Sending a '
                         'reserved type raises ReservedFrameType (fail closed).',
            },
            'sequence_ceiling': 'EFFECTIVE_LAST_SEQ = 2**53 - 1 (W0/D8); beyond it SequenceExhausted, '
                                'session closed, no wraparound',
        },
        'channel': _channel_cases(sess),
        'registry': _registry_cases(),
        'pool': {'task_states': [t.value for t in TaskState], 'cases': _pool_cases()},
        'agent': _agent_cases(),
        'hang': {
            'exception_class': MockHangReleased.__name__,
            'bases': [b.__name__ for b in MockHangReleased.__mro__[1:]],
            'semantics': ('a hung worker blocks permanently and produces no RESPONSE; the client sees '
                          'a timeout, never a clean BYE; console is treated as recovery-pending'),
            'semantics_source': 'docs/spec-history/Pasted_text(5).txt l.906-909, l.990-991',
        },
        'w0_decisions_applied': [
            {'decision': 'D8', 'id': 'effective_sequence_ceiling',
             'effect': 'EFFECTIVE_LAST_SEQ = 2**53 - 1 is enforced in seal()/open(); reaching it '
                       'closes the session with SequenceExhausted, never wraps around',
             'vectors': ['constants.EFFECTIVE_LAST_SEQ',
                         'boundaries:seal_at_effective_ceiling_then_exhausted',
                         'boundaries:seal_sequence_exhausted']},
            {'decision': 'D9', 'id': 'authentication_failure_mapping',
             'effect': 'the shared helper core.rpc.handshake.open_authenticated maps InvalidTag to '
                       'AuthenticationFailed (ProtocolError); no library exception escapes the RPC layer',
             'vectors': ['channel:cases', 'boundaries:open_tampered_tag_then_ok']},
            {'decision': 'D12', 'id': 'frame_type_byte_table',
             'effect': 'wire mapping v1 is in-repo property and single-sourced in core/rpc/wire.py '
                       '(0x01 REQUEST, 0x02 RESPONSE, 0x03 EVENT, 0x04 BYE, 0x05 READY); any other '
                       'byte is a protocol error and the session fails closed',
             'vectors': ['wire_frame.type_table', 'frames[].frame_type_byte',
                         'frames[].header_hex', 'frames[].wire_hex']},
            {'decision': 'D13', 'id': 'ready_and_event_scope',
             'effect': 'EVENT and READY are reserved: not sent in v0.1, no body, out of the W2 byte '
                       'parity scope; the host may tolerate READY for mock compatibility',
             'vectors': ['wire_frame.reserved_types', 'wire_frame.reserved_semantics',
                         'wire_frame.active_types_w2']},
        ],
    }


def render(vectors: dict) -> bytes:
    return (json.dumps(vectors, indent=1, sort_keys=True, ensure_ascii=False) + '\n').encode('utf-8')


def main() -> int:
    vectors = build()
    out = pathlib.Path(__file__).resolve().parent / OUT_NAME
    data = render(vectors)
    out.write_bytes(data)
    print(f'wrote {out} ({len(data)} bytes)')
    print(f'  schema={vectors["schema"]} frames={len(vectors["frames"])}'
          f' registry_cases={len(vectors["registry"]["cases"])}'
          f' pool_cases={len(vectors["pool"]["cases"])}'
          f' agent_cases={len(vectors["agent"]["cases"])}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
