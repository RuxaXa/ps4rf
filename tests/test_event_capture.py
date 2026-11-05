"""W11.1A: host side EVENT capture, single reader routing and evidence assembly (offline).

The console sends EVENT frames unsolicited -- while a response is pending, between two
responses, after the last response, or immediately before BYE. The contract tested here:

* exactly one component reads the socket (``HostSession._recv_frame``); no request specific wait
  loop reads frames itself,
* every inbound frame is routed by type: RESPONSE -> request dispatcher, EVENT -> event sink,
  BYE -> session lifecycle,
* an EVENT is never dropped silently: unknown types are recorded as opaque authenticated events,
  a known type failing its schema is recorded as EVENT_SCHEMA_REJECTED with the reason,
  duplicates are defined,
* a BYE does not cut the event queue, and the evidence assembly copies whatever was captured --
  the live branch of the runner used to lose it, which is the root cause of the W11.1 live
  ``boot_binding_event: null`` gap.

The ``boot.binding`` fixtures are the real events of the approved W11.1 payload, captured offline
from the host stand-in runs (``tests/fixtures/w11_1_event_*.json``); nothing is invented here.

An EVENT that arrives after a response stays in the socket until the host reads again -- which is
exactly why the "between responses" and "after the last response" cases below read twice before
asserting, and why the live runner must assemble its evidence from the session, not from the
last response it happened to see.
"""

from __future__ import annotations

import json
import pathlib
import socket
import threading

import pytest

from core.canonical import canonical_bytes
from core.rpc import wire
from core.rpc.handshake import (Direction, DirectionChannel, agent_handshake, new_nonce,
                                nonce_prefix, transcript_hash)

from tools.hostctl import cli
from tools.hostctl.endpoint import SocketEndpoint
from tools.hostctl.evidence import RunRecord
from tools.hostctl.session import HostSession

REPO = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = pathlib.Path(__file__).resolve().parent / 'fixtures'
PSK = bytes(range(32))

STABLE_EVENT = json.loads((FIXTURES / 'w11_1_event_stable.json').read_text())
DIAG_EVENT = json.loads((FIXTURES / 'w11_1_event_both_not_found.json').read_text())


# --------------------------------------------------------------------------- scripted agent

def _hello() -> dict:
    return {'aead': 'AEAD_CHACHA20_POLY1305', 'agent_version': 'scripted', 'label': 'scripted-peer',
            'msg': 'HELLO', 'nonce': new_nonce().hex(), 'protocol_version': 1,
            'provider': 'scripted-peer', 'transport': 'tcp'}


READY = {'msg': 'READY', 'agent_version': 'scripted', 'label': 'scripted-peer',
         'transport': 'tcp', 'capabilities': {'operations': []}}

BYE_BOOT_READ_FAILED = {'msg': 'BYE', 'reason': 'BOOT_READ_FAILED', 'cleanup': 'COMPLETE',
                        'resources': []}


class ScriptedAgent(threading.Thread):
    """Agent side peer over a socketpair: real handshake, real AEAD, scripted frame order.

    ``script`` maps a 0 based request index to a callback ``fn(agent, request)``. A callback may
    send any sequence of EVENT/RESPONSE/BYE frames; if it sends no RESPONSE, a plain OK response
    for the current request is appended automatically (so the host never blocks by accident).
    The request index in the script *is* the gate -- a callback must not re-check the request
    count itself.
    """

    def __init__(self, sock: socket.socket, script: dict) -> None:
        super().__init__(daemon=True)
        self.ep = SocketEndpoint(sock)
        self.script = script
        self.requests: list[dict] = []
        self.error: BaseException | None = None
        self._sent_response = False
        self._stop = False

    # --- plumbing -----------------------------------------------------------------
    def run(self) -> None:  # pragma: no cover - exercised through the tests
        try:
            hello = _hello()
            keys, ack = agent_handshake(self.ep, PSK, hello)
            an, hn = bytes.fromhex(hello['nonce']), bytes.fromhex(ack['nonce'])
            th = transcript_hash(hello, ack)
            sid = ack['session_id']
            self.ch_h2a = DirectionChannel(keys.k_host_to_agent,
                                           nonce_prefix(PSK, an, hn, th, Direction.HOST_TO_AGENT),
                                           sid, Direction.HOST_TO_AGENT,
                                           suite='AEAD_CHACHA20_POLY1305',
                                           protocol_version=1)
            self.ch_a2h = DirectionChannel(keys.k_agent_to_host,
                                           nonce_prefix(PSK, an, hn, th, Direction.AGENT_TO_HOST),
                                           sid, Direction.AGENT_TO_HOST,
                                           suite='AEAD_CHACHA20_POLY1305',
                                           protocol_version=1)
            self.send('READY', READY)
            while not self._stop:
                header = self.ep.recv_exact(wire.FRAME_HEADER_BYTES)
                mtype, seq, length = wire.parse_header(header)
                plaintext = self.ch_h2a.open(mtype, seq, self.ep.recv_exact(length))
                assert mtype == 'REQUEST', f'the host may only send REQUEST, got {mtype!r}'
                request = json.loads(plaintext)
                index = len(self.requests)
                self.requests.append(request)
                self._sent_response = False
                callback = self.script.get(index)
                if callback is not None:
                    callback(self, request)
                if not self._sent_response:
                    self.respond(self.rid(request))
        except BaseException as exc:  # recorded, never raised into the test thread
            self.error = exc

    @staticmethod
    def rid(request: dict) -> str:
        return request['header']['request_id']

    def frames(self, items) -> bytes:
        """Seal several frames and return them as one byte string (one write, exact order)."""
        # READY and EVENT are reserved types in wire spec v1: they may only be sent with an
        # explicit opt in, exactly like the frozen agent does (W8 READY, W9/W11 EVENT)
        return b''.join(wire.encode_frame(self.ch_a2h, mtype, canonical_bytes(obj),
                                          allow_reserved=(mtype in ('READY', 'EVENT')))
                        for mtype, obj in items)

    def send(self, mtype: str, obj: dict) -> None:
        self.ep.send_all(self.frames([(mtype, obj)]))

    def send_many(self, items) -> None:
        """Deliver several frames in a single write: [EVENT][BYE] really are adjacent."""
        self.ep.send_all(self.frames(items))

    def event(self, event: dict) -> None:
        self.send('EVENT', event)

    def respond(self, rid: str, status: str = 'OK', result: dict | None = None) -> None:
        self._sent_response = True
        self.send('RESPONSE', {'header': {'in_reply_to': rid}, 'status': status,
                               'body': {'result': result or {}}})

    def bye(self, reason: str = 'DONE') -> None:
        self._stop = True
        self.send('BYE', {'msg': 'BYE', 'reason': reason, 'cleanup': 'COMPLETE', 'resources': []})


# --- the two shapes the console actually used ---------------------------------------------

def respond_then_event(event):
    """A response with the event behind it: read with the *next* read."""
    def callback(agent, request):
        agent.respond(agent.rid(request))
        agent.event(event)
    return callback


def event_then_respond(event):
    """The event is in flight *before* the awaited response."""
    def callback(agent, request):
        agent.event(event)
        agent.respond(agent.rid(request))
    return callback


@pytest.fixture
def peer():
    live: list[tuple[HostSession, ScriptedAgent]] = []

    def _make(script: dict, *, accept_event: bool = True, trace: bool = False,
              monkeypatch=None):
        if trace and monkeypatch is not None:
            monkeypatch.setenv('PS4RF_FRAME_TRACE', '1')
        host_sock, agent_sock = socket.socketpair()
        agent = ScriptedAgent(agent_sock, script)
        agent.start()
        session = HostSession(SocketEndpoint(host_sock), PSK, accept_event=accept_event)
        session.handshake()
        session.recv_ready()
        live.append((session, agent))
        return session, agent

    yield _make
    for session, agent in live:
        session.close()
        agent.ep.close()


def _recorder(mode: str = 'offline-loopback') -> RunRecord:
    return RunRecord(run_id='RUN-test', mode=mode, repo={}, payload={}, transport={})


# ----------------------------------------------------------- mandated regression tests (1-4)

def test_event_between_responses_recorded(peer):
    """EVENT between two RESPONSEs: buffered as unsolicited, then recorded by the next read."""
    session, _ = peer({1: respond_then_event(STABLE_EVENT)})
    session.request('session.ping')                       # index 0
    session.request('session.status')                     # index 1: response, then the event
    assert session.boot_binding is None, 'not read yet -- the event is unsolicited'
    session.request('telemetry.read')                     # index 2: reads the event first
    assert session.boot_binding is not None, 'the event between two responses was lost'
    assert len(session.events) == 1
    assert session.boot_binding['event'] == 'boot.binding'


def test_event_before_expected_response_not_lost(peer):
    """EVENT arriving before the awaited RESPONSE: the waiter must not consume or drop it."""
    session, _ = peer({1: event_then_respond(DIAG_EVENT)})
    session.request('session.ping')
    response = session.request('session.status')
    assert response['status'] == 'OK', 'the waiter must return the RESPONSE, not the EVENT'
    assert session.boot_binding is not None, 'the event before the response was dropped'
    # READY + RESPONSE(ping) + EVENT + RESPONSE(status): the event was read *and* the response
    assert session.counters['frames_received'] == 4
    assert session.boot_binding['run_status_name'] == 'BOOT_READ_FAILED'


def test_event_after_final_response_before_bye_recorded(peer):
    """EVENT after the last RESPONSE, BYE later: await_bye must still record the event.

    The console writes all three frames from the same thread, so the order cannot invert; the
    callback writes them too (a second writer would make this test racy, not the host).
    """
    def callback(agent, request):
        agent.respond(agent.rid(request))
        agent.event(STABLE_EVENT)
        agent.bye('BOOT_READ_FAILED')

    session, agent = peer({0: callback})
    session.request('session.ping')
    bye = session.await_bye()
    assert bye is not None and bye['reason'] == 'BOOT_READ_FAILED'
    assert session.boot_binding is not None, (
        f'the event before the BYE was lost: events={len(session.events)} '
        f'rejected={session.event_schema_rejected} '
        f'agent_error={agent.error!r}')


def test_event_immediately_before_bye_recorded(peer):
    """[EVENT][BYE] in one write: the event queue is not cut by the BYE."""
    def callback(agent, request):
        agent.respond(agent.rid(request))
        agent.send_many([('EVENT', DIAG_EVENT), ('BYE', BYE_BOOT_READ_FAILED)])
        agent._stop = True

    session, _ = peer({0: callback})
    session.request('session.ping')
    bye = session.await_bye()
    assert bye['reason'] == 'BOOT_READ_FAILED'
    assert session.boot_binding is not None, 'the event immediately before the BYE was lost'
    assert session.events_before_bye == 1, 'the BYE must not cut the event queue'

    # ... and the evidence assembly copies it, exactly as the live branch must
    rec = _recorder('live-controller')
    report = cli.capture_events(rec, session, w11=True)
    assert rec.doc['boot_binding_event'] is not None
    assert report['verified'] is True and report['no_boot_id'] is True
    assert rec.doc['event_capture']['boot_binding_captured'] is True


# ------------------------------------------------------ dispatcher / reader invariants (5, 6)

def test_request_waiter_does_not_consume_event(peer, monkeypatch):
    """Every EVENT goes to the sink, once, whichever request is being awaited."""
    calls = []
    original = HostSession.record_event

    def counting(self, mtype, sequence, plaintext, raw):
        calls.append(json.loads(plaintext).get('event'))
        return original(self, mtype, sequence, plaintext, raw)

    monkeypatch.setattr(HostSession, 'record_event', counting)
    session, _ = peer({1: lambda agent, request: agent.event(STABLE_EVENT),
                       2: lambda agent, request: agent.event(DIAG_EVENT)})
    for op in ('session.ping', 'session.status', 'session.status'):
        session.request(op)
    assert calls == ['boot.binding', 'boot.binding'], 'an event was consumed by a wait loop'
    assert len(session.events) == 2
    assert session.boot_binding is not None


def test_single_socket_reader():
    """One reader per session: no wait loop reads the socket on its own."""
    source = (REPO / 'tools' / 'hostctl' / 'session.py').read_text()
    assert source.count('def _recv_frame') == 1
    assert source.count('self.ep.recv_exact(') == 2, 'the frame reader must be the only reader'
    # both wait paths route through the one router instead of inspecting frames themselves
    assert source.count('self._route(') == 2, \
        'request() and await_bye() must both route through the one router'
    for token in ("if mtype == 'EVENT'", "if mtype == 'BYE'",
                  "wire.check_inbound(mtype, ('RESPONSE',))"):
        assert token in source, f'the router must handle {token}'

    # no other host tool module opens the session socket for reading
    # sorted(): glob enumerates in filesystem order, so comparing the list as found
    # made this test pass or fail depending on the directory layout.
    readers = sorted(p.name for p in (REPO / 'tools' / 'hostctl').glob('*.py')
                     if 'recv_exact(' in p.read_text())
    assert readers == ['endpoint.py', 'session.py'], f'unexpected socket readers: {readers}'


# --------------------------------------------------------- fail closed / schema / junk (7-9)

def test_event_schema_failure_is_recorded_not_dropped(peer):
    """A boot.binding event that fails its schema is recorded as EVENT_SCHEMA_REJECTED."""
    bad_schema = dict(STABLE_EVENT, schema='ps4rf.boot.binding.v0')
    missing = {k: v for k, v in STABLE_EVENT.items() if k != 'read2'}

    def callback(agent, request):
        agent.event(bad_schema)
        agent.event(missing)

    session, _ = peer({0: callback})
    session.request('session.ping', request_id='r-1')
    assert session.boot_binding is None, 'a schema-invalid event must never become the binding'
    assert len(session.events) == 2, 'schema-invalid events are still recorded raw'
    reasons = [r['reason'] for r in session.event_schema_rejected]
    assert len(session.event_schema_rejected) == 2, reasons
    assert any('schema' in r for r in reasons)
    assert any('missing required fields' in r for r in reasons)
    assert [r['event'] for r in session.event_schema_rejected] == ['boot.binding', 'boot.binding']

    rec = _recorder()
    report = cli.capture_events(rec, session, w11=True)
    assert rec.doc['boot_binding_event'] is None
    assert rec.doc['event_schema_rejected'], 'the reason must reach the evidence'
    detail = [c['detail'] for c in rec.doc['checks']
              if c['name'] == 'w11:boot.binding event received'][0]
    assert 'EVENT_SCHEMA_REJECTED' in detail, 'the evidence must say why, not just null'
    assert report['verified'] is False


def test_duplicate_event_behavior_defined(peer):
    """Two boot.binding events: both are kept, the last one wins, the duplicate is noted."""
    first = dict(STABLE_EVENT, label='first')
    second = dict(DIAG_EVENT, label='second')

    def callback(agent, request):
        agent.event(first)
        agent.event(second)

    session, _ = peer({0: callback})
    session.request('session.ping')
    assert len(session.events) == 2
    assert session.boot_binding['label'] == 'second', 'the last event must win'
    assert len(session.duplicate_events) == 1
    assert session.duplicate_events[0]['event'] == 'boot.binding'

    rec = _recorder()
    cli.capture_events(rec, session, w11=True)
    assert rec.doc['duplicate_events'], 'duplicates must be visible in the evidence'


def test_unknown_event_behavior_defined(peer):
    """Unknown event types are kept as opaque authenticated events -- never a silent drop."""
    unknown = {'msg': 'EVENT', 'event': 'kernel.something.new', 'status': 'OK', 'payload': [1, 2]}

    def callback(agent, request):
        agent.event(unknown)
        agent.event(STABLE_EVENT)

    session, _ = peer({0: callback})
    session.request('session.ping')
    assert len(session.events) == 2, 'the unknown event must still be recorded'
    assert session.unknown_events and session.unknown_events[0]['event'] == 'kernel.something.new'
    assert session.unknown_events[0]['bytes'] > 0
    assert session.boot_binding is not None, 'the known event next to it is unaffected'

    # an EVENT in a session that did not negotiate event capture fails closed (ProtocolError),
    # it is not ignored: 'never a silent drop' holds in both directions
    refused, _ = peer({0: lambda agent, request: agent.event(unknown)}, accept_event=False)
    with pytest.raises(Exception) as excinfo:
        refused.request('session.ping', request_id='r-2')
    assert 'EVENT' in str(excinfo.value)
    assert refused.refused_events and refused.events == []


# ------------------------------------------------------------------ live order replay (10)

def test_live_order_replay_captures_boot_binding_event(peer, monkeypatch):
    """The W11.1 live order, replayed: RESPONSE(ping), RESPONSE(status), EVENT, RESPONSE, BYE.

    The event must be captured, survive the BYE, and land in the evidence -- the exact sequence
    the console performed live, where the plain BYE branch used to lose it.
    """
    def respond_only(agent, request):
        agent.respond(agent.rid(request))

    def final_status(agent, request):
        # the console reports the diagnostics, answers, and then stops itself, like live
        agent.send_many([('EVENT', DIAG_EVENT),
                         ('RESPONSE', {'header': {'in_reply_to': agent.rid(request)},
                                       'status': 'OK', 'body': {'result': {}}})])
        agent._sent_response = True

    def last_request(agent, request):
        agent.respond(agent.rid(request))
        agent.bye('BOOT_READ_FAILED')

    session, agent = peer({0: respond_only, 1: respond_only, 2: final_status, 3: last_request},
                          accept_event=True, trace=True, monkeypatch=monkeypatch)
    session.request('session.ping')
    session.request('session.status')
    session.request('session.status')          # the "final status" step carries the EVENT
    session.request('telemetry.read')          # the agent answers and then says BYE
    bye_obj = session.await_bye()

    assert bye_obj['reason'] == 'BOOT_READ_FAILED'
    assert session.boot_binding is not None, 'the live order replay lost the event'
    assert session.boot_binding['event'] == 'boot.binding'

    rec = _recorder('live-controller')
    report = cli.capture_events(rec, session, w11=True)
    assert rec.doc['boot_binding_event'] is not None
    assert report['verified'] is True and report['no_boot_id'] is True
    assert rec.doc['boot_binding_frame_sha256']
    assert rec.doc['event_capture']['events_recorded_before_bye'] == 1

    # instrumentation: the trace proves the routing (types, AEAD sequence, lengths, destination)
    trace = rec.doc['frame_trace']
    assert any(e.get('type') == 'EVENT' and e.get('destination') == 'event sink' for e in trace)
    assert any(e.get('type') == 'BYE' and e.get('destination') == 'session lifecycle' for e in trace)
    frames = [e for e in trace if e['kind'] == 'frame']
    assert frames and all('plaintext_bytes' in e and 'aead_sequence' in e and 'type' in e
                          for e in frames), 'every frame entry carries type, AEAD seq and length'
    routed = [e for e in trace if e['kind'] != 'frame']
    assert all('type' in e and 'sequence' in e for e in routed), \
        'every routed frame entry names its type and its routing destination'
    assert PSK.hex() not in json.dumps(trace), 'the trace must never carry key material'
    assert rec.doc['event_capture']['single_reader'] is True


def test_live_failure_branch_records_captured_event():
    """Guard: the live runner must call the shared capture helper in its agent-stop branch.

    This is the W11.1A root cause -- the live branch recorded a failed check and returned, while
    the offline branch copied the captured event into the evidence. Both paths now call the one
    shared helper, and this test keeps them from diverging again.
    """
    def fn_source(source: str, name: str) -> str:
        start = source.index(f'def {name}(')
        end = source.find('\ndef ', start + 1)
        return source[start:end if end != -1 else len(source)]

    source = (REPO / 'tools' / 'hostctl' / 'cli.py').read_text()
    # every runner routes its capture through the one shared helper ...
    for name in ('drive', 'mode_selftest', 'mode_live', 'mode_listen'):
        body = fn_source(source, name)
        assert 'capture_events(' in body or 'live_agent_stop_outcome(' in body, \
            f'{name}() must capture events through the shared helper'
    # ... and the shared live stop decision captures before it decides
    stop = fn_source(source, 'live_agent_stop_outcome')
    assert 'capture_events(' in stop, 'the shared live stop must capture events first'
    assert 'no_boot_id' in stop, 'the shared live stop must keep the W11.1 success criterion'
    # the pre-fix behaviour is nowhere left in the runner
    assert "rec.check('live session', False, str(exc))\n        result" not in source
