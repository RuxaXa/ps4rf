"""W12: the ``kernel.read.bounded`` payload event in the host session pipeline (offline).

The payload's one bounded ``kernel.read`` emits exactly one sealed EVENT (schema
``ps4rf.kernel.read.bounded.v1``). These are the W11.1A regression cases applied to the new event
type -- the contract the payload's live flow depends on:

* the event may arrive between responses, before an expected response, or immediately before BYE;
  in every order it must be captured and must not disturb the response pipeline or BYE handling,
* capture happens in frame order: ``events_raw`` keeps the raw frames exactly as they arrived,
* it is never dropped silently: a schema-invalid event is recorded as ``EVENT_SCHEMA_REJECTED``
  with the exact reason (never a bare ``null``), a duplicate is recorded with a duplicate note and
  every copy is kept, an unknown type stays an opaque authenticated event, and an EVENT in a
  session that did not negotiate capture fails closed,
* only one component reads/extracts it (the W11.1A single-reader invariant).

No sockets, no threads: the session is built from raw frames over an in-memory endpoint whose
byte-stream semantics match ``SocketEndpoint``; the scripted console seals its frames with the
real handshake keys and the real wire code. The fixture bytes are the pinned
``kernel.attest.image_elf`` expectation of the promoted profile (the first STRICT region the
frozen payload's trigger reads), so the valid event is the shape the console actually emits.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
from collections.abc import Callable

import pytest

from core.canonical import canonical_bytes
from core.rpc import wire
from core.rpc.handshake import (Direction, DirectionChannel, derive_keys, nonce_prefix, proof,
                                transcript_hash)

from tools.hostctl import session as session_mod
from tools.hostctl.endpoint import EndpointClosed
from tools.hostctl.session import (EVENT_KERNEL_READ_BOUNDED, KERNEL_READ_BOUNDED_BOOL_FIELDS,
                                   KERNEL_READ_BOUNDED_INT_FIELDS,
                                   KERNEL_READ_BOUNDED_REQUIRED_FIELDS,
                                   KERNEL_READ_BOUNDED_SCHEMA,
                                   KERNEL_READ_BOUNDED_STRING_FIELDS, KNOWN_EVENT_TYPES,
                                   HostSession, kernel_read_bounded_problems)

REPO = pathlib.Path(__file__).resolve().parents[1]
PSK = bytes(range(32))
ACK_NONCE = bytes.fromhex('00112233445566778899aabbccddeeff')
HELLO_NONCE = bytes.fromhex('ffeeddccbbaa99887766554433221100')
# the pinned profile expectation of kernel.attest.image_elf (16 bytes, STRICT_FINGERPRINT)
ELF16_HEX = '7f454c46020101090000000000000000'

READY = {'msg': 'READY', 'agent_version': 'scripted', 'label': 'scripted-peer',
         'transport': 'tcp', 'capabilities': {'operations': []}}
BYE_KREAD_FAILED = {'msg': 'BYE', 'reason': 'KERNEL_READ_FAILED', 'cleanup': 'COMPLETE',
                    'resources': []}


def _hello() -> dict:
    return {'aead': 'AEAD_CHACHA20_POLY1305', 'agent_version': 'scripted', 'label': 'scripted-peer',
            'msg': 'HELLO', 'nonce': HELLO_NONCE.hex(), 'protocol_version': 1,
            'provider': 'scripted-peer', 'transport': 'tcp'}


def _hs(obj: dict) -> bytes:
    """One length-prefixed handshake frame, exactly as core.rpc.handshake writes them."""
    data = canonical_bytes(obj)
    return len(data).to_bytes(4, 'big') + data


def kread_event(**changes) -> dict:
    """One ``kernel.read.bounded`` event as ``ps4rf_kread_event`` emits it for the live trigger.

    Values mirror the frozen payload's first-STRICT-region probe (``image_elf``, index 0, offset 0,
    16 bytes -- the pinned profile bytes); ``changes`` overrides a field or adds one.
    """
    raw = bytes.fromhex(ELF16_HEX)
    body = {
        'msg': 'EVENT', 'event': EVENT_KERNEL_READ_BOUNDED, 'schema': KERNEL_READ_BOUNDED_SCHEMA,
        'status': 'OK', 'run_status': 0, 'run_status_name': 'OK', 'callback_executed': True,
        'cb_status': 0, 'cb_status_name': 'OK', 'kexec_rc': 0,
        'requested_region': 'image_elf', 'requested_region_index': 0,
        'region_identity': 'STRICT_FINGERPRINT', 'region_rva': '0x0000000000000000',
        'requested_offset': '0', 'requested_length': '16', 'copied_len': len(raw),
        'offset_length_sum': '0x0000000000000010',
        'lstar': '0xffffffff898541c0', 'kbase_candidate': '0xffffffff89854000',
        'kbase_sdk': '0xffffffff89854000', 'cross_check': 'MATCH',
        'resolved_rva': '0x0000000000000000', 'resolved_runtime_va': '0xffffffff89854000',
        'bytes_hex': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest(),
        'sha256_status': 'MEASURED', 'max_read_len': 4096, 'region_count': 9,
        'single_callback': True, 'retry': False, 'writes_to_kernel': False,
        'host_supplied_address': False,
        'generic_read_primitive': 'NONE: one bounded region read per session; the host picks '
                                  'region index, offset and length, never an address',
        'resolved_runtime_va_note': 'the resolved address lives in this evidence only; the '
                                    'request carries no address and cannot contain one',
        'build_id': 'f' * 32, 'label': 'ps4rfd-live-w12',
        'provider': 'ps4rfd-kread-privileged',
        'scope': 'read-only; one bounded privileged callback per session; region table '
                 'compile-time; max 4096; no kernel write; no generic primitive',
        'profile_decision': 'PROFILE_UNBOUND',
    }
    body.update(changes)
    return body


def assert_no_silent_drop(session: HostSession) -> None:
    """The W11.1A invariant, restated per case: nothing that arrived vanishes without a record.

    Every EVENT frame the console sent is either in ``events``/``events_raw`` or explicitly
    accounted for (``event_schema_rejected`` / ``unknown_events`` / ``duplicate_events`` /
    ``refused_events``); a path that consumed a frame without recording it would break the
    raw-frame pairing asserted here.
    """
    assert len(session.events) == len(session.events_raw), 'an event lost its raw frame'
    for body, raw in zip(session.events, session.events_raw):
        assert raw, f'{body.get("event")!r} was recorded without its raw frame'
    report = session.event_capture_report()
    assert report['single_reader'] is True
    assert report['events_seen'] == len(session.events)


# ------------------------------------------------------------------- in-memory session rig

class FrameEndpoint:
    """Raw-frame endpoint: the exact ``SocketEndpoint`` I/O contract, no socket, no thread.

    The host reads from ``inbound`` (the scripted console's sealed frames, in order) and writes to
    ``outbound``; ``recv_exact`` fails exactly like ``SocketEndpoint`` when the peer has nothing
    more ready. Deterministic order is the point of this rig: ``[EVENT][BYE]`` really are adjacent.
    """

    def __init__(self) -> None:
        self.inbound = bytearray()
        self.outbound = bytearray()
        self.on_send: Callable[[], None] | None = None

    def send_all(self, data: bytes) -> None:
        self.outbound.extend(data)
        if self.on_send is not None:
            self.on_send()

    def recv_exact(self, n: int) -> bytes:
        if len(self.inbound) < n:
            raise EndpointClosed(f'no scripted frame bytes left ({len(self.inbound)} < {n})')
        chunk = bytes(self.inbound[:n])
        del self.inbound[:n]
        return chunk

    def close(self) -> None:
        pass


class Console:
    """Synchronous scripted console (agent side), same semantics as the W11.1A ``ScriptedAgent``.

    ``script`` maps a 0-based request index to a callback ``fn(console, request)``; a callback may
    send any sequence of EVENT/RESPONSE/BYE frames, and a plain OK response is appended
    automatically if it sent none (so the host never blocks by accident). The host's ``send_all``
    is the console's read side, so receiving a REQUEST and queueing the scripted answer is one
    synchronous step.
    """

    def __init__(self, ep: FrameEndpoint, session: HostSession, keys, th: bytes, script: dict) -> None:
        self.ep = ep
        self.script = script
        self.requests: list[dict] = []
        self.sealed: list[tuple[str, bytes]] = []   # every frame this console wrote, in order
        self._out = len(ep.outbound)                # skip the handshake bytes the host wrote
        self._sent_response = False
        self.ch_h2a = DirectionChannel(keys.k_host_to_agent,
                                       nonce_prefix(PSK, HELLO_NONCE, ACK_NONCE, th,
                                                    Direction.HOST_TO_AGENT),
                                       session.session_id, Direction.HOST_TO_AGENT,
                                       suite='AEAD_CHACHA20_POLY1305', protocol_version=1)
        self.ch_a2h = DirectionChannel(keys.k_agent_to_host,
                                       nonce_prefix(PSK, HELLO_NONCE, ACK_NONCE, th,
                                                    Direction.AGENT_TO_HOST),
                                       session.session_id, Direction.AGENT_TO_HOST,
                                       suite='AEAD_CHACHA20_POLY1305', protocol_version=1)
        ep.on_send = self.on_host_write

    @staticmethod
    def rid(request: dict) -> str:
        return request['header']['request_id']

    def on_host_write(self) -> None:
        """The console's read side: parse every complete REQUEST the host wrote, run its script."""
        while True:
            rest = bytes(self.ep.outbound[self._out:])
            if len(rest) < wire.FRAME_HEADER_BYTES:
                return
            mtype, seq, length = wire.parse_header(rest[:wire.FRAME_HEADER_BYTES])
            if len(rest) < wire.FRAME_HEADER_BYTES + length:
                return
            body = rest[wire.FRAME_HEADER_BYTES:wire.FRAME_HEADER_BYTES + length]
            self._out += wire.FRAME_HEADER_BYTES + length
            plaintext = self.ch_h2a.open(mtype, seq, body)
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

    def frames(self, items) -> bytes:
        """Seal several frames into one byte string, exact order (READY/EVENT are reserved)."""
        out = bytearray()
        for mtype, obj in items:
            raw = wire.encode_frame(self.ch_a2h, mtype, canonical_bytes(obj),
                                    allow_reserved=(mtype in ('READY', 'EVENT')))
            self.sealed.append((mtype, raw))
            out.extend(raw)
        return bytes(out)

    def send(self, mtype: str, obj: dict) -> None:
        self.ep.inbound += self.frames([(mtype, obj)])

    def send_many(self, items) -> None:
        """Deliver several frames as one contiguous write: [EVENT][BYE] really are adjacent."""
        self.ep.inbound += self.frames(items)

    def event(self, event: dict) -> None:
        self.send('EVENT', event)

    def respond(self, rid: str, status: str = 'OK', result: dict | None = None) -> None:
        self._sent_response = True
        self.send('RESPONSE', {'header': {'in_reply_to': rid}, 'status': status,
                               'body': {'result': result or {}}})

    def bye(self, reason: str = 'DONE') -> None:
        self.send('BYE', {'msg': 'BYE', 'reason': reason, 'cleanup': 'COMPLETE', 'resources': []})


@pytest.fixture
def make_session(monkeypatch):
    """A real HostSession driven by raw frames only (no socket, no thread, no network)."""
    opened: list[HostSession] = []

    def _make(script: dict | None = None, *, accept_event: bool = True, trace: bool = False):
        if trace:
            monkeypatch.setenv('PS4RF_FRAME_TRACE', '1')
        # deterministic handshake: pin the host nonce so the console's AUTH frame can be sealed
        # before host_handshake() runs (the key derivation itself stays the real one)
        monkeypatch.setattr(session_mod, 'new_nonce', lambda: ACK_NONCE)
        ep = FrameEndpoint()
        # FrameEndpoint implements exactly the endpoint I/O contract HostSession uses
        session = HostSession(ep, PSK, accept_event=accept_event)  # type: ignore[arg-type]
        ack = session.build_hello_ack()
        hello = _hello()
        th = transcript_hash(hello, ack)
        keys = derive_keys(PSK, HELLO_NONCE, ACK_NONCE, th)
        ep.inbound += _hs(hello) + _hs({'msg': 'AUTH',
                                        'mac': proof(keys.k_hs, 'agent', th).hex()})
        session.handshake()
        console = Console(ep, session, keys, th, script or {})
        ep.inbound += console.frames([('READY', READY)])
        session.recv_ready()
        opened.append(session)
        return session, console

    yield _make
    for session in opened:
        session.close()


def respond_then_event(event: dict):
    """A response with the event behind it: read with the *next* read."""
    def callback(console: Console, request: dict) -> None:
        console.respond(console.rid(request))
        console.event(event)
    return callback


def event_then_respond(event: dict):
    """The event is in flight *before* the awaited response."""
    def callback(console: Console, request: dict) -> None:
        console.event(event)
        console.respond(console.rid(request))
    return callback


# ------------------------------------------- ordering: between / before / immediately before BYE

def test_kernel_read_bounded_event_between_responses_captured(make_session):
    """EVENT between two RESPONSEs: buffered as unsolicited, recorded by the next read."""
    session, _ = make_session({1: respond_then_event(kread_event())})
    session.request('session.ping', request_id='r-0')
    session.request('session.status', request_id='r-1')       # response, then the event
    assert session.kernel_read_bounded is None, 'not read yet -- the event is unsolicited'
    session.request('session.status', request_id='r-2')       # reads the event first
    assert session.kernel_read_bounded is not None, 'the event between two responses was lost'
    assert session.kernel_read_bounded['event'] == EVENT_KERNEL_READ_BOUNDED
    assert len(session.events) == 1 and len(session.events_raw) == 1
    assert_no_silent_drop(session)


def test_kernel_read_bounded_event_before_expected_response_not_lost(make_session):
    """EVENT arriving before the awaited RESPONSE: the waiter must not consume or drop it."""
    session, console = make_session({1: event_then_respond(kread_event())})
    session.request('session.ping', request_id='r-0')
    response = session.request('session.status', request_id='r-1')
    assert response['status'] == 'OK', 'the waiter must return the RESPONSE, not the EVENT'
    assert response['header']['in_reply_to'] == 'r-1'
    assert session.kernel_read_bounded is not None, 'the event before the response was dropped'
    # READY + RESPONSE(ping) + EVENT + RESPONSE(status): the event was read *and* the response
    assert session.counters['frames_received'] == 4
    assert [r['header']['request_id'] for r in console.requests] == ['r-0', 'r-1']
    assert_no_silent_drop(session)


def test_kernel_read_bounded_event_immediately_before_bye_captured(make_session):
    """[EVENT][BYE] in one write: the event queue is not cut by the BYE, order is kept."""
    def callback(console: Console, request: dict) -> None:
        console.respond(console.rid(request))
        console.send_many([('EVENT', kread_event()), ('BYE', BYE_KREAD_FAILED)])

    session, console = make_session({0: callback})
    response = session.request('session.ping', request_id='r-0')
    assert response['status'] == 'OK'
    bye = session.await_bye()
    assert bye is not None and bye['reason'] == 'KERNEL_READ_FAILED'
    assert session.kernel_read_bounded is not None, 'the event immediately before the BYE was lost'
    assert session.events_before_bye == 1, 'the BYE must not cut the event queue'
    # frame order: the raw frames are the exact bytes the console sealed, in arrival order
    assert session.events_raw == [raw for mtype, raw in console.sealed if mtype == 'EVENT']
    assert_no_silent_drop(session)


def test_kernel_read_bounded_routes_to_the_sink_before_the_bye(make_session):
    """Trace-level proof of the order: EVENT -> sink strictly before BYE -> lifecycle."""
    def callback(console: Console, request: dict) -> None:
        console.respond(console.rid(request))
        console.send_many([('EVENT', kread_event(label='before-bye')), ('BYE', BYE_KREAD_FAILED)])

    session, _ = make_session({0: callback}, trace=True)
    session.request('session.ping', request_id='r-0')
    session.await_bye()
    routed = [(e['type'], e['destination']) for e in session.frame_trace if e['kind'] != 'frame']
    assert ('EVENT', 'event sink') in routed and ('BYE', 'session lifecycle') in routed
    assert routed.index(('EVENT', 'event sink')) < routed.index(('BYE', 'session lifecycle')), \
        'the EVENT must be recorded before the BYE is processed'
    frames = [e for e in session.frame_trace if e['kind'] == 'frame']
    assert [e['type'] for e in frames] == ['READY', 'RESPONSE', 'EVENT', 'BYE']
    assert PSK.hex() not in json.dumps(session.frame_trace), 'the trace must never carry keys'
    assert_no_silent_drop(session)


# --------------------------------------------------------------------- duplicate semantics

def test_kernel_read_bounded_duplicate_recorded_with_note_first_kept(make_session):
    """Two kernel.read.bounded events: both copies stay, the second is noted as a duplicate."""
    first = kread_event(label='first')
    second = kread_event(label='second')

    def callback(console: Console, request: dict) -> None:
        console.event(first)
        console.event(second)

    session, _ = make_session({0: callback})
    session.request('session.ping', request_id='r-0')
    assert len(session.events) == 2 and len(session.events_raw) == 2
    assert session.events[0] == first, 'the first recorded copy must not be overwritten'
    assert session.events[1] == second
    assert len(session.duplicate_events) == 1, 'a second event must be recorded as a duplicate'
    entry = session.duplicate_events[0]
    assert entry['event'] == EVENT_KERNEL_READ_BOUNDED and 'already recorded' in entry['note']
    # mirrored duplicate semantics (W11.1A): all copies kept, the last one is the typed accessor
    assert session.kernel_read_bounded == second
    assert_no_silent_drop(session)


# --------------------------------------------------------- schema handling: malformed variants

def _without(field: str) -> dict:
    body = kread_event()
    del body[field]
    return body


#: malformed variant -> the exact reason the host must record as EVENT_SCHEMA_REJECTED
MALFORMED = {
    'wrong-schema': (dict(kread_event(), schema='ps4rf.kernel.read.bounded.v0'),
                     "unexpected schema 'ps4rf.kernel.read.bounded.v0'"),
    'missing-field': (_without('copied_len'), 'missing required fields: copied_len'),
    'bool-as-int': (dict(kread_event(), callback_executed=1),
                    'callback_executed must be a boolean, got int'),
    'int-as-string': (dict(kread_event(), copied_len='16'),
                      'copied_len must be an integer, got str'),
    'string-as-int': (dict(kread_event(), status=0), 'status must be a string, got int'),
    'hex-shorter-than-claimed': (dict(kread_event(), bytes_hex=ELF16_HEX[:16]),
                                 'bytes_hex has 8 bytes, copied_len claims 16'),
    'measured-without-bytes': (dict(kread_event(), bytes_hex=''),
                               'bytes_hex has 0 bytes, copied_len claims 16'),
    'measured-without-digest': (dict(kread_event(), sha256=''),
                                'sha256_status MEASURED requires the 64-character output digest'),
}


@pytest.mark.parametrize('name', sorted(MALFORMED))
def test_kernel_read_bounded_malformed_variant_recorded_with_exact_reason(make_session, name):
    """Every malformed variant is kept raw and named as EVENT_SCHEMA_REJECTED, never dropped."""
    event, reason = MALFORMED[name]
    session, _ = make_session({0: lambda console, request: console.event(event)})
    session.request('session.ping', request_id='r-0')
    assert session.kernel_read_bounded is None, 'a malformed event must never become the capture'
    assert len(session.events) == 1, 'the malformed event is still recorded raw'
    assert session.events_raw[0]
    assert len(session.event_schema_rejected) == 1
    entry = session.event_schema_rejected[0]
    assert entry['event'] == EVENT_KERNEL_READ_BOUNDED
    assert entry['reason'] == reason
    assert entry['problems'] == [reason]
    assert_no_silent_drop(session)


def test_kernel_read_bounded_malformed_does_not_clear_a_captured_event(make_session):
    """A bad event after a good one: the good capture stays, the bad one is rejected."""
    good = kread_event()
    bad = dict(kread_event(), schema='nope')

    def callback(console: Console, request: dict) -> None:
        console.event(good)
        console.event(bad)

    session, _ = make_session({0: callback})
    session.request('session.ping', request_id='r-0')
    assert session.kernel_read_bounded == good, 'a later malformed event must not null the capture'
    assert len(session.event_schema_rejected) == 1
    assert session.duplicate_events == [], 'a malformed copy is a rejection, not a duplicate'
    assert_no_silent_drop(session)


def test_kernel_read_bounded_refusal_event_is_a_valid_capture(make_session):
    """A refused read (no bytes copied) is a well-formed event, not a schema failure.

    The payload emits this shape when the request/callback refused before copying anything
    (``NOT_RUN``, zero copied bytes, no digest); the host must capture it as the read result,
    not lock it out with the hex/length rule meant for measured output.
    """
    refusal = kread_event(
        status='FAILED', run_status=5, run_status_name='REQUEST_REFUSED',
        callback_executed=False, cb_status=255, cb_status_name='NOT_RUN',
        region_rva='UNMEASURED', offset_length_sum='UNMEASURED',
        resolved_rva='UNMEASURED', resolved_runtime_va='UNMEASURED', cross_check='UNMEASURED',
        copied_len=0, bytes_hex='', sha256='', sha256_status='NOT_MEASURED')
    session, _ = make_session({0: lambda console, request: console.event(refusal)})
    session.request('session.ping', request_id='r-0')
    assert session.kernel_read_bounded == refusal, 'a refusal event must still be the capture'
    assert session.event_schema_rejected == []
    assert_no_silent_drop(session)


# ------------------------------------------------ unknown types, capture negotiation, mixed burst

def test_unknown_event_type_still_recorded_beside_the_new_type(make_session):
    """Unknown event types stay opaque authenticated events -- never a silent drop."""
    unknown = {'msg': 'EVENT', 'event': 'kernel.something.new', 'status': 'OK', 'payload': [1, 2]}

    def callback(console: Console, request: dict) -> None:
        console.event(unknown)
        console.event(kread_event())

    session, _ = make_session({0: callback})
    session.request('session.ping', request_id='r-0')
    assert len(session.events) == 2, 'the unknown event must still be recorded'
    assert session.unknown_events and session.unknown_events[0]['event'] == 'kernel.something.new'
    assert session.unknown_events[0]['bytes'] > 0
    assert session.kernel_read_bounded is not None, 'the known event next to it is unaffected'
    assert_no_silent_drop(session)


def test_event_without_capture_negotiation_fails_closed(make_session):
    """An EVENT in a session that did not negotiate capture is refused, not ignored."""
    session, _ = make_session({0: lambda console, request: console.event(kread_event())},
                              accept_event=False)
    with pytest.raises(Exception) as excinfo:
        session.request('session.ping', request_id='r-0')
    assert 'EVENT' in str(excinfo.value)
    assert session.refused_events and session.events == [], 'fails closed, never a silent drop'


def test_no_event_is_silently_dropped_in_a_mixed_burst(make_session):
    """One session, four events (valid, duplicate, malformed, unknown): all four accounted for."""
    good = kread_event()
    duplicate = kread_event(label='second')
    malformed = dict(kread_event(), bytes_hex='00')
    unknown = {'msg': 'EVENT', 'event': 'kernel.something.else', 'status': 'OK'}

    def callback(console: Console, request: dict) -> None:
        for body in (good, duplicate, malformed, unknown):
            console.event(body)

    session, console = make_session({0: callback})
    session.request('session.ping', request_id='r-0')
    assert len(session.events) == 4 and len(session.events_raw) == 4
    assert session.events_raw == [raw for mtype, raw in console.sealed if mtype == 'EVENT']
    assert session.kernel_read_bounded == duplicate, 'the valid capture is unaffected'
    assert len(session.event_schema_rejected) == 1
    assert len(session.duplicate_events) == 1
    assert len(session.unknown_events) == 1
    report = session.event_capture_report()
    assert report['kernel_read_bounded_captured'] is True
    assert report['events_seen'] == 4
    assert report['schema_rejected'] and report['duplicate_events'] and report['unknown_events']
    assert_no_silent_drop(session)


# ------------------------------------------------------------------- single reader invariant

def test_single_reader_extracts_the_new_event_once(make_session, monkeypatch):
    """Every EVENT goes to the sink, once, whichever request is being awaited."""
    calls = []
    original = HostSession.record_event

    def counting(self, mtype, sequence, plaintext, raw):
        calls.append(json.loads(plaintext).get('event'))
        return original(self, mtype, sequence, plaintext, raw)

    monkeypatch.setattr(HostSession, 'record_event', counting)
    session, _ = make_session({0: lambda console, request: console.event(kread_event()),
                               1: lambda console, request: console.event(kread_event(label='b')),
                               })
    session.request('session.ping', request_id='r-0')
    session.request('session.ping', request_id='r-1')
    assert calls == [EVENT_KERNEL_READ_BOUNDED, EVENT_KERNEL_READ_BOUNDED], \
        'an event was consumed by a wait loop instead of the one sink'
    assert len(session.events) == 2 and session.kernel_read_bounded is not None
    assert_no_silent_drop(session)


def test_single_reader_source_invariant_for_the_new_event():
    """W11.1A single-reader invariant, asserted for the new event type at source level.

    One frame reader, one router, one event sink; the typed accessor is extracted in exactly one
    place (``record_event``) and no other hostctl module assigns it.
    """
    source = (REPO / 'tools' / 'hostctl' / 'session.py').read_text()
    assert source.count('def _recv_frame') == 1
    assert source.count('self.ep.recv_exact(') == 2, 'the frame reader must be the only reader'
    assert source.count('self._route(') == 2, \
        'request() and await_bye() must both route through the one router'
    assert source.count('.kernel_read_bounded = ') == 1, 'one extraction site, in the sink only'
    start = source.index('def record_event(')
    end = source.index('\n    def ', start + 1)
    sink = source[start:end]
    assert 'self.kernel_read_bounded = body' in sink, 'the extraction must live in the one sink'
    # no other hostctl module owns a frame reader or an event sink: a consumer may read the typed
    # accessor, but only the session itself may extract an event from the wire
    owners = [p.name for p in (REPO / 'tools' / 'hostctl').glob('*.py')
              if re.search(r'def (?:record_event|_recv_frame)\b', p.read_text())]
    assert owners == ['session.py'], f'foreign event readers/sinks: {owners}'


# --------------------------------------------------------------- contract pins (constants, C)

def test_kernel_read_bounded_is_a_registered_known_event_type():
    assert EVENT_KERNEL_READ_BOUNDED == 'kernel.read.bounded'
    assert KERNEL_READ_BOUNDED_SCHEMA == 'ps4rf.kernel.read.bounded.v1'
    assert EVENT_KERNEL_READ_BOUNDED in KNOWN_EVENT_TYPES
    assert kernel_read_bounded_problems(kread_event()) == [], 'the real event shape must pass'


def test_required_field_types_partition_the_required_fields():
    bools = set(KERNEL_READ_BOUNDED_BOOL_FIELDS)
    ints = set(KERNEL_READ_BOUNDED_INT_FIELDS)
    strings = set(KERNEL_READ_BOUNDED_STRING_FIELDS)
    assert bools | ints | strings == set(KERNEL_READ_BOUNDED_REQUIRED_FIELDS)
    assert not (bools & ints) and not (bools & strings) and not (ints & strings)


def test_required_fields_are_exactly_what_the_payload_emits():
    """The C file is the authoritative field list: pin the session contract to it.

    ``ps4rf_kread_event`` builds the object all-or-nothing (a failing set frees the event), so
    every key it sets is always emitted -- the host may require all of them and must tolerate no
    less. If the frozen payload ever gains a field, this pin fails first.
    """
    source = (REPO / 'native' / 'target' / 'ps4rf_kread.c').read_text()
    body = source[source.index('jval *ps4rf_kread_event('):source.index('return event;')]
    emitted = re.findall(r'jval_obj_set\(event,\s*"([^"]+)"', body)
    assert len(emitted) == len(set(emitted)) == len(KERNEL_READ_BOUNDED_REQUIRED_FIELDS)
    assert set(emitted) == set(KERNEL_READ_BOUNDED_REQUIRED_FIELDS)
    assert '"ps4rf.kernel.read.bounded.v1"' in source
    assert '"kernel.read.bounded"' in source
