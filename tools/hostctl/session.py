"""Host side of a W8 session: frozen handshake, READY attestation, request/response loop.

All protocol primitives are the frozen core ones. The only W8 addition is the READY frame:
the wire specification reserved type 0x05 and states that it "receives active wire
semantics only once shape, encryption status, capability content and state transition are
fully specified". W8 specifies exactly that (see docs/P4-W8-LIVE-BRINGUP.md):

* shape ......... canonical JSON object (attestation, see below)
* encryption .... sealed with the agent-to-host channel, like every other frame after
                  AUTH_ACK; the first agent-to-host frame of the session
* content ....... agent identity + target facts + capability summary + negotiated limits
* transition .... the agent sends it exactly once, immediately after AUTH_ACK and before it
                  serves any REQUEST; the host requires it in W8 mode. The host's general
                  tolerance (a peer that never sends READY stays usable) is unchanged.

Nothing about the frozen direction rule is relaxed: REQUEST inbound and
RESPONSE/EVENT/BYE outbound are checked with ``wire.check_inbound`` unchanged; READY is
accepted as the documented W8 control frame and every other type is refused.
"""

from __future__ import annotations

import json
import os
import time

from core.canonical import canonical_bytes
from core.rpc import wire

#: W14 §14: the fields of the HELLO identity block that must be *identical* in every session of
#: one resident agent (agent lifetime + boot facts). The per-session fields (nonce) and the
#: boot-wide recovery state (which may be raised during a run, never lowered) are not in here.
IDENTITY_FIELDS = ('agent_version', 'build_id', 'platform', 'profile_id', 'boot_id', 'boot_sec',
                   'boot_usec', 'boot_status', 'context', 'label', 'provider', 'transport')
from core.rpc.handshake import (Direction, DirectionChannel, ProtocolError, derive_keys,
                                host_handshake, new_nonce, nonce_prefix, transcript_hash)
from core.session.states import SessionState

from .endpoint import EndpointClosed, SocketEndpoint

HOST_INBOUND_W8 = ('READY', 'RESPONSE', 'BYE')
# W9 adds exactly one documented agent-to-host control frame: the sealed EVENT carrying the
# kernel.attestation report. It is accepted only when a caller asks for it (accept_event).
HOST_INBOUND_W9 = ('READY', 'RESPONSE', 'EVENT', 'BYE')

# W11.1A: the registered event contracts. An event of a *known* type is validated before it is
# used; an event of an unknown type is still recorded as an authenticated opaque event (never
# dropped silently). A known type that fails validation is recorded as EVENT_SCHEMA_REJECTED
# with the reason, so the evidence can never simply show "null" without an explanation.
EVENT_KERNEL_ATTESTATION = 'kernel.attestation'
EVENT_BOOT_BINDING = 'boot.binding'
BOOT_BINDING_SCHEMA = 'ps4rf.boot.binding.diag.v1'
BOOT_BINDING_REQUIRED_FIELDS = ('msg', 'event', 'schema', 'status', 'source', 'run_status',
                                'methods', 'read1', 'read2', 'timeval_sizeof', 'plausible')
BOOT_BINDING_REQUIRED_METHODS = ('sysctlbyname', 'sysctl_mib')

# W11.2: the sealed event of the fixed privileged boot read. Same routing and the same fail-closed
# schema handling as every other event; the payload's body is what the host verifies.
EVENT_BOOT_BINDING_PRIVILEGED = 'boot.binding.privileged'
BOOT_BINDING_PRIVILEGED_SCHEMA = 'ps4rf.boot.binding.privileged.v1'
BOOT_BINDING_PRIVILEGED_REQUIRED_FIELDS = (
    'msg', 'event', 'schema', 'status', 'run_status', 'run_status_name', 'callback_executed',
    'cb_status', 'cb_status_name', 'kexec_rc', 'lstar', 'kbase_candidate', 'kbase_sdk',
    'cross_check', 'source_rva', 'read_length', 'raw_hex', 'tv_sec', 'tv_usec',
    'wall_clock_sec', 'validation', 'kernel_timeval_bytes', 'single_callback', 'retry',
    'writes_to_kernel', 'host_supplied_address', 'generic_read_primitive', 'boot_id_claim',
    'build_id', 'label')
# W12: the sealed event of one bounded kernel.read. The payload composes the address internally
# from the generated region table; the request carries region index, offset and length only. It
# gets the same routing and the same fail-closed handling as every other event, plus per-type
# validation: the exact schema, the fields ps4rf_kread_event always emits, their types, and the
# hex output must describe exactly the byte count the event claims (the W11.2 hex-encoder lesson,
# host side: a claimed length its own bytes cannot support is refused, never "roughly" accepted).
EVENT_KERNEL_READ_BOUNDED = 'kernel.read.bounded'
KERNEL_READ_BOUNDED_SCHEMA = 'ps4rf.kernel.read.bounded.v1'
KERNEL_READ_BOUNDED_REQUIRED_FIELDS = (
    'msg', 'event', 'schema', 'status', 'run_status', 'run_status_name', 'callback_executed',
    'cb_status', 'cb_status_name', 'kexec_rc', 'requested_region', 'requested_region_index',
    'region_identity', 'region_rva', 'requested_offset', 'requested_length', 'copied_len',
    'offset_length_sum', 'lstar', 'kbase_candidate', 'kbase_sdk', 'cross_check', 'resolved_rva',
    'resolved_runtime_va', 'bytes_hex', 'sha256', 'sha256_status', 'max_read_len',
    'region_count', 'single_callback', 'retry', 'writes_to_kernel', 'host_supplied_address',
    'generic_read_primitive', 'resolved_runtime_va_note', 'build_id', 'label', 'provider',
    'scope', 'profile_decision')
KERNEL_READ_BOUNDED_BOOL_FIELDS = ('callback_executed', 'single_callback', 'retry',
                                   'writes_to_kernel', 'host_supplied_address')
KERNEL_READ_BOUNDED_INT_FIELDS = ('run_status', 'cb_status', 'kexec_rc',
                                  'requested_region_index', 'copied_len', 'max_read_len',
                                  'region_count')
KERNEL_READ_BOUNDED_STRING_FIELDS = tuple(
    f for f in KERNEL_READ_BOUNDED_REQUIRED_FIELDS
    if f not in KERNEL_READ_BOUNDED_BOOL_FIELDS and f not in KERNEL_READ_BOUNDED_INT_FIELDS)
KNOWN_EVENT_TYPES = (EVENT_KERNEL_ATTESTATION, EVENT_BOOT_BINDING, EVENT_BOOT_BINDING_PRIVILEGED,
                     EVENT_KERNEL_READ_BOUNDED)

_HEX_CHARS = frozenset('0123456789abcdef')


def kernel_read_bounded_problems(body: dict) -> list[str]:
    """The exact reasons a kernel.read.bounded event fails its contract ([] when it passes).

    The required set is exactly the field list ``ps4rf_kread_event`` emits (the payload builds the
    object all-or-nothing); fields beyond it are tolerated. Types are checked where the payload has
    no freedom: booleans stay booleans (never 0/1), counted values stay integers, text stays text.
    The hex output must describe exactly the byte count the event claims -- a claimed length its
    own bytes cannot support is refused, never "roughly" accepted (the W11.2 lesson, host side).
    """
    problems: list[str] = []
    missing = [f for f in KERNEL_READ_BOUNDED_REQUIRED_FIELDS if f not in body]
    if missing:
        problems.append('missing required fields: ' + ', '.join(missing))
    if body.get('schema') != KERNEL_READ_BOUNDED_SCHEMA:
        problems.append(f"unexpected schema {body.get('schema')!r}")
    for field in KERNEL_READ_BOUNDED_BOOL_FIELDS:
        if field in body and not isinstance(body[field], bool):
            problems.append(f'{field} must be a boolean, got {type(body[field]).__name__}')
    for field in KERNEL_READ_BOUNDED_INT_FIELDS:
        if field in body and (isinstance(body[field], bool) or not isinstance(body[field], int)):
            problems.append(f'{field} must be an integer, got {type(body[field]).__name__}')
    for field in KERNEL_READ_BOUNDED_STRING_FIELDS:
        if field in body and not isinstance(body[field], str):
            problems.append(f'{field} must be a string, got {type(body[field]).__name__}')
    bytes_hex, sha256 = body.get('bytes_hex'), body.get('sha256')
    status, copied = body.get('sha256_status'), body.get('copied_len')
    for name, value in (('bytes_hex', bytes_hex), ('sha256', sha256)):
        if isinstance(value, str) and any(c not in _HEX_CHARS for c in value):
            problems.append(f'{name} must be a lowercase hex string')
    if isinstance(bytes_hex, str) and len(bytes_hex) % 2:
        problems.append('bytes_hex must be an even number of hex characters')
    if isinstance(status, str) and status not in ('MEASURED', 'NOT_MEASURED'):
        problems.append(f"sha256_status must be 'MEASURED' or 'NOT_MEASURED', got {status!r}")
    if status == 'MEASURED':
        if (isinstance(copied, int) and not isinstance(copied, bool) and isinstance(bytes_hex, str)
                and (copied < 1 or len(bytes_hex) != 2 * copied)):
            problems.append(f'bytes_hex has {len(bytes_hex) // 2} bytes, copied_len claims {copied}')
        if not (isinstance(sha256, str) and len(sha256) == 64):
            problems.append('sha256_status MEASURED requires the 64-character output digest')
    elif status == 'NOT_MEASURED' and (bytes_hex != '' or sha256 != ''):
        problems.append('bytes_hex and sha256 must be empty when sha256_status is NOT_MEASURED')
    return problems


class SessionError(Exception):
    """Any deviation from the frozen wire contract or the W8 sequence."""


class HostSession:
    def __init__(self, ep: SocketEndpoint, psk: bytes, *, session_id: str | None = None,
                 max_frame_bytes: int = 1048576, context: str = 'ps4rfctl/w8',
                 timeout: float = 30.0, accept_event: bool = False) -> None:
        if len(psk) != 32:
            raise SessionError('the pre-shared key must be 32 bytes')
        self.ep = ep
        self._psk = psk
        self._sid_override = session_id
        self._max = max_frame_bytes
        self._context = context
        self._timeout = timeout
        self._ch_h2a: DirectionChannel | None = None
        self._ch_a2h: DirectionChannel | None = None
        self.session_id: str | None = None
        self.ready: dict | None = None
        self.ready_raw: bytes | None = None
        self.transcript_hex: str | None = None
        self.hello_seen: dict | None = None
        self.bye: dict | None = None
        self.bye_raw: bytes | None = None
        # W9: a session may carry one sealed EVENT (the kernel.attestation report). It is
        # unsolicited, so it is recorded and skipped while waiting for a RESPONSE/BYE.
        self._accept_event = accept_event
        self.events: list[dict] = []
        self.events_raw: list[bytes] = []
        self.attestation: dict | None = None
        # W11: the sealed boot.binding report (raw KERN_BOOTTIME reads, measured this boot)
        self.boot_binding: dict | None = None
        self.boot_binding_privileged: dict | None = None
        # W12: the sealed kernel.read.bounded report (one bounded region read; evidence only)
        self.kernel_read_bounded: dict | None = None
        # W11.1A: event capture bookkeeping. Nothing is ever dropped silently: refused, unknown,
        # duplicated and schema-rejected events are all accounted for and exported to evidence.
        self.event_schema_rejected: list[dict] = []
        self.unknown_events: list[dict] = []
        self.duplicate_events: list[dict] = []
        self.refused_events: list[dict] = []
        self.events_before_bye: int | None = None
        self.frame_trace: list[dict] = []
        self.frame_trace_enabled = os.environ.get('PS4RF_FRAME_TRACE', '') not in ('', '0')
        self.counters = {'frames_received': 0, 'requests_sent': 0}
        self.timeline: list[dict] = []

    # ------------------------------------------------------------------ helpers
    def _now(self) -> float:
        return time.time()

    def _note(self, event: str, **fields) -> None:
        self.timeline.append({'t': self._now(), 'event': event, **fields})

    # --------------------------------------------------------------- handshake
    def build_hello_ack(self) -> dict:
        """HELLO_ACK with the pinned field set (native/src/ps4rfd_main.c); the values are
        host local. The session id is chosen by the host and binds every AAD."""
        nonce = new_nonce()
        session_id = self._sid_override or ('SES-' + nonce.hex())
        self.session_id = session_id
        return {
            'aead': 'AEAD_CHACHA20_POLY1305',
            'auth_required': True,
            'limits': {'max_chunk_bytes': 1048576, 'max_ir_bytes': 262144},
            'msg': 'HELLO_ACK',
            'nonce': nonce.hex(),
            'protocol_version': 1,
            'session_id': session_id,
        }

    def handshake(self) -> dict:
        ack = self.build_hello_ack()
        try:
            keys, hello = host_handshake(self.ep, self._psk, ack)
        except ProtocolError as exc:
            raise SessionError(f'handshake failed: {exc}') from exc
        self.hello_seen = hello
        # W14 §14/§4: the derived key material stays on the host side of this object so that a
        # caller can prove session isolation (different keys per session) without recomputing it.
        self.keys = keys
        self.transcript_hex = transcript_hash(hello, ack).hex()
        an = bytes.fromhex(hello['nonce'])
        hn = bytes.fromhex(ack['nonce'])
        th = bytes.fromhex(self.transcript_hex)
        # channels: same construction as the frozen parity fixtures
        self._ch_h2a = DirectionChannel(keys.k_host_to_agent,
                                        nonce_prefix(self._psk, an, hn, th, Direction.HOST_TO_AGENT),
                                        self.session_id, Direction.HOST_TO_AGENT,
                                        suite='AEAD_CHACHA20_POLY1305',
                                        max_frame_bytes=self._max, protocol_version=1)
        self._ch_a2h = DirectionChannel(keys.k_agent_to_host,
                                        nonce_prefix(self._psk, an, hn, th, Direction.AGENT_TO_HOST),
                                        self.session_id, Direction.AGENT_TO_HOST,
                                        suite='AEAD_CHACHA20_POLY1305',
                                        max_frame_bytes=self._max, protocol_version=1)
        self._note('handshake', session_id=self.session_id, transcript_sha256=self.transcript_hex,
                   agent_label=hello.get('label'), agent_version=hello.get('agent_version'),
                   provider=hello.get('provider'), transport=hello.get('transport'))
        return hello

    # ------------------------------------------------------------------- frames
    def _recv_frame(self) -> tuple[str, int, bytes, bytes]:
        assert self._ch_a2h is not None
        header = self.ep.recv_exact(wire.FRAME_HEADER_BYTES)
        mtype, seq, length = wire.parse_header(header, max_frame_bytes=self._max)
        body = self.ep.recv_exact(length)
        frame = header + body
        plaintext = self._ch_a2h.open(mtype, seq, body)
        self.counters['frames_received'] += 1
        self._trace('frame', 'router', type=mtype, aead_sequence=seq,
                    ciphertext_bytes=len(body), plaintext_bytes=len(plaintext))
        return mtype, seq, plaintext, frame

    @property
    def agent_identity(self) -> dict:
        """W14 §14: the identity block the agent announced in HELLO (empty for a pre-W14 agent).

        Everything in it is a fact of the agent lifetime or of the boot; nothing in it may differ
        between two sessions of the same resident agent.
        """
        hello = self.hello_seen or {}
        return {key: hello.get(key) for key in IDENTITY_FIELDS}

    def recv_ready(self) -> dict:
        """The first agent-to-host frame of a W8 session must be the READY attestation."""
        try:
            mtype, seq, plaintext, raw = self._recv_frame()
        except (ProtocolError, EndpointClosed) as exc:
            raise SessionError(f'no READY frame: {exc}') from exc
        if mtype != 'READY':
            raise SessionError(f'expected READY as the first agent frame, got {mtype!r}')
        if seq != 0:
            raise SessionError(f'READY must be the first agent-to-host frame (sequence 0), got {seq}')
        attestation = json.loads(plaintext)
        if not isinstance(attestation, dict) or attestation.get('msg') != 'READY':
            raise SessionError('READY body is not a READY attestation object')
        self.ready = attestation
        self.ready_raw = raw
        self._note('ready', sequence=seq, bytes=len(raw))
        return attestation

    def request(self, op: str, arguments: dict | None = None, *, request_id: str | None = None,
                seq: int | None = None) -> dict:
        if self._ch_h2a is None or self._ch_a2h is None:
            raise SessionError('session is not in ACTIVE state')
        rid = request_id or smoke_request_id(self.counters['requests_sent'])
        body: dict = {'operation': op, 'arguments': arguments or {}}
        if seq is not None:
            body['seq'] = seq
        message = {'header': {'request_id': rid}, 'body': body}
        frame = wire.encode_frame(self._ch_h2a, 'REQUEST', canonical_bytes(message))
        self.ep.send_all(frame)
        self.counters['requests_sent'] += 1
        self._note('request', request_id=rid, op=op, bytes=len(frame))
        while True:
            mtype, rseq, plaintext, raw = self._recv_frame()
            routed = self._route(mtype, rseq, plaintext, raw, rid=rid)
            if routed is None:                      # EVENT: recorded by the event sink
                continue
            if routed.get('bye'):
                raise SessionError(f'agent closed the session (BYE {self.bye.get("reason")}) '
                                   f'while waiting for the response to {op}')
            response = json.loads(routed['plaintext'])
            in_reply = (response.get('header') or {}).get('in_reply_to')
            if in_reply != rid:
                raise SessionError(f'response in_reply_to {in_reply!r} does not match {rid!r}')
            self._note('response', request_id=rid, op=op, status=response.get('status'),
                       in_reply_to=in_reply, sequence=rseq, bytes=len(raw))
            return response

    def _trace(self, kind: str, destination: str, **fields) -> None:
        """W11.1A diagnostics: frame-level trace, opt in with PS4RF_FRAME_TRACE=1. Carries
        message types, sequences, lengths, request ids and routing destinations -- never key
        material, never plaintext bodies."""
        if not self.frame_trace_enabled:
            return
        entry = {'kind': kind, 'destination': destination}
        entry.update(fields)
        self.frame_trace.append(entry)

    def _route(self, mtype: str, rseq: int, plaintext: bytes, raw: bytes,
               *, rid: str | None = None) -> dict | None:
        """The single inbound router. Exactly one reader exists per session (``_recv_frame``);
        every frame is decrypted, validated and then routed here by type:

        * EVENT  -> event sink (recorded for evidence, schema-checked, never dropped)
        * BYE    -> session lifecycle
        * RESPONSE -> request dispatcher (the caller compares ``in_reply_to``)

        Returns ``None`` when the frame was consumed by the sink/lifecycle, otherwise a dict with
        the response payload. An EVENT in a session that did not negotiate event capture fails
        closed with a ProtocolError instead of being ignored.
        """
        if mtype == 'EVENT':
            if not self._accept_event:
                self.refused_events.append({
                    'reason': 'EVENT in a session that did not negotiate event capture',
                    'sequence': rseq, 'bytes': len(raw)})
                self._trace('event', 'refused (accept_event=False)', sequence=rseq)
                wire.check_inbound(mtype, ('RESPONSE',))   # fails closed, never a silent drop
            self.record_event(mtype, rseq, plaintext, raw)
            self._trace('event', 'event sink', type=mtype, sequence=rseq, request_id=rid,
                        event_type=(json.loads(plaintext).get('event')
                                    if plaintext.strip().startswith(b'{') else None))
            return None
        if mtype == 'BYE':
            self.bye = json.loads(plaintext)
            self.bye_raw = raw
            # BYE never cuts the event queue: everything authenticated before it is already
            # recorded at this point (the reader processes frames strictly in order).
            self.events_before_bye = len(self.events)
            self._note('bye', sequence=rseq, reason=self.bye.get('reason'),
                       events_recorded=len(self.events))
            self._trace('bye', 'session lifecycle', type=mtype, sequence=rseq,
                        events_recorded=len(self.events))
            return {'bye': True}
        wire.check_inbound(mtype, ('RESPONSE',))
        self._trace('response', 'request dispatcher', type=mtype, sequence=rseq, request_id=rid)
        return {'sequence': rseq, 'plaintext': plaintext, 'raw': raw}

    def record_event(self, mtype: str, sequence: int, plaintext: bytes, raw: bytes) -> dict:
        """Records one sealed agent EVENT (W9: kernel.attestation, W11: boot.binding, W11.2:
        boot.binding.privileged, W12: kernel.read.bounded).

        Contract: an event is *always* stored raw. Known types are schema-checked; a failure is
        recorded as EVENT_SCHEMA_REJECTED with the reason (never silently "null"). Unknown types
        are recorded as opaque authenticated events. Duplicates are defined: every copy is kept,
        the last one wins for the typed accessor, and the duplicate is noted.
        """
        body = json.loads(plaintext)
        etype = body.get('event') if isinstance(body, dict) else None
        self.events.append(body)
        self.events_raw.append(raw)
        duplicated = False

        if etype == EVENT_KERNEL_ATTESTATION:
            if not isinstance(body, dict) or 'status' not in body:
                self.event_schema_rejected.append({
                    'event': etype, 'reason': 'kernel.attestation without a status field',
                    'sequence': sequence})
            else:
                self.attestation = body
        elif etype == EVENT_BOOT_BINDING:
            missing = [f for f in BOOT_BINDING_REQUIRED_FIELDS if f not in (body or {})]
            methods = (body or {}).get('methods')
            missing_methods = []
            if not isinstance(methods, dict):
                missing.append('methods{object}')
            else:
                missing_methods = [m for m in BOOT_BINDING_REQUIRED_METHODS if m not in methods]
            if body.get('schema') not in (BOOT_BINDING_SCHEMA,):
                self.event_schema_rejected.append({
                    'event': etype, 'reason': f"unexpected schema {body.get('schema')!r}",
                    'sequence': sequence})
            elif missing or missing_methods:
                self.event_schema_rejected.append({
                    'event': etype, 'reason': 'missing required fields',
                    'missing': missing, 'missing_methods': missing_methods, 'sequence': sequence})
            else:
                if self.boot_binding is not None:
                    duplicated = True
                    self.duplicate_events.append({
                        'event': etype, 'sequence': sequence,
                        'note': 'a previous boot.binding event was already recorded; the last one'
                                ' is used for the typed accessor and both stay in the evidence'})
                self.boot_binding = body
        elif etype == EVENT_BOOT_BINDING_PRIVILEGED:
            missing = [f for f in BOOT_BINDING_PRIVILEGED_REQUIRED_FIELDS if f not in (body or {})]
            if body.get('schema') not in (BOOT_BINDING_PRIVILEGED_SCHEMA,):
                self.event_schema_rejected.append({
                    'event': etype, 'reason': f"unexpected schema {body.get('schema')!r}",
                    'sequence': sequence})
            elif missing:
                self.event_schema_rejected.append({
                    'event': etype, 'reason': 'missing required fields', 'missing': missing,
                    'sequence': sequence})
            else:
                if self.boot_binding_privileged is not None:
                    duplicated = True
                    self.duplicate_events.append({
                        'event': etype, 'sequence': sequence,
                        'note': 'a previous boot.binding.privileged event was already recorded; '
                                'the last one is used for the typed accessor and both stay in the '
                                'evidence'})
                self.boot_binding_privileged = body
        elif etype == EVENT_KERNEL_READ_BOUNDED:
            problems = kernel_read_bounded_problems(body)
            if problems:
                self.event_schema_rejected.append({
                    'event': etype, 'reason': '; '.join(problems), 'problems': problems,
                    'sequence': sequence})
            else:
                if self.kernel_read_bounded is not None:
                    duplicated = True
                    self.duplicate_events.append({
                        'event': etype, 'sequence': sequence,
                        'note': 'a previous kernel.read.bounded event was already recorded; the '
                                'last one is used for the typed accessor and both stay in the '
                                'evidence'})
                self.kernel_read_bounded = body
        else:
            self.unknown_events.append({
                'event': etype, 'sequence': sequence, 'bytes': len(raw),
                'note': 'recorded as an opaque authenticated event: unknown types are never '
                        'dropped silently'})

        self._note('event', sequence=sequence, kind=etype,
                   status=body.get('status') if isinstance(body, dict) else None, bytes=len(raw),
                   schema_rejected=bool(self.event_schema_rejected), duplicate=duplicated)
        return body

    def event_capture_report(self) -> dict:
        """Compact, secret-free summary of what the single reader captured."""
        return {
            'capture_mode': 'central reader: RESPONSE -> dispatcher, EVENT -> sink, BYE -> lifecycle',
            'single_reader': True,
            'frames_received': self.counters['frames_received'],
            'events_seen': len(self.events),
            'event_types': [e.get('event') if isinstance(e, dict) else None for e in self.events],
            'boot_binding_captured': self.boot_binding is not None,
            'boot_binding_privileged_captured': self.boot_binding_privileged is not None,
            'kernel_read_bounded_captured': self.kernel_read_bounded is not None,
            'kernel_attestation_captured': self.attestation is not None,
            'schema_rejected': self.event_schema_rejected,
            'unknown_events': self.unknown_events,
            'duplicate_events': self.duplicate_events,
            'refused_events': self.refused_events,
            'events_recorded_before_bye': self.events_before_bye,
            'frame_trace_enabled': self.frame_trace_enabled,
        }

    def await_bye(self, timeout_note: str = 'close') -> dict | None:
        """After the last request the host closes; the agent's BYE is best effort."""
        while True:
            try:
                mtype, rseq, plaintext, raw = self._recv_frame()
            except (EndpointClosed, ProtocolError):
                self._note('bye_missing', note=timeout_note)
                return None
            routed = self._route(mtype, rseq, plaintext, raw)
            if routed is None:                      # EVENT: recorded by the event sink
                continue
            break                                   # BYE or unexpected frame: handled below
        if self.bye is None:
            self._note('bye_missing', note=f'got {mtype!r}')
            return None
        return self.bye

    def close(self) -> None:
        self.ep.close()

    @property
    def state(self) -> str:
        return SessionState.ACTIVE.value


def smoke_request_id(index: int) -> str:
    """Stable, reproducible request id: REQ-<sha256("ps4rf/w8/<index>")[:32]>.

    Reproducibility matters for the evidence pack: the same run script produces the same
    request ids byte for byte (the W7 trace determinism lesson)."""
    import hashlib
    digest = hashlib.sha256(f'ps4rf/w8/{index}'.encode()).hexdigest()
    return 'REQ-' + digest[:32]
