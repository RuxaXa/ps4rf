"""Wire framing v1 tests (W0 decisions D8/D9/D12/D13, Core/Wire Revision R1).

Pins the shared frame-type table, the 13-byte header layout, the reserved-type
policy and the two R1 behaviour changes: the effective sequence ceiling
(``EFFECTIVE_LAST_SEQ``) and the mapping of AEAD failures to
``AuthenticationFailed`` (no library exception escapes the RPC layer).

Run from the repo root:

    .venv/bin/python -m pytest -q tests/test_wire_frames.py
"""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from core.rpc.handshake import (EFFECTIVE_LAST_SEQ, AuthenticationFailed, Direction,
                                DirectionChannel, FrameLimitExceeded, ProtocolError,
                                ReplayDetected, SequenceExhausted)
from core.rpc.wire import (AGENT_INBOUND, FRAME_HEADER_BYTES, FRAME_TYPE_BYTES,
                           FRAME_TYPE_NAMES, HOST_INBOUND, RESERVED_FRAME_TYPES,
                           WIRE_SPEC_VERSION, ReservedFrameType, UnknownFrameType,
                           build_header, check_inbound, decode_frame, encode_frame,
                           parse_header, type_byte)

SESSION_ID = 'SES-0123456789ABCDEF'
KEY = bytes(range(32))
PREFIX = b'abcd'


def channel(direction: Direction = Direction.AGENT_TO_HOST, *, max_frame_bytes: int = 1048576,
            prefix: bytes = PREFIX) -> DirectionChannel:
    return DirectionChannel(KEY, prefix, SESSION_ID, direction,
                            suite='AEAD_CHACHA20_POLY1305',
                            max_frame_bytes=max_frame_bytes, protocol_version=1)


# --------------------------------------------------------------- table contracts
def test_wire_mapping_v1_is_pinned():
    assert WIRE_SPEC_VERSION == 1
    assert FRAME_TYPE_NAMES == {0x01: 'REQUEST', 0x02: 'RESPONSE', 0x03: 'EVENT',
                                0x04: 'BYE', 0x05: 'READY'}
    assert FRAME_TYPE_BYTES == {name: value for value, name in FRAME_TYPE_NAMES.items()}
    assert RESERVED_FRAME_TYPES == frozenset({'EVENT', 'READY'})
    assert AGENT_INBOUND == frozenset({'REQUEST'})
    assert HOST_INBOUND == frozenset({'RESPONSE', 'EVENT', 'BYE'})
    assert FRAME_HEADER_BYTES == 13


def test_type_byte_encoding_and_reserved_policy():
    assert type_byte('REQUEST') == 0x01
    assert type_byte('RESPONSE') == 0x02
    assert type_byte('BYE') == 0x04
    with pytest.raises(ReservedFrameType):
        type_byte('EVENT')
    with pytest.raises(ReservedFrameType):
        type_byte('READY')
    assert type_byte('READY', allow_reserved=True) == 0x05
    with pytest.raises(UnknownFrameType):
        type_byte('HELLO')  # handshake type, never a frame type


def test_header_layout_is_big_endian_and_thirteen_bytes():
    sequence = 0x000A0B0C0D0E0F10  # within EFFECTIVE_LAST_SEQ, distinctive byte order
    header = build_header(16, 'RESPONSE', sequence)
    assert len(header) == FRAME_HEADER_BYTES
    assert header == bytes.fromhex('00000010') + b'\x02' + bytes.fromhex('000a0b0c0d0e0f10')
    mtype, parsed_sequence, length = parse_header(header)
    assert (mtype, parsed_sequence, length) == ('RESPONSE', sequence, 16)


def test_unknown_type_byte_fails_closed():
    for bad in (0x00, 0x06, 0x7F, 0xFF):
        header = b'\x00\x00\x00\x10' + bytes([bad]) + (0).to_bytes(8, 'big')
        with pytest.raises(UnknownFrameType):
            parse_header(header)
        assert issubclass(UnknownFrameType, ProtocolError)
    with pytest.raises(ProtocolError):
        parse_header(b'\x00' * 12)


# --------------------------------------------------------------- frame round trip
def test_encode_decode_round_trip_uses_the_shared_table():
    sender = channel(Direction.AGENT_TO_HOST)
    receiver = channel(Direction.AGENT_TO_HOST)
    frame = encode_frame(sender, 'RESPONSE', b'{"status":"OK"}')
    assert len(frame) == FRAME_HEADER_BYTES + len(b'{"status":"OK"}') + 16
    mtype, sequence, plaintext = decode_frame(receiver, frame)
    assert (mtype, sequence, plaintext) == ('RESPONSE', 0, b'{"status":"OK"}')


def test_reserved_types_cannot_be_sent_but_can_be_received():
    sender = channel()
    with pytest.raises(ReservedFrameType):
        encode_frame(sender, 'EVENT', b'reserved')
    with pytest.raises(ReservedFrameType):
        encode_frame(sender, 'READY', b'reserved')
    raw = encode_frame(sender, 'READY', b'reserved', allow_reserved=True)
    assert parse_header(raw[:FRAME_HEADER_BYTES])[0] == 'READY'


def test_length_and_limit_checks_fail_closed():
    small = channel(max_frame_bytes=64)
    with pytest.raises(FrameLimitExceeded):
        parse_header(build_header(65, 'RESPONSE', 0), max_frame_bytes=64)
    sender = channel(max_frame_bytes=64)
    with pytest.raises(FrameLimitExceeded):
        encode_frame(sender, 'RESPONSE', b'x' * 64)  # 64 + tag > max
    frame = encode_frame(channel(), 'RESPONSE', b'payload')
    with pytest.raises(ProtocolError):
        decode_frame(channel(), frame[:-1])  # length mismatch


def test_direction_fsm_check():
    check_inbound('REQUEST', AGENT_INBOUND)
    check_inbound('RESPONSE', HOST_INBOUND)
    with pytest.raises(ProtocolError):
        check_inbound('RESPONSE', AGENT_INBOUND)
    with pytest.raises(ProtocolError):
        check_inbound('REQUEST', HOST_INBOUND)


# ------------------------------------------------------- D9: no library exception
def test_aead_failure_maps_to_authentication_failed():
    sender = channel()
    frame = bytearray(encode_frame(sender, 'RESPONSE', b'payload'))
    frame[-1] ^= 0x01  # tag tamper
    with pytest.raises(AuthenticationFailed) as excinfo:
        decode_frame(channel(), bytes(frame))
    assert isinstance(excinfo.value, ProtocolError)
    assert not isinstance(excinfo.value, InvalidTag)


def test_wrong_message_type_maps_to_authentication_failed():
    sender = channel()
    frame = encode_frame(sender, 'RESPONSE', b'payload')
    # header says EVENT (reserved but valid byte), AAD was bound to RESPONSE
    forged = bytearray(frame)
    forged[4] = FRAME_TYPE_BYTES['EVENT']
    with pytest.raises(AuthenticationFailed):
        decode_frame(channel(), bytes(forged))


def test_open_never_leaks_the_library_exception():
    sender = channel()
    _seq, ciphertext = sender.seal('RESPONSE', b'x')
    receiver = channel()
    with pytest.raises(ProtocolError):
        receiver.open('RESPONSE', 0, ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF]))
    try:
        channel().open('RESPONSE', 0, b'\x00' * 32)
    except Exception as exc:  # noqa: BLE001 - the contract is "not InvalidTag"
        assert not isinstance(exc, InvalidTag)
        assert isinstance(exc, ProtocolError)


# ---------------------------------------------------------- D8: effective ceiling
def test_sequence_ceiling_is_effective_last_seq():
    assert EFFECTIVE_LAST_SEQ == 2 ** 53 - 1
    at_ceiling = channel()
    at_ceiling._send = EFFECTIVE_LAST_SEQ
    at_ceiling.seal('RESPONSE', b'last valid')
    assert at_ceiling._send == EFFECTIVE_LAST_SEQ + 1
    with pytest.raises(SequenceExhausted):
        at_ceiling.seal('RESPONSE', b'no wraparound')
    with pytest.raises(SequenceExhausted):
        build_header(1, 'RESPONSE', EFFECTIVE_LAST_SEQ + 1)
    header = b'\x00\x00\x00\x01' + b'\x02' + (EFFECTIVE_LAST_SEQ + 1).to_bytes(8, 'big')
    with pytest.raises(SequenceExhausted):
        parse_header(header)


def test_receive_ceiling_and_replay_still_ordered():
    sender = channel()
    sender._send = EFFECTIVE_LAST_SEQ
    seq, ct = sender.seal('RESPONSE', b'x')
    assert seq == EFFECTIVE_LAST_SEQ
    receiver = channel()
    receiver._recv = EFFECTIVE_LAST_SEQ
    assert receiver.open('RESPONSE', EFFECTIVE_LAST_SEQ, ct) == b'x'
    with pytest.raises(SequenceExhausted):
        receiver.open('RESPONSE', EFFECTIVE_LAST_SEQ + 1, ct)
    fresh = channel()
    with pytest.raises(ReplayDetected):
        fresh.open('RESPONSE', 5, ct)
