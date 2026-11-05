"""PS4RF wire framing v1 -- the single shared frame-type table (W0 decisions D12/D13).

Frame layout (post-handshake, both directions)::

    4-byte big-endian ciphertext length | 1 type byte | 8-byte big-endian sequence | ciphertext

The type table below is **normative** for the PS4RF wire specification v1 and is
the only place where message types are mapped to bytes. Every implementation --
host core, mock and the future native agent -- must use this same table
(``FRAME_TYPE_NAMES`` / ``FRAME_TYPE_BYTES``); no other byte values exist:

* ``0x01`` REQUEST, ``0x02`` RESPONSE, ``0x03`` EVENT, ``0x04`` BYE, ``0x05`` READY.
* Any other value is a ``UnknownFrameType`` (a ``ProtocolError``): the session
  fails closed, no reply attempt.
* ``EVENT`` and ``READY`` are **reserved**: v0.1 does not send them (no body is
  defined for ``EVENT``; ``READY`` gets wire semantics only once shape,
  encryption status, capability content and state transition are specified).
  Sending a reserved type raises ``ReservedFrameType`` (fail closed); receiving
  one is handled by the session FSM, which may tolerate ``READY`` for mock
  compatibility (D13).

Sequence: the AAD carries the sequence as a JCS integer, so the effective
ceiling is ``EFFECTIVE_LAST_SEQ`` (2**53 - 1, D8). A sequence beyond it fails
closed with ``SequenceExhausted`` -- never wraps around.

Direction rule (spec F16): the agent accepts ``REQUEST`` only and emits
``RESPONSE``/``EVENT``/``BYE``; the host accepts ``RESPONSE``/``EVENT``/``BYE``
only and emits ``REQUEST``. ``check_inbound`` enforces it before any decryption.
"""

from __future__ import annotations

from typing import Iterable

from core.rpc.handshake import (EFFECTIVE_LAST_SEQ, DirectionChannel,
                                FrameLimitExceeded, ProtocolError,
                                SequenceExhausted)

WIRE_SPEC_VERSION = 1
FRAME_HEADER_BYTES = 13
MAX_FRAME_BYTES_DEFAULT = 1048576

FRAME_TYPE_NAMES = {
    0x01: 'REQUEST',
    0x02: 'RESPONSE',
    0x03: 'EVENT',
    0x04: 'BYE',
    0x05: 'READY',
}

FRAME_TYPE_BYTES = {
    name: value
    for value, name in FRAME_TYPE_NAMES.items()
}

#: Reserved for later wire semantics; never sent in v0.1, not part of W2 byte parity.
RESERVED_FRAME_TYPES = frozenset({'EVENT', 'READY'})

#: Spec F16 direction FSM.
AGENT_INBOUND = frozenset({'REQUEST'})
HOST_INBOUND = frozenset({'RESPONSE', 'EVENT', 'BYE'})


class UnknownFrameType(ProtocolError):
    """A type byte outside the wire mapping v1 table (fail closed)."""


class ReservedFrameType(ProtocolError):
    """An attempt to send a reserved message type (EVENT/READY)."""


def type_byte(message_type: str, *, allow_reserved: bool = False) -> int:
    """Encode a message type name; unknown/reserved types fail closed."""
    if message_type not in FRAME_TYPE_BYTES:
        raise UnknownFrameType(f'unknown message type {message_type!r}')
    if message_type in RESERVED_FRAME_TYPES and not allow_reserved:
        raise ReservedFrameType(
            f'{message_type} is reserved in wire spec v{WIRE_SPEC_VERSION} '
            f'and must not be sent')
    return FRAME_TYPE_BYTES[message_type]


def build_header(ciphertext_len: int, message_type: str, sequence: int,
                 *, allow_reserved: bool = False) -> bytes:
    """13-byte frame header for one frame (length, type, sequence)."""
    if ciphertext_len < 0:
        raise ProtocolError('negative frame length')
    if sequence < 0 or sequence > EFFECTIVE_LAST_SEQ:
        raise SequenceExhausted()
    return (ciphertext_len.to_bytes(4, 'big') + bytes([type_byte(message_type, allow_reserved=allow_reserved)])
            + sequence.to_bytes(8, 'big'))


def parse_header(raw: bytes, *, max_frame_bytes: int = MAX_FRAME_BYTES_DEFAULT) -> tuple[str, int, int]:
    """Parse and validate a 13-byte header; returns ``(message_type, sequence, length)``.

    Length is checked *before* any allocation happens (spec R8) and the type byte
    must be part of the wire mapping v1 table -- otherwise fail closed.
    """
    if len(raw) != FRAME_HEADER_BYTES:
        raise ProtocolError(f'frame header must be {FRAME_HEADER_BYTES} bytes, got {len(raw)}')
    length = int.from_bytes(raw[0:4], 'big')
    type_value = raw[4]
    sequence = int.from_bytes(raw[5:13], 'big')
    if type_value not in FRAME_TYPE_NAMES:
        raise UnknownFrameType(f'unknown frame type byte 0x{type_value:02x}')
    if length > max_frame_bytes:
        raise FrameLimitExceeded()
    if sequence > EFFECTIVE_LAST_SEQ:
        raise SequenceExhausted()
    return FRAME_TYPE_NAMES[type_value], sequence, length


def check_inbound(message_type: str, allowed: Iterable[str]) -> None:
    """Direction FSM check (spec F16); wrong direction fails closed."""
    if message_type not in allowed:
        raise ProtocolError(f'message type {message_type!r} not allowed inbound')


def encode_frame(channel: DirectionChannel, message_type: str, plaintext: bytes,
                 *, allow_reserved: bool = False) -> bytes:
    """Seal one plaintext and return the complete frame (header + ciphertext).

    One attempt, no retries; reserved types are refused unless explicitly allowed.
    """
    sequence, ciphertext = channel.seal(message_type, plaintext)
    return build_header(len(ciphertext), message_type, sequence,
                        allow_reserved=allow_reserved) + ciphertext


def decode_frame(channel: DirectionChannel, frame: bytes) -> tuple[str, int, bytes]:
    """Validate a complete frame and return ``(message_type, sequence, plaintext)``."""
    if len(frame) < FRAME_HEADER_BYTES:
        raise ProtocolError('frame shorter than the 13-byte header')
    message_type, sequence, length = parse_header(frame[:FRAME_HEADER_BYTES],
                                                  max_frame_bytes=channel._max)
    ciphertext = frame[FRAME_HEADER_BYTES:]
    if len(ciphertext) != length:
        raise ProtocolError(f'frame length mismatch: header {length}, body {len(ciphertext)}')
    plaintext = channel.open(message_type, sequence, ciphertext)
    return message_type, sequence, plaintext


__all__ = ['WIRE_SPEC_VERSION', 'FRAME_HEADER_BYTES', 'MAX_FRAME_BYTES_DEFAULT',
           'FRAME_TYPE_NAMES', 'FRAME_TYPE_BYTES', 'RESERVED_FRAME_TYPES',
           'AGENT_INBOUND', 'HOST_INBOUND', 'UnknownFrameType', 'ReservedFrameType',
           'type_byte', 'build_header', 'parse_header', 'check_inbound',
           'encode_frame', 'decode_frame']
