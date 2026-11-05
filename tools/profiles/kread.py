#!/usr/bin/env python3
"""W12 ``kernel.read`` request model and 64-bit bounds primitives (offline, host side).

The W12 wave promotes the first bounded, read-only ``kernel.read`` provider. This module
is the request half of that promotion: the wire-visible request has exactly four keys --
``operation='kernel.read'``, ``region``, ``offset``, ``length`` -- and no address of any
kind. There is no raw-address mode and no fallback: a request that carries an address-ish
field (``addr``, ``address``, ``va``, ``kva``, ``pointer``, ``ptr``, ``raw``, ``resolve``,
in any casing) is refused at this schema boundary *before* any other check runs. The
resolved internal address is produced by the registry (:mod:`tools.profiles.regions`) and
only ever travels inside a ``ResolvedRead``; the request never gains one.

Why the bounds primitives are explicit (each owns a failure mode):

* :func:`checked_add` -- unsigned 64-bit checked addition. Python integers never wrap, so
  a missing bound would *not* fail loudly by itself; the wrap would silently reappear
  only at the boundary where the sum is handed to a 64-bit consumer (the native provider,
  the wire framing). The helper turns "does not fit unsigned 64 bits" into an explicit
  ``None`` that :func:`tools.profiles.regions.resolve_read` refuses with
  ``KREAD_OFFSET_OVERFLOW``.
* :func:`is_canonical_x86_64` -- 48-bit sign-extended canonicality. A non-canonical
  address is transformed by the CPU the moment it is dereferenced, so it is the wrong
  address even before a read; the registry refuses it with ``KREAD_NON_CANONICAL_ADDRESS``.

Schema decisions, fail closed:

* unknown keys are **rejected** (:data:`KREAD_SCHEMA_UNKNOWN_KEY`), never ignored -- an
  ignored field is an unreviewed field, and the capability path may only ever see the
  reviewed shape. The address-ish scan runs first so an address-like key can never pass
  as "just an unknown key";
* ``offset`` and ``length`` must be integers; ``bool`` counts as a wrong type
  (:data:`KREAD_SCHEMA_TYPE`). ``region`` must be a non-empty string;
* ``operation`` must be exactly ``kernel.read`` (:data:`KREAD_SCHEMA_OPERATION`): this
  model expresses no other operation and applies no implicit default.

The refusal vocabulary (schema here, registry/bounds below) is defined once so the
request model, the registry and their tests can never drift apart.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

OPERATION_KERNEL_READ = 'kernel.read'

#: The four expressible wire keys -- the request model can express nothing else.
REQUEST_KEYS: tuple[str, ...] = ('operation', 'region', 'offset', 'length')

#: Address-ish keys that must never appear in a request (any casing). A request carrying
#: one is a schema reject, never a raw-address mode: the resolved address is produced by
#: the registry, and no alias, spelling or fallback exists for it.
RAW_ADDRESS_KEYS = frozenset({'addr', 'address', 'va', 'kva', 'pointer', 'ptr', 'raw',
                              'resolve'})

#: Largest value representable in one unsigned 64-bit word (the wire/provider domain).
U64_MAX = (1 << 64) - 1

#: x86-64 4-level paging: an address is canonical when bits 63..47 are all zero or all one.
CANONICAL_TOP_BITS_SHIFT = 47
CANONICAL_TOP_BITS_ONES = (1 << (64 - CANONICAL_TOP_BITS_SHIFT)) - 1

# --- refusal vocabulary (defined once; enforced by this module and regions.py) ----------

# schema: the request never reaches the registry
KREAD_SCHEMA_RAW_ADDRESS = 'KREAD_SCHEMA_RAW_ADDRESS'
KREAD_SCHEMA_UNKNOWN_KEY = 'KREAD_SCHEMA_UNKNOWN_KEY'
KREAD_SCHEMA_MISSING_KEY = 'KREAD_SCHEMA_MISSING_KEY'
KREAD_SCHEMA_TYPE = 'KREAD_SCHEMA_TYPE'
KREAD_SCHEMA_OPERATION = 'KREAD_SCHEMA_OPERATION'

# registry and bounds: frozen order, enforced by regions.resolve_read
KREAD_UNKNOWN_REGION = 'KREAD_UNKNOWN_REGION'
KREAD_UNRESOLVED_REGION = 'KREAD_UNRESOLVED_REGION'
KREAD_POLICY_NOT_APPROVED = 'KREAD_POLICY_NOT_APPROVED'
KREAD_STRICT_IDENTITY_REQUIRED = 'KREAD_STRICT_IDENTITY_REQUIRED'
KREAD_NEGATIVE_OFFSET = 'KREAD_NEGATIVE_OFFSET'
KREAD_OFFSET_OVERFLOW = 'KREAD_OFFSET_OVERFLOW'
KREAD_LENGTH_ZERO = 'KREAD_LENGTH_ZERO'
KREAD_LENGTH_EXCEEDS_MAX = 'KREAD_LENGTH_EXCEEDS_MAX'
KREAD_CROSS_REGION = 'KREAD_CROSS_REGION'
KREAD_NON_CANONICAL_ADDRESS = 'KREAD_NON_CANONICAL_ADDRESS'

# runtime resolution (W12-RVA0-BINDING): a *relative* locator resolved against the current
# boot's kernel base is checked arithmetic; every failure refuses the read, fail closed.
KREAD_RUNTIME_OVERFLOW = 'KREAD_RUNTIME_OVERFLOW'
KREAD_ZERO_RUNTIME_ADDRESS = 'KREAD_ZERO_RUNTIME_ADDRESS'
KREAD_OUTSIDE_IMAGE_WINDOW = 'KREAD_OUTSIDE_IMAGE_WINDOW'

#: The compiled target table cannot be trusted (duplicate entry, an incomplete non-UNRESOLVED
#: entry, an empty table).  A wrong table must never reach a payload or a verifier
#: (deviation ``W12-A-D1``).
KREAD_TABLE_INVALID = 'KREAD_TABLE_INVALID'


class KReadReject(Exception):
    """Fail-closed ``kernel.read`` refusal: the first failed check stops the read.

    ``reason`` is the machine-readable code; ``detail`` is human context only and never
    carries an address the request did not have. Nothing partial is ever returned.
    """

    def __init__(self, reason: str, detail: str = '') -> None:
        super().__init__(f'{reason}: {detail}' if detail else reason)
        self.reason = reason
        self.detail = detail


def checked_add(a: int, b: int) -> int | None:
    """Unsigned 64-bit checked addition: ``None`` when the sum would not fit a u64.

    Python integers do not wrap, so an unchecked sum would not fail loudly by itself;
    the wrap would silently reappear where the value is consumed as 64 bits (native
    provider, wire framing). This helper makes "does not fit unsigned 64 bits" an
    explicit value the caller must refuse.

    Preconditions are programmer errors and raise (``TypeError`` for non-integers,
    ``bool`` included; ``ValueError`` outside ``[0, 2**64 - 1]``). Valid operands whose
    sum would exceed ``2**64 - 1`` return ``None`` -- never a wrapped value.
    """
    if isinstance(a, bool) or not isinstance(a, int) or \
            isinstance(b, bool) or not isinstance(b, int):
        raise TypeError('checked_add operands must be integers (bool is not an integer here)')
    if a < 0 or b < 0 or a > U64_MAX or b > U64_MAX:
        raise ValueError('checked_add operands must fit unsigned 64 bits')
    total = a + b
    if total > U64_MAX:
        return None
    return total


def is_canonical_x86_64(address: int) -> bool:
    """True for a canonical 48-bit sign-extended x86-64 address.

    The CPU transforms a non-canonical address on dereference, so a non-canonical
    "address" is the wrong address even before a read. Anything that is not a plain
    integer inside ``[0, 2**64 - 1]`` is False (fail closed).
    """
    if isinstance(address, bool) or not isinstance(address, int):
        return False
    if address < 0 or address > U64_MAX:
        return False
    return (address >> CANONICAL_TOP_BITS_SHIFT) in (0, CANONICAL_TOP_BITS_ONES)


def is_raw_address_key(key) -> bool:
    """True when ``key`` is an address-ish request key (casing is not a loophole)."""
    return isinstance(key, str) and key.lower() in RAW_ADDRESS_KEYS


@dataclass(frozen=True)
class KReadRequest:
    """The wire-visible ``kernel.read`` request: region + offset + length, nothing else.

    The dataclass has exactly the four expressible keys and no address field; none may
    be added -- the resolved address exists only inside ``ResolvedRead``, and only after
    the registry accepted the read. Build requests through :func:`parse_request` /
    :meth:`from_mapping`, the strict mapping validator.
    """

    operation: str
    region: str
    offset: int
    length: int

    def as_mapping(self) -> dict:
        """Exact wire shape of this request (round-trip of the validated mapping)."""
        return {'operation': self.operation, 'region': self.region,
                'offset': self.offset, 'length': self.length}

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, object] | dict) -> 'KReadRequest':
        """Strict constructor for one wire mapping (see :func:`parse_request`)."""
        return parse_request(mapping)


def parse_request(mapping: Mapping[str, object] | dict) -> KReadRequest:
    """Validate one wire mapping; the only sanctioned way a request enters the path.

    Refuses (never ignores) the first of, in this order:

    * an address-ish key in any casing -- ``KREAD_SCHEMA_RAW_ADDRESS``: there is no
      raw-address mode and no fallback, so this is refused before anything else, even
      when the mapping also carries unknown keys;
    * a key outside :data:`REQUEST_KEYS` -- ``KREAD_SCHEMA_UNKNOWN_KEY`` (unknown keys
      are rejected by decision; an ignored field is an unreviewed field);
    * a missing required key -- ``KREAD_SCHEMA_MISSING_KEY``;
    * ``operation`` other than ``kernel.read`` -- ``KREAD_SCHEMA_OPERATION``;
    * a wrongly typed value -- ``KREAD_SCHEMA_TYPE`` (``region`` must be a non-empty
      string; ``offset``/``length`` must be integers, and ``bool`` is not one).
    """
    if not isinstance(mapping, Mapping):
        raise KReadReject(KREAD_SCHEMA_TYPE,
                          f'request must be an object, got {type(mapping).__name__}')
    for key in mapping:
        if is_raw_address_key(key):
            raise KReadReject(
                KREAD_SCHEMA_RAW_ADDRESS,
                f'key {key!r} is an address-ish field; a kernel.read request is '
                'operation/region/offset/length only, with no raw-address mode')
    unknown = [key for key in mapping
               if not isinstance(key, str) or key not in REQUEST_KEYS]
    if unknown:
        raise KReadReject(KREAD_SCHEMA_UNKNOWN_KEY,
                          f'unknown key(s) {unknown!r}: the request is exactly '
                          f'{list(REQUEST_KEYS)}')
    missing = [key for key in REQUEST_KEYS if key not in mapping]
    if missing:
        raise KReadReject(KREAD_SCHEMA_MISSING_KEY, f'missing key(s) {missing!r}')
    operation = mapping['operation']
    if operation != OPERATION_KERNEL_READ:
        raise KReadReject(KREAD_SCHEMA_OPERATION,
                          f'operation must be exactly {OPERATION_KERNEL_READ!r}, '
                          f'got {operation!r}')
    region = mapping['region']
    if not isinstance(region, str) or not region:
        raise KReadReject(KREAD_SCHEMA_TYPE, 'region must be a non-empty string')
    offset = _require_integer(mapping['offset'], 'offset')
    length = _require_integer(mapping['length'], 'length')
    return KReadRequest(OPERATION_KERNEL_READ, region, offset, length)


def _require_integer(value, name: str) -> int:
    """Strict integer field check: ``bool`` is not an integer on this wire."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise KReadReject(KREAD_SCHEMA_TYPE,
                          f'{name} must be an integer, got {type(value).__name__}')
    return value
