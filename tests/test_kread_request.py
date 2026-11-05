"""W12 request-model tests: exactly four keys, no address ever, checked arithmetic.

The request model is the only entrance to the bounded ``kernel.read`` path, so these
tests pin the whole refusal surface: every address-ish key in every casing, unknown keys
(rejected, not ignored), missing keys, wrong types, the frozen reason strings, and the
64-bit checked-addition helper including its wrap detection. No network, deterministic.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:                      # pragma: no cover - import bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from tools.profiles import kread                                        # noqa: E402
from tools.profiles import regions as reg                               # noqa: E402
from tools.profiles.kread import (                                      # noqa: E402
    KReadReject, KReadRequest, RAW_ADDRESS_KEYS, REQUEST_KEYS, U64_MAX, checked_add,
    is_raw_address_key, parse_request,
)

VALID = {'operation': 'kernel.read', 'region': 'boottime', 'offset': 0, 'length': 16}


def _reject(reason, fn, *args, **kwargs):
    with pytest.raises(KReadReject) as excinfo:
        fn(*args, **kwargs)
    assert excinfo.value.reason == reason, \
        f'expected {reason}, got {excinfo.value.reason}'
    return excinfo.value


# --- the frozen request shape -------------------------------------------------------------

def test_the_frozen_request_shape_parses():
    request = parse_request(VALID)
    assert request == KReadRequest('kernel.read', 'boottime', 0, 16)
    assert request.as_mapping() == VALID
    assert KReadRequest.from_mapping(VALID) == request


def test_the_request_model_has_no_address_field():
    assert tuple(field.name for field in dataclasses.fields(KReadRequest)) == REQUEST_KEYS
    assert set(parse_request(VALID).as_mapping()) == set(REQUEST_KEYS)
    assert 'address' not in KReadRequest.__dataclass_fields__
    assert 'resolved' not in KReadRequest.__dataclass_fields__


def test_request_dataclass_is_frozen():
    request = parse_request(VALID)
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(request, 'offset', 1)


# --- raw-address keys: refused in any casing, before everything else ----------------------

@pytest.mark.parametrize('key', sorted(RAW_ADDRESS_KEYS))
def test_every_address_ish_key_is_refused(key):
    reject = _reject(kread.KREAD_SCHEMA_RAW_ADDRESS, parse_request,
                     dict(VALID, **{key: 0xffffffff80000000}))
    assert key in reject.detail


@pytest.mark.parametrize('key', ['ADDR', 'Address', 'VA', 'KVA', 'Pointer', 'PTR',
                                 'Raw', 'ReSoLvE'])
def test_address_ish_keys_are_refused_in_any_casing(key):
    _reject(kread.KREAD_SCHEMA_RAW_ADDRESS, parse_request, dict(VALID, **{key: 1}))


def test_address_ish_refusal_wins_even_next_to_unknown_keys():
    reject = _reject(kread.KREAD_SCHEMA_RAW_ADDRESS, parse_request,
                     dict(VALID, addr=1, something_else=2))
    assert kread.KREAD_SCHEMA_UNKNOWN_KEY not in reject.reason


def test_raw_address_key_predicate():
    for key in RAW_ADDRESS_KEYS:
        assert is_raw_address_key(key)
        assert is_raw_address_key(key.upper())
        assert is_raw_address_key(key.title())
    assert not is_raw_address_key('region')
    assert not is_raw_address_key('offset')
    assert not is_raw_address_key(None)


@pytest.mark.parametrize('key', ['kernel_addr', 'addr64', 'kaddr', 'raw_address',
                                 'pointer_value', 'va_hint', 'ptr_low', 'kva_guess',
                                 'kernel_address', 'resolved_address'])
def test_an_address_smuggled_under_an_unusual_name_is_still_refused(key):
    """No spelling of an address can enter a request.

    The exact alias scan owns the known spellings (``addr``, ``va``, ``raw``, ...); every
    other name -- however address-flavoured -- fails the unknown-key rejection, because
    the four frozen keys are the only keys the request model accepts.
    """
    _reject(kread.KREAD_SCHEMA_UNKNOWN_KEY, parse_request,
            dict(VALID, **{key: 0xffffffff80000000}))
    # the value's shape is irrelevant: the key alone refuses the request
    _reject(kread.KREAD_SCHEMA_UNKNOWN_KEY, parse_request, dict(VALID, **{key: None}))


def test_no_key_outside_the_frozen_four_is_ever_accepted():
    # "region" is a key; the rest of the four are the only others. Every value a caller
    # could use to smuggle an address is either an alias (raw-address reject) or an
    # unknown key (unknown-key reject) -- there is no third outcome and no fallback.
    accepted = set()
    for candidate in ('region', 'offset', 'length', 'operation', 'addr', 'va', 'ptr',
                      'raw', 'resolve', 'kva', 'pointer', 'address', 'kernel_addr',
                      'offset_bytes', 'region_id', 'Address'):
        mapping = dict(VALID, **{candidate: 1}) if candidate not in VALID else VALID
        try:
            parse_request(mapping)
        except KReadReject as reject:
            assert reject.reason in (kread.KREAD_SCHEMA_RAW_ADDRESS,
                                     kread.KREAD_SCHEMA_UNKNOWN_KEY,
                                     kread.KREAD_SCHEMA_TYPE), reject.reason
            continue
        accepted.add(candidate)
    assert accepted <= set(REQUEST_KEYS)


# --- unknown / missing / wrong-shaped requests --------------------------------------------

def test_unknown_keys_are_rejected_not_ignored():
    _reject(kread.KREAD_SCHEMA_UNKNOWN_KEY, parse_request, dict(VALID, extra=1))
    _reject(kread.KREAD_SCHEMA_UNKNOWN_KEY, parse_request, dict(VALID, region2='x'))
    reject = _reject(kread.KREAD_SCHEMA_UNKNOWN_KEY, parse_request, {**VALID, 7: 'x'})
    assert '7' in reject.detail


def test_missing_keys_are_rejected():
    for key in REQUEST_KEYS:
        mapping = {k: v for k, v in VALID.items() if k != key}
        reject = _reject(kread.KREAD_SCHEMA_MISSING_KEY, parse_request, mapping)
        assert key in reject.detail


def test_operation_must_be_exactly_kernel_read():
    _reject(kread.KREAD_SCHEMA_OPERATION, parse_request,
            dict(VALID, operation='kernel.write'))
    _reject(kread.KREAD_SCHEMA_OPERATION, parse_request,
            dict(VALID, operation='KERNEL.READ'))
    _reject(kread.KREAD_SCHEMA_OPERATION, parse_request, dict(VALID, operation=None))


def test_values_are_strictly_typed():
    for mapping in (dict(VALID, offset='16'), dict(VALID, offset=16.0),
                    dict(VALID, offset=True), dict(VALID, offset=None),
                    dict(VALID, length='16'), dict(VALID, length=True),
                    dict(VALID, region=17), dict(VALID, region='')):
        _reject(kread.KREAD_SCHEMA_TYPE, parse_request, mapping)


def test_non_object_requests_are_refused():
    for value in ('kernel.read', None, ['kernel.read'], 17,
                  [('operation', 'kernel.read')]):
        _reject(kread.KREAD_SCHEMA_TYPE, parse_request, value)


def test_json_round_trip_keeps_the_wire_shape():
    request = parse_request(json.loads(json.dumps(VALID)))
    assert request.as_mapping() == VALID
    # a JSON float length is refused, even when it is whole
    _reject(kread.KREAD_SCHEMA_TYPE, parse_request,
            json.loads('{"operation": "kernel.read", "region": "boottime", '
                       '"offset": 0, "length": 16.0}'))


def test_reason_vocabulary_is_the_frozen_string_set():
    vocabulary = {
        'KREAD_SCHEMA_RAW_ADDRESS': kread.KREAD_SCHEMA_RAW_ADDRESS,
        'KREAD_SCHEMA_UNKNOWN_KEY': kread.KREAD_SCHEMA_UNKNOWN_KEY,
        'KREAD_SCHEMA_MISSING_KEY': kread.KREAD_SCHEMA_MISSING_KEY,
        'KREAD_SCHEMA_TYPE': kread.KREAD_SCHEMA_TYPE,
        'KREAD_SCHEMA_OPERATION': kread.KREAD_SCHEMA_OPERATION,
        'KREAD_UNKNOWN_REGION': kread.KREAD_UNKNOWN_REGION,
        'KREAD_UNRESOLVED_REGION': kread.KREAD_UNRESOLVED_REGION,
        'KREAD_POLICY_NOT_APPROVED': kread.KREAD_POLICY_NOT_APPROVED,
        'KREAD_STRICT_IDENTITY_REQUIRED': kread.KREAD_STRICT_IDENTITY_REQUIRED,
        'KREAD_NEGATIVE_OFFSET': kread.KREAD_NEGATIVE_OFFSET,
        'KREAD_OFFSET_OVERFLOW': kread.KREAD_OFFSET_OVERFLOW,
        'KREAD_LENGTH_ZERO': kread.KREAD_LENGTH_ZERO,
        'KREAD_LENGTH_EXCEEDS_MAX': kread.KREAD_LENGTH_EXCEEDS_MAX,
        'KREAD_CROSS_REGION': kread.KREAD_CROSS_REGION,
        'KREAD_NON_CANONICAL_ADDRESS': kread.KREAD_NON_CANONICAL_ADDRESS,
    }
    for name, value in vocabulary.items():
        assert value == name


# --- checked 64-bit arithmetic -------------------------------------------------------------

def test_checked_add_plain_sums():
    assert checked_add(0, 0) == 0
    assert checked_add(4096, 4096) == 8192
    assert checked_add(U64_MAX, 0) == U64_MAX
    assert checked_add(U64_MAX - 4096, 4096) == U64_MAX


def test_checked_add_detects_wraparound():
    assert checked_add(U64_MAX, 1) is None                 # exactly 2**64
    assert checked_add(U64_MAX - 1, 2) is None
    assert checked_add(2 ** 63, 2 ** 63) is None           # exactly 2**64
    assert checked_add(U64_MAX - 4096, 4097) is None
    assert checked_add(U64_MAX, U64_MAX) is None


def test_checked_add_rejects_invalid_operands():
    with pytest.raises(ValueError):
        checked_add(-1, 1)
    with pytest.raises(ValueError):
        checked_add(1, -1)
    with pytest.raises(ValueError):
        checked_add(U64_MAX + 1, 0)
    with pytest.raises(TypeError):
        checked_add('1', 1)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        checked_add(True, 1)
    with pytest.raises(TypeError):
        checked_add(1.0, 1)  # type: ignore[arg-type]


# --- request model meets the registry ------------------------------------------------------

def test_parsed_request_resolves_through_the_registry():
    request = parse_request({'operation': 'kernel.read', 'region': 'boottime',
                             'offset': 0, 'length': 16})
    resolved = reg.resolve_read(request.region, request.offset, request.length)
    assert resolved.address == 0x224C6C8
    assert resolved.region.name == request.region
    # the request never carries the resolved address - that lives in ResolvedRead only
    assert 'address' not in request.as_mapping()


def test_parsed_request_out_of_bounds_reaches_the_registry_refusals():
    request = parse_request({'operation': 'kernel.read', 'region': 'boottime',
                             'offset': 15, 'length': 2})
    with pytest.raises(KReadReject) as excinfo:
        reg.resolve_read(request.region, request.offset, request.length)
    assert excinfo.value.reason == 'KREAD_CROSS_REGION'
