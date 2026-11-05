#!/usr/bin/env python3
"""Fail-closed request/response validation for the P4/W3 primitive interface freeze v1.

Validates the message envelope and the per-operation argument/result schemas of
``tools/primitive_iface/schema.py``. Everything is fail-closed: an unknown field, a
wrong type, a missing required field or an unknown error code is an error, never a
silent pass-through. Nothing here talks to a socket, a console or a subprocess.

Usage::

    python tools/primitive_iface/validate.py --self-test

Exit codes: 0 = valid, 1 = invalid (reasons printed), 2 = usage/IO error.
"""

from __future__ import annotations

import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from tools.primitive_iface.schema import (  # noqa: E402
    CLEANUP_STATES, ERROR_CODES, HEX32, OPS_BY_NAME, REF_PATTERN, Field,
)

REQUEST_ID_RE = re.compile(r'^REQ-[0-9a-f]{32}$')
BYE_REASONS = ('CLIENT_CLOSE', 'RECOVERY_REQUIRED', 'SERVER_CLOSE')
REQUEST_KEYS = ('header', 'body')
RESPONSE_KEYS = ('header', 'status', 'result', 'error', 'cleanup')


class InterfaceError(Exception):
    """Protocol-level refusal, carrying a frozen error code."""

    def __init__(self, code: str, detail: str = ''):
        if code not in ERROR_CODES:
            raise ValueError(f'unknown error code {code!r}')
        super().__init__(f'{code}: {detail}' if detail else code)
        self.code = code
        self.detail = detail


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _type_ok(kind: str, value) -> bool:
    if kind == 'int':
        return _is_int(value)
    if kind == 'str':
        return isinstance(value, str)
    if kind == 'bool':
        return isinstance(value, bool)
    if kind == 'ref':
        return isinstance(value, str) and bool(REF_PATTERN.fullmatch(value))
    if kind == 'hex32':
        return isinstance(value, str) and bool(HEX32.fullmatch(value))
    if kind == 'array':
        return isinstance(value, list)
    if kind == 'object':
        return isinstance(value, dict)
    raise ValueError(f'unknown field type {kind!r}')


def _validate_fields(op: str, fields: tuple[Field, ...], payload: dict, where: str) -> None:
    if not isinstance(payload, dict):
        raise InterfaceError('ARGUMENT_INVALID', f'{op}: {where} must be an object')
    known = {fl.name for fl in fields}
    unknown = sorted(set(payload) - known)
    if unknown:
        raise InterfaceError('ARGUMENT_INVALID', f'{op}: unknown {where} field(s): {", ".join(unknown)}')
    for fl in fields:
        if fl.name not in payload:
            if fl.required:
                raise InterfaceError('ARGUMENT_INVALID', f'{op}: {where} field {fl.name!r} is required')
            continue
        value = payload[fl.name]
        if value is None and not fl.required:
            continue
        if not _type_ok(fl.type, value):
            raise InterfaceError(
                'ARGUMENT_INVALID',
                f'{op}: {where} field {fl.name!r} must be {fl.type} (got {type(value).__name__})')


def validate_arguments(op: str, arguments: dict) -> None:
    """Validate the request ``body.arguments`` of one operation (fail-closed)."""
    spec = OPS_BY_NAME.get(op)
    if spec is None:
        raise InterfaceError('OPERATION_UNSUPPORTED', f'no such operation: {op}')
    _validate_fields(op, spec.args, arguments if arguments is not None else {}, 'argument')


def validate_request(body: dict) -> str:
    """Validate a decoded REQUEST *body*; returns the operation name."""
    if not isinstance(body, dict):
        raise InterfaceError('ARGUMENT_INVALID', 'request body must be an object')
    unknown = sorted(set(body) - {'operation', 'arguments', 'seq'})
    if unknown:
        raise InterfaceError('ARGUMENT_INVALID', f'unknown body field(s): {", ".join(unknown)}')
    op = body.get('operation')
    if not isinstance(op, str) or not op:
        raise InterfaceError('ARGUMENT_INVALID', 'body.operation must be a non-empty string')
    validate_arguments(op, body.get('arguments') or {})
    if 'seq' in body and body['seq'] is not None and not _is_int(body['seq']):
        raise InterfaceError('ARGUMENT_INVALID', 'body.seq must be an integer')
    return op


def validate_request_envelope(obj: dict) -> str:
    """Validate a full REQUEST message (``header`` + ``body``); returns the operation."""
    if not isinstance(obj, dict) or 'header' not in obj or 'body' not in obj:
        raise InterfaceError('ARGUMENT_INVALID', 'request must carry header and body')
    unknown = sorted(set(obj) - set(REQUEST_KEYS))
    if unknown:
        raise InterfaceError('ARGUMENT_INVALID', f'unknown request field(s): {", ".join(unknown)}')
    header = obj['header']
    if not isinstance(header, dict) or not isinstance(header.get('request_id'), str):
        raise InterfaceError('ARGUMENT_INVALID', 'header.request_id is required')
    if not REQUEST_ID_RE.fullmatch(header['request_id']):
        raise InterfaceError('ARGUMENT_INVALID', f'bad request id shape: {header["request_id"]!r}')
    extra = sorted(set(header) - {'request_id'})
    if extra:
        raise InterfaceError('ARGUMENT_INVALID', f'unknown header field(s): {", ".join(extra)}')
    return validate_request(obj['body'])


def ok_response(op: str, request_id: str, result: dict, cleanup: dict | None = None) -> dict:
    """Build (and validate) a successful RESPONSE for one operation."""
    response: dict = {'header': {'in_reply_to': request_id}, 'status': 'OK', 'result': result}
    if cleanup is not None:
        response['cleanup'] = cleanup
    validate_response_envelope(op, response)
    return response


def error_response(request_id: str, code: str, cleanup: dict | None = None) -> dict:
    if code not in ERROR_CODES:
        raise ValueError(f'unknown error code {code!r}')
    response: dict = {'header': {'in_reply_to': request_id}, 'status': 'ERROR', 'error': {'code': code}}
    if cleanup is not None:
        response['cleanup'] = cleanup
    return response


def cleanup_report(state: str, resources: list[dict] | None = None) -> dict:
    if state not in CLEANUP_STATES:
        raise ValueError(f'unknown cleanup state {state!r}')
    return {'state': state, 'resources': resources or []}


def validate_response_envelope(op: str, obj: dict) -> None:
    """Validate a RESPONSE message against the frozen result schema of ``op``."""
    spec = OPS_BY_NAME.get(op)
    if spec is None:
        raise InterfaceError('OPERATION_UNSUPPORTED', f'no such operation: {op}')
    if not isinstance(obj, dict):
        raise InterfaceError('ARGUMENT_INVALID', f'{op}: response must be an object')
    unknown = sorted(set(obj) - set(RESPONSE_KEYS))
    if unknown:
        raise InterfaceError('ARGUMENT_INVALID', f'{op}: unknown response field(s): {", ".join(unknown)}')
    header = obj.get('header')
    if not isinstance(header, dict) or not REQUEST_ID_RE.fullmatch(str(header.get('in_reply_to', ''))):
        raise InterfaceError('ARGUMENT_INVALID', f'{op}: header.in_reply_to is required')
    extra = sorted(set(header) - {'in_reply_to'})
    if extra:
        raise InterfaceError('ARGUMENT_INVALID', f'{op}: unknown response header field(s): {", ".join(extra)}')
    status = obj.get('status')
    if status not in ('OK', 'ERROR'):
        raise InterfaceError('ARGUMENT_INVALID', f'{op}: status must be OK or ERROR')
    if 'cleanup' in obj:
        cleanup = obj['cleanup']
        if not isinstance(cleanup, dict) or cleanup.get('state') not in CLEANUP_STATES:
            raise InterfaceError('ARGUMENT_INVALID', f'{op}: bad cleanup report')
        if not isinstance(cleanup.get('resources', []), list):
            raise InterfaceError('ARGUMENT_INVALID', f'{op}: cleanup.resources must be an array')
    if status == 'ERROR':
        error = obj.get('error')
        if not isinstance(error, dict) or error.get('code') not in ERROR_CODES:
            raise InterfaceError('ARGUMENT_INVALID', f'{op}: error.code must be a frozen code')
        if sorted(set(error) - {'code', 'detail'}):
            raise InterfaceError('ARGUMENT_INVALID', f'{op}: unknown error field(s)')
        if 'result' in obj:
            raise InterfaceError('ARGUMENT_INVALID', f'{op}: an ERROR response carries no result')
        return
    if 'error' in obj:
        raise InterfaceError('ARGUMENT_INVALID', f'{op}: an OK response carries no error')
    if spec.result is None:
        raise InterfaceError('ARGUMENT_INVALID', f'{op}: operation has no result shape')
    result = obj.get('result')
    if not isinstance(result, dict):
        raise InterfaceError('ARGUMENT_INVALID', f'{op}: result must be an object')
    known = {fl.name for fl in spec.result}
    unknown = sorted(set(result) - known)
    if unknown:
        raise InterfaceError('ARGUMENT_INVALID', f'{op}: unknown result field(s): {", ".join(unknown)}')
    for fl in spec.result:
        if fl.required and fl.name not in result:
            raise InterfaceError('ARGUMENT_INVALID', f'{op}: result field {fl.name!r} is required')
        if fl.name in result and result[fl.name] is not None and not _type_ok(fl.type, result[fl.name]):
            raise InterfaceError('ARGUMENT_INVALID',
                                 f'{op}: result field {fl.name!r} must be {fl.type}')


def validate_bye(obj: dict) -> None:
    """Validate a BYE message (``msg`` / ``reason`` / ``cleanup``)."""
    if not isinstance(obj, dict) or obj.get('msg') != 'BYE':
        raise InterfaceError('ARGUMENT_INVALID', 'BYE message must carry msg="BYE"')
    if obj.get('reason') not in BYE_REASONS:
        raise InterfaceError('ARGUMENT_INVALID', f'BYE reason must be one of {BYE_REASONS}')
    unknown = sorted(set(obj) - {'msg', 'reason', 'cleanup'})
    if unknown:
        raise InterfaceError('ARGUMENT_INVALID', f'unknown BYE field(s): {", ".join(unknown)}')
    cleanup = obj.get('cleanup')
    if not isinstance(cleanup, dict) or cleanup.get('state') not in CLEANUP_STATES:
        raise InterfaceError('ARGUMENT_INVALID', 'BYE cleanup report is required')


def main(argv: list[str]) -> int:
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: validate.py --self-test')
        return 2
    checks: list[str] = []

    def expect(condition: bool, label: str) -> None:
        checks.append(label)
        if not condition:
            raise SystemExit(f'FAIL {label}')

    rid = 'REQ-' + '0' * 31 + '1'
    for op in sorted(OPS_BY_NAME):
        spec = OPS_BY_NAME[op]
        args = {}
        for fl in spec.args:
            args[fl.name] = {'int': 1, 'str': 'x', 'bool': True, 'ref': 'mem:0123456789ABCDEF',
                             'hex32': 'a' * 64, 'array': [], 'object': {}}[fl.type]
        validate_arguments(op, args)
        expect(True, f'{op}: schema-valid arguments accepted')
        if spec.result is not None:
            result = {}
            for fl in spec.result:
                if fl.required:
                    result[fl.name] = {'int': 1, 'str': 'x', 'bool': True, 'ref': 'mem:0123456789ABCDEF',
                                       'hex32': 'a' * 64, 'array': [], 'object': {}}[fl.type]
            validate_response_envelope(op, ok_response(op, rid, result))
            expect(True, f'{op}: schema-valid response accepted')
        try:
            validate_arguments(op, {'__not_a_field__': 1})
        except InterfaceError as exc:
            expect(exc.code == 'ARGUMENT_INVALID', f'{op}: unknown field refused ({exc.code})')
        else:
            expect(False, f'{op}: unknown field accepted')
    expect(REQUEST_ID_RE.fullmatch(rid) is not None, 'request id shape')
    print(f'validate.py self-test: {len(checks)} checks passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
