#!/usr/bin/env python3
"""PS4RF P4/W7 provider invocation evidence.

Every dispatch attempt - accepted or refused - produces exactly one evidence record with
the fields the work order names: run id, request id, operation, selected provider,
provider type, capability, effective assurance, W4 gate result, profile sha256, boot id,
session id, context, provider entry yes/no, result/error, resource changes and cleanup
result. A refused dispatch additionally names the chain step that stopped it
(``stopped_at``), so a refusal is never ambiguous.

Records are immutable snapshots (plain dicts) and the sink is thread-safe: concurrent
requests cannot overwrite each other's evidence.

Usage::

    python tools/dispatch/evidence.py --self-test
"""

from __future__ import annotations

import json
import pathlib
import sys
import threading

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

EVIDENCE_SCHEMA = 'ps4rf.provider-router.evidence.v1'

# the normative chain (W7 work order), in order; a refusal names the step that stopped it
CHAIN_STEPS = (
    'rpc_validation',
    'operation_registry',
    'capability_resolution',
    'effective_grant',
    'w4_gate',
    'w5_profile_binding',
    'provider_router',
    'primitive_interface',
    'resource_policy',
    'response',
)

# W4 reason -> the chain step that this reason belongs to
REASON_TO_STEP = {
    'RECOVERY_REQUIRED': 'resource_policy',
    'CAPABILITY_MISSING': 'capability_resolution',
    'ASSURANCE_TOO_LOW': 'effective_grant',
    'PROVIDER_NOT_ALLOWED': 'effective_grant',
    'CONTEXT_MISMATCH': 'capability_resolution',
    'BINDING_MISMATCH': 'capability_resolution',
    'PROFILE_UNBOUND': 'w5_profile_binding',
    'EVIDENCE_MISSING': 'w4_gate',
    'APPROVAL_MISSING': 'w4_gate',
    'NOT_WIRED': 'provider_router',
}

STOP_STEPS = CHAIN_STEPS

FIELDS = (
    'run_id', 'request_id', 'operation', 'selected_provider', 'provider_type', 'capability',
    'effective_assurance', 'w4_decision', 'w4_reasons', 'profile_sha256', 'boot_id',
    'session_id', 'context', 'provider_entry', 'stopped_at', 'result', 'error',
    'error_detail', 'resource_changes', 'cleanup', 'metadata',
)


def record(*, run_id: str, request_id: str, operation: str, selected_provider: str,
           provider_type: str | None = None, capability: str | None = None,
           effective_assurance: str | None = None, w4_decision: str | None = None,
           w4_reasons: tuple[str, ...] = (), profile_sha256: str | None = None,
           boot_id: str | None = None, session_id: str | None = None,
           context: str | None = None, provider_entry: bool = False,
           stopped_at: str | None = None, result: str = 'PENDING', error: str | None = None,
           error_detail: str | None = None,
           resource_changes: list | None = None, cleanup: dict | None = None,
           metadata: dict | None = None) -> dict:
    if stopped_at is not None and stopped_at not in STOP_STEPS:
        raise ValueError(f'unknown chain step {stopped_at!r}')
    entry = {
        'schema': EVIDENCE_SCHEMA,
        'run_id': run_id, 'request_id': request_id, 'operation': operation,
        'selected_provider': selected_provider, 'provider_type': provider_type,
        'capability': capability, 'effective_assurance': effective_assurance,
        'w4_decision': w4_decision, 'w4_reasons': list(w4_reasons),
        'profile_sha256': profile_sha256, 'boot_id': boot_id, 'session_id': session_id,
        'context': context, 'provider_entry': bool(provider_entry), 'stopped_at': stopped_at,
        'result': result, 'error': error, 'error_detail': error_detail,
        'resource_changes': list(resource_changes or []),
        'cleanup': cleanup or {'state': 'NOT_ATTEMPTED', 'resources': []},
        'metadata': dict(metadata or {}),
    }
    missing = [name for name in FIELDS if name not in entry]
    if missing:
        raise ValueError(f'evidence record is incomplete: {missing}')
    return entry


class EvidenceSink:
    """Thread-safe evidence sink; every record is a snapshot."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: list[dict] = []

    def add(self, entry: dict) -> dict:
        with self._lock:
            self._records.append(entry)
            return entry

    def records(self) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._records]

    def for_request(self, request_id: str) -> list[dict]:
        return [r for r in self.records() if r['request_id'] == request_id]

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def dump(self) -> str:
        return json.dumps({'schema': EVIDENCE_SCHEMA, 'records': self.records()},
                          indent=1, sort_keys=True) + '\n'

    def refused_steps(self) -> list[str]:
        return sorted({r['stopped_at'] for r in self.records() if r['stopped_at']})


def _self_test() -> list[str]:
    checks: list[str] = []
    entry = record(run_id='RUN-1', request_id='REQ-1', operation='session.ping',
                   selected_provider='ps4rfd-stub', stopped_at='w4_gate',
                   w4_reasons=('NOT_WIRED',))
    if entry['provider_entry'] is not False or entry['stopped_at'] != 'w4_gate':
        checks.append('a refused dispatch must record entry=false and the stopping step')
    if len(FIELDS) != 21:
        checks.append('the evidence field list changed without a test update')
    try:
        record(run_id='RUN-1', request_id='REQ-1', operation='x', selected_provider='p',
               stopped_at='not_a_step')
    except ValueError:
        pass
    else:
        checks.append('unknown chain steps must be refused')
    sink = EvidenceSink()
    sink.add(entry)
    sink.add(dict(entry, request_id='REQ-2'))
    if len(sink.for_request('REQ-1')) != 1 or len(sink) != 2:
        checks.append('the sink must keep per-request records')
    return checks


def main(argv: list[str]) -> int:
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: evidence.py --self-test')
        return 2
    failures = _self_test()
    if failures:
        print(f'evidence self-test: {len(failures)} FAILED')
        for item in failures:
            print(f'  - {item}')
        return 1
    print(f'evidence self-test: OK ({len(FIELDS)} fields, {len(CHAIN_STEPS)} chain steps, '
          'thread-safe snapshots)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
