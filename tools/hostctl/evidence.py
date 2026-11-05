"""W8 evidence record (no secrets, no session keys, no key digests).

The record is what the W8 brief asks for, section by section, plus an explicit checklist
that maps every W8 success criterion to the field that proves it. Everything is derived
from what was actually observed; a value that was not observed stays ``null`` or
``UNRESOLVED``.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def canonical_sha256(obj) -> str:
    from core.canonical import canonical_bytes
    return sha256_bytes(canonical_bytes(obj))


class RunRecord:
    """Assembles the W8 evidence document."""

    def __init__(self, *, run_id: str, mode: str, repo: dict, payload: dict,
                 transport: dict) -> None:
        self.doc: dict = {
            'schema': 'ps4rf-w8-evidence/1',
            'run_id': run_id,
            'mode': mode,
            'started_utc': utc_now(),
            'ended_utc': None,
            'repo': repo,
            'payload': payload,
            'transport': transport,
            'wire_parity': None,
            'handshake': None,
            'attestation': None,
            'requests': [],
            'session': None,
            'bye': None,
            'health': None,
            'checks': [],
            'verdict': None,
            'notes': [],
        }

    # ------------------------------------------------------------------ helpers
    def note(self, text: str) -> None:
        self.doc['notes'].append(text)

    def check(self, name: str, ok: bool, detail: str = '') -> bool:
        self.doc['checks'].append({'name': name, 'ok': bool(ok), 'detail': detail})
        return bool(ok)

    def add_request(self, *, step, request: dict, response: dict, request_id: str,
                    route_expected: str, provider_entry: bool, provider_entry_detail: bool,
                    outcome_matches: bool, response_frame_sha256: str,
                    requested_utc: str, responded_utc: str) -> None:
        self.doc['requests'].append({
            'step': step,
            'request_id': request_id,
            'operation': request['body']['operation'],
            'arguments': request['body'].get('arguments', {}),
            'request_canonical_sha256': canonical_sha256(request),
            'response_canonical_sha256': canonical_sha256(response),
            'response_frame_sha256': response_frame_sha256,
            'status': response.get('status'),
            'result': response.get('result'),
            'error': response.get('error'),
            'cleanup': response.get('cleanup'),
            'route_expected': route_expected,
            'provider_entry': provider_entry,
            'provider_entry_false_in_detail': provider_entry_detail,
            'outcome_matches_frozen_route': outcome_matches,
            'requested_utc': requested_utc,
            'responded_utc': responded_utc,
        })

    def finalize(self, *, session: dict, bye: dict | None, health: dict | None,
                 verdict: str) -> dict:
        self.doc['session'] = session
        self.doc['bye'] = bye
        self.doc['health'] = health
        self.doc['verdict'] = verdict
        self.doc['ended_utc'] = utc_now()
        return self.doc


def write_evidence(doc: dict, out_dir: str | pathlib.Path) -> pathlib.Path:
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / 'w8-evidence.json'
    path.write_text(json.dumps(doc, indent=1, sort_keys=True) + '\n')
    return path
