#!/usr/bin/env python3
"""PS4RF P4/W5 profile loader: read, validate, hash-check, expose facts.

The loader is the only entrance for profile documents: it validates the schema (key
allowlist, mandatory fields, evidence rules), recomputes the canonical hash and
refuses any document whose declared hash does not match. A profile is a *fact store* -
loading it grants nothing, and an unresolved or fixture profile stays fail-closed in
the gate.

Usage::

    python tools/profiles/loader.py path/to/profile.json          # validate + summary
    python tools/profiles/loader.py --self-test

Exit codes: 0 = valid/consistent, 1 = invalid profile or self-test failed, 2 = usage.
"""

from __future__ import annotations

import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from tools.profiles.schema import (  # noqa: E402
    SCHEMA_ID, canonical_profile_sha256, empty_profile, evidence_backed,
    unresolved_facts, validate_profile,
)
from tools.primitive_iface.gate import privilege_gated_ops  # noqa: E402  (W17F: no count literal)


class ProfileLoadError(Exception):
    def __init__(self, errors: list[str]):
        super().__init__('; '.join(errors))
        self.errors = errors


def load_profile(path: str | pathlib.Path) -> dict:
    """Load and validate a profile document (fail-closed)."""
    p = pathlib.Path(path)
    try:
        doc = json.loads(p.read_text(encoding='utf-8'))
    except Exception as exc:  # noqa: BLE001 - reported as a load failure
        raise ProfileLoadError([f'{p.name}: not readable as JSON ({exc})']) from exc
    errors = validate_profile(doc)
    if errors:
        raise ProfileLoadError(errors)
    return doc


def profile_summary(doc: dict) -> dict:
    return {
        'profile_id': doc.get('profile_id'),
        'profile_version': doc.get('profile_version'),
        'schema': doc.get('schema'),
        'fixture': doc.get('fixture'),
        'canonical_sha256': canonical_profile_sha256(doc),
        'evidence_backed': evidence_backed(doc),
        'unresolved': unresolved_facts(doc),
        'gated_operations': len(doc.get('operation_policy') or {}),
    }


def write_profile(doc: dict, path: str | pathlib.Path, *, stamp: bool = True) -> str:
    """Write a profile with its computed canonical hash; returns the hash."""
    body = dict(doc)
    if stamp:
        body['canonical_sha256'] = canonical_profile_sha256(body)
    errors = validate_profile(body)
    if errors:
        raise ProfileLoadError(errors)
    pathlib.Path(path).write_text(json.dumps(body, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    return body['canonical_sha256']


def _self_test() -> list[str]:
    checks: list[str] = []
    doc = empty_profile('fw-selftest', fixture=True)
    summary = profile_summary(doc)
    if summary['schema'] != SCHEMA_ID:
        checks.append('summary must report the schema id')
    if summary['evidence_backed']:
        checks.append('a placeholder profile must not be evidence-backed')
    if summary['gated_operations'] != len(privilege_gated_ops()):
        checks.append('placeholder must cover exactly the gated operations '
                      f'(expected {len(privilege_gated_ops())}, got {summary["gated_operations"]})')
    stamped = dict(doc, canonical_sha256=canonical_profile_sha256(doc))
    if validate_profile(stamped):
        checks.append('a correctly stamped profile must validate')
    broken = dict(stamped, canonical_sha256='0' * 64)
    if not validate_profile(broken):
        checks.append('a wrong declared hash must be refused')
    try:
        load_profile(REPO_ROOT / 'does-not-exist.json')
    except ProfileLoadError:
        pass
    else:
        checks.append('missing file must raise ProfileLoadError')
    return checks


def main(argv: list[str]) -> int:
    args = [a for a in argv if a != '--self-test']
    if '--self-test' in argv:
        failures = _self_test()
        if failures:
            print(f'loader self-test: {len(failures)} FAILED')
            for item in failures:
                print(f'  - {item}')
            return 1
        print('loader self-test: OK (validate, hash-check, fail-closed)')
        return 0
    if len(args) != 1:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: loader.py <profile.json> | --self-test')
        return 2
    try:
        doc = load_profile(args[0])
    except ProfileLoadError as exc:
        print(f'PROFILE INVALID ({len(exc.errors)})')
        for err in exc.errors:
            print(f'  - {err}')
        return 1
    summary = profile_summary(doc)
    print(f'PROFILE OK {summary["profile_id"]} v{summary["profile_version"]}')
    print(f'  canonical_sha256: {summary["canonical_sha256"]}')
    print(f'  fixture: {summary["fixture"]} | evidence_backed: {summary["evidence_backed"]}')
    print(f'  gated operations: {summary["gated_operations"]}')
    print(f'  unresolved facts: {len(summary["unresolved"])}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
