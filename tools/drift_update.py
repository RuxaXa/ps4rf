#!/usr/bin/env python3
"""Refresh the ``new_sha256`` pins in FREEZE-DRIFT.md from the working tree (W0/D18).

The drift log keeps human-written reasons and phase/review references; only the
"new hash" column is derived data. This tool recomputes it, verifies that every
recorded old hash still matches the point-in-time manifest, and rewrites the
machine-readable block in place. It never touches the manifest itself and never
adds or removes entries - new drift must be documented by hand, on purpose.

Usage::

    python tools/drift_update.py            # refresh pins, report changes
    python tools/drift_update.py --check    # exit 1 if pins are stale (CI/gate)

Exit codes: 0 = up to date (or refreshed), 1 = stale in --check mode or a
validation error, 2 = usage/IO error.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DRIFT_LOG = REPO_ROOT / 'FREEZE-DRIFT.md'
MANIFEST = REPO_ROOT / 'SHA256SUMS'
BLOCK = re.compile(r'```json\n(.*?)\n```', re.S)


def _sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest_entries() -> dict:
    entries = {}
    for line in MANIFEST.read_text(encoding='utf-8').splitlines():
        parts = line.split()
        if len(parts) == 2:
            entries[parts[1].lstrip('*')] = parts[0]
    return entries


def main(argv: list) -> int:
    check_only = '--check' in argv[1:]
    if [a for a in argv[1:] if a != '--check']:
        print((__doc__ or '').strip())
        return 2

    text = DRIFT_LOG.read_text(encoding='utf-8')
    match = BLOCK.search(text)
    if match is None:
        print('FREEZE-DRIFT.md: json block not found')
        return 2
    log = json.loads(match.group(1))
    manifest = _manifest_entries()

    errors = []
    changed = []
    for entry in log['entries']:
        rel = entry['file']
        path = REPO_ROOT / rel
        if not path.exists():
            errors.append(f'{rel}: file missing')
            continue
        if rel not in manifest:
            errors.append(f'{rel}: not in the freeze manifest - not drift, remove the entry')
            continue
        if manifest[rel] != entry['old_sha256']:
            errors.append(f'{rel}: old hash no longer matches the manifest')
            continue
        actual = _sha256(path)
        if actual != entry['new_sha256']:
            changed.append((rel, entry['new_sha256'][:12], actual[:12]))
            entry['new_sha256'] = actual

    if errors:
        print(f'FREEZE-DRIFT: {len(errors)} error(s)')
        for error in errors:
            print(f'  - {error}')
        return 1

    if not changed:
        print(f'FREEZE-DRIFT: up to date ({len(log["entries"])} entries)')
        return 0

    print(f'FREEZE-DRIFT: {len(changed)} pin(s) {"stale" if check_only else "refreshed"}')
    for rel, old_prefix, new_prefix in changed:
        print(f'  - {rel}: {old_prefix}... -> {new_prefix}...')
    if check_only:
        return 1

    rendered = json.dumps(log, indent=2)
    DRIFT_LOG.write_text(text[:match.start(1)] + rendered + text[match.end(1):],
                         encoding='utf-8')
    print('FREEZE-DRIFT.md updated (manifest untouched)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
