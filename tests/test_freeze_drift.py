"""Gate checks for the freeze drift log (W0/D18).

The point-in-time manifest ``SHA256SUMS`` is never silently updated; every
divergence must be documented in ``FREEZE-DRIFT.md`` with file, old hash, new
hash, reason, phase, review reference and core impact. These tests read the log
(machine-readable JSON block) and fail when

* an entry is incomplete or has a malformed hash,
* a documented hash does not match reality,
* any manifest mismatch is undocumented (or a logged entry is stale),
* the manifest file itself changed (silent re-issue),
* a core file drifted without a core-impact flag and review reference.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DRIFT_LOG = REPO_ROOT / 'FREEZE-DRIFT.md'
MANIFEST = REPO_ROOT / 'SHA256SUMS'
HEX64 = re.compile(r'^[0-9a-f]{64}$')
REQUIRED_FIELDS = {'file', 'old_sha256', 'new_sha256', 'reason', 'phase',
                   'review_reference', 'core_impact'}


def _load_log() -> dict:
    text = DRIFT_LOG.read_text(encoding='utf-8')
    match = re.search(r'```json\n(.*?)\n```', text, re.S)
    assert match is not None, 'FREEZE-DRIFT.md must contain a machine-readable json block'
    return json.loads(match.group(1))


def _manifest_entries() -> dict:
    entries = {}
    for line in MANIFEST.read_text(encoding='utf-8').splitlines():
        parts = line.split()
        if len(parts) == 2:
            entries[parts[1].lstrip('*')] = parts[0]
    return entries


def _file_sha256(rel: str) -> str:
    return hashlib.sha256((REPO_ROOT / rel).read_bytes()).hexdigest()


def _actual_drift(entries: dict) -> set:
    drift = set()
    for rel, digest in entries.items():
        path = REPO_ROOT / rel
        if not path.exists() or _file_sha256(rel) != digest:
            drift.add(rel)
    return drift


def test_log_shape_and_required_fields():
    log = _load_log()
    assert log['entries'], 'drift log must not be empty'
    assert log['manifest']['path'] == 'SHA256SUMS'
    assert log['manifest']['freeze_tag'] == 'PS4RF-CORE-1.0-MOCK-READY'
    assert HEX64.match(log['manifest']['manifest_sha256'])
    for entry in log['entries']:
        missing = REQUIRED_FIELDS - set(entry)
        assert not missing, f'{entry.get("file")}: missing {sorted(missing)}'
        assert HEX64.match(entry['old_sha256']), entry['file']
        assert HEX64.match(entry['new_sha256']), entry['file']
        assert entry['old_sha256'] != entry['new_sha256'], entry['file']
        assert entry['core_impact'] in ('yes', 'no'), entry['file']
        assert entry['reason'].strip() and entry['phase'].strip(), entry['file']
        assert entry['review_reference'].strip(), entry['file']


def test_logged_hashes_match_reality():
    manifest = _manifest_entries()
    for entry in _load_log()['entries']:
        rel = entry['file']
        assert _file_sha256(rel) == entry['new_sha256'], f'{rel} does not match the log'
        assert rel in manifest, f'{rel} is not in the freeze manifest - not drift'
        assert manifest[rel] == entry['old_sha256'], f'{rel} old hash differs from the manifest'


def test_no_undocumented_drift():
    logged = {entry['file'] for entry in _load_log()['entries']}
    actual = _actual_drift(_manifest_entries())
    assert actual == logged, (
        f'undocumented drift: {sorted(actual - logged)}; stale entries: {sorted(logged - actual)}')


def test_manifest_is_not_silently_reissued():
    expected = _load_log()['manifest']['manifest_sha256']
    assert hashlib.sha256(MANIFEST.read_bytes()).hexdigest() == expected, (
        'SHA256SUMS changed - re-freeze requires the revision process (W0/D18)')


def test_core_drift_requires_revision_reference():
    log = _load_log()
    revisions = log.get('revisions') or {'R1 (D8, D9, D12)': 'docs/P4-W0-DECISIONS.md'}
    for entry in log['entries']:
        if entry['file'].startswith('core/'):
            assert entry['core_impact'] == 'yes', entry['file']
            assert entry['revision'] in revisions, entry['file']
            assert revisions[entry['revision']] in entry['review_reference'], entry['file']
            assert entry['review_reference'].strip(), entry['file']
        else:
            assert entry['core_impact'] == 'no', entry['file']


def test_revisions_map_names_every_core_revision():
    log = _load_log()
    revisions = log.get('revisions')
    assert revisions, 'the log must name each revision and its review document'
    for name, reference in revisions.items():
        assert name in log['revision'], f'{name} is not declared in the revision field'
        assert reference.startswith('docs/') and reference.endswith('.md'), name
    core_revisions = {entry['revision'] for entry in log['entries']
                      if entry['file'].startswith('core/')}
    assert core_revisions <= set(revisions), 'a core entry names an undeclared revision'
