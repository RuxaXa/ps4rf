#!/usr/bin/env python3
"""W13 — the research dataset: one immutable snapshot index per boot, bytes content-addressed.

The index (owner's §8) carries exactly: ``profile_sha256``, ``boot_id``, ``kbase``, ``read_run_id``,
``region``, ``offset``, ``length``, ``sha256``, ``timestamp``. The raw bytes live separately under
``blobs/<sha256>`` so a snapshot is a *pointer* to content, never a copy of it, and two identical
reads deduplicate to one blob and one index entry.

Determinism: the index is ordered by ``(boot_id, region, offset, offset+length, sha256)`` and
``index_sha256`` is the hash of that canonical body, so the same reads always yield the same index
hash -- independent of the order in which they arrived.

Sensitive-data rule: a read whose bytes look like a credential or a long printable run in a data
window is *flagged for manual review* and never auto-expanded (there is no auto-expansion anywhere in
W13, and a flag stops the offline pipeline from treating the snapshot as routine).
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from tools.profiles import regions as R                                    # noqa: E402
from tools.research import classification as C                             # noqa: E402

SCHEMA_INDEX = 'ps4rf.research.snapshot-index.v1'
SCHEMA_SNAPSHOT = 'ps4rf.research.snapshot.v1'
BLOB_DIR = 'blobs'
INDEX_FILE = 'index.json'

#: Patterns that make a snapshot "unexpectedly sensitive": never auto-expanded, flagged instead.
SENSITIVE_PATTERNS = (
    re.compile(rb'password', re.IGNORECASE),
    re.compile(rb'passwd', re.IGNORECASE),
    re.compile(rb'secret', re.IGNORECASE),
    re.compile(rb'api[_-]?key', re.IGNORECASE),
    re.compile(rb'[Aa]uthorization\s*:', re.IGNORECASE),
    re.compile(rb'BEGIN [A-Z ]*PRIVATE KEY', re.IGNORECASE),
    re.compile(rb'[A-Za-z0-9+/]{40,}={0,2}'),                 # a long base64-ish run
)


class DatasetError(Exception):
    """A dataset operation that must not proceed (fail closed)."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_dump(obj) -> str:
    return json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=False) + '\n'


def sensitive_hints(data: bytes) -> list[str]:
    """Names of the sensitive patterns a read window matches (empty for ordinary kernel bytes)."""
    return [pattern.pattern.decode('utf-8', 'replace') for pattern in SENSITIVE_PATTERNS
            if pattern.search(data)]


def snapshot_id(entry: dict) -> str:
    """Deterministic identity of a snapshot: the facts, not the arrival time."""
    core = {key: entry[key] for key in ('boot_id', 'profile_sha256', 'region', 'offset', 'length',
                                        'sha256')}
    return 'SNAP-' + hashlib.sha256(
        json.dumps(core, sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:16]


class ResearchDataset:
    """One directory per research dataset: ``index.json`` plus content-addressed ``blobs/``."""

    def __init__(self, root: str | pathlib.Path) -> None:
        self.root = pathlib.Path(root)

    # ------------------------------------------------------------------ blobs
    @property
    def blob_root(self) -> pathlib.Path:
        return self.root / BLOB_DIR

    def blob_path(self, digest: str) -> pathlib.Path:
        return self.blob_root / digest

    def put_bytes(self, data: bytes) -> str:
        """Store bytes content-addressed; returns the sha256 (idempotent)."""
        digest = sha256_bytes(data)
        path = self.blob_path(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if sha256_bytes(path.read_bytes()) != digest:
                raise DatasetError(f'{path}: existing blob does not hash to its name')
            return digest
        path.write_bytes(data)
        return digest

    def get_bytes(self, digest: str) -> bytes:
        path = self.blob_path(digest)
        if not path.exists():
            raise DatasetError(f'{digest}: no such blob')
        data = path.read_bytes()
        if sha256_bytes(data) != digest:
            raise DatasetError(f'{digest}: blob content does not match its name')
        return data

    # ------------------------------------------------------------------ index
    def index(self) -> dict:
        path = self.root / INDEX_FILE
        if not path.exists():
            return {'schema': SCHEMA_INDEX, 'snapshots': []}
        document = json.loads(path.read_text())
        if document.get('schema') != SCHEMA_INDEX:
            raise DatasetError(f'{path}: unknown schema {document.get("schema")!r}')
        return document

    def add_read(self, *, read_run_record: dict, region_name: str, kbase: int,
                 profile_sha256: str, boot_id: str, timestamp: str | None = None,
                 region_detail: dict | None = None) -> dict:
        """Add one read window of a read-run record. Fail closed on anything unapproved.

        The window must come from a real read-run record whose separation proof is intact, the
        region must be a W13 ``APPROVED_READ`` region, and the bytes must be the record's own.
        """
        problems = self._read_run_problems(read_run_record)
        if problems:
            raise DatasetError('; '.join(problems))
        classification = {row['region']: row['class']
                          for row in C.classification_matrix()['rows']}
        if classification.get(region_name) != C.CLASS_APPROVED_READ:
            raise DatasetError(f'{region_name}: not an APPROVED_READ region '
                               f'({classification.get(region_name)})')
        registry_region = R.regions().get(region_name)
        if registry_region is None:
            raise DatasetError(f'{region_name}: not registered')

        evidence = read_run_record.get('read_evidence') or {}
        if evidence.get('requested_region') != region_name:
            raise DatasetError(f'{region_name}: the read-run record read '
                               f'{evidence.get("requested_region")!r}')
        raw = bytes.fromhex(evidence.get('bytes_hex') or '')
        if not raw:
            raise DatasetError(f'{region_name}: the read-run record carries no bytes')
        if len(raw) != evidence.get('observed_length'):
            raise DatasetError(f'{region_name}: bytes and observed_length disagree')
        if registry_region.length is not None and len(raw) > registry_region.length:
            raise DatasetError(f'{region_name}: window larger than the registered region')

        digest = self.put_bytes(raw)
        if evidence.get('output_sha256') not in (None, digest):
            raise DatasetError(f'{region_name}: record sha256 {evidence.get("output_sha256")!r} '
                               f'does not match the bytes {digest}')
        entry = {
            'schema': SCHEMA_SNAPSHOT,
            'profile_sha256': profile_sha256,
            'boot_id': boot_id,
            'kbase': hex(kbase),
            'read_run_id': read_run_record.get('read_run_id'),
            'region': region_name,
            'locator': registry_region.locator,
            'rva': None if evidence.get('resolved_rva') in (None, 'UNMEASURED')
            else int(evidence['resolved_rva'], 16) if isinstance(evidence['resolved_rva'], str)
            else evidence['resolved_rva'],
            'offset': int(evidence.get('requested_offset', 0)),
            'length': len(raw),
            'sha256': digest,
            'timestamp': timestamp or read_run_record.get('timestamp')
            or time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'sensitive_hints': sensitive_hints(raw),
            'region_detail': region_detail or {'permissions': None, 'class': classification[region_name]},
        }
        entry['snapshot_id'] = snapshot_id(entry)
        entry['sensitive_review_required'] = bool(entry['sensitive_hints'])

        document = self.index()
        for existing in document['snapshots']:
            if existing['snapshot_id'] == entry['snapshot_id']:
                return {'added': False, 'deduplicated': True, 'snapshot': existing}
        document['snapshots'].append(entry)
        document['snapshots'].sort(key=lambda item: (item['boot_id'], item['region'],
                                                     item['offset'], item['length'],
                                                     item['sha256']))
        self._write_index(document)
        return {'added': True, 'deduplicated': False, 'snapshot': entry}

    # ------------------------------------------------------------------ integrity
    def _write_index(self, document: dict) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        body = {key: value for key, value in document.items() if key != 'index_sha256'}
        document['index_sha256'] = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        (self.root / INDEX_FILE).write_text(canonical_dump(document))

    def index_sha256(self) -> str:
        document = self.index()
        if 'index_sha256' not in document:
            return hashlib.sha256(
                json.dumps(document, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        body = {key: value for key, value in document.items() if key != 'index_sha256'}
        return hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def problems(self) -> list[str]:
        """Every invariant of the dataset, checked from disk."""
        problems: list[str] = []
        try:
            document = self.index()
        except DatasetError as exc:
            return [str(exc)]
        seen_ids, seen_tuples = set(), set()
        for entry in document['snapshots']:
            for field in ('profile_sha256', 'boot_id', 'kbase', 'read_run_id', 'region', 'offset',
                          'length', 'sha256', 'timestamp'):
                if field not in entry:
                    problems.append(f"{entry.get('snapshot_id')}: missing {field}")
            key = (entry['boot_id'], entry['region'], entry['offset'], entry['length'],
                   entry['sha256'])
            if key in seen_tuples:
                problems.append(f"{entry['snapshot_id']}: duplicate snapshot")
            seen_tuples.add(key)
            if entry['snapshot_id'] in seen_ids:
                problems.append(f"{entry['snapshot_id']}: duplicate id")
            seen_ids.add(entry['snapshot_id'])
            blob = self.blob_path(entry['sha256'])
            if not blob.exists():
                problems.append(f"{entry['snapshot_id']}: blob {entry['sha256'][:12]}… missing")
            elif sha256_bytes(blob.read_bytes()) != entry['sha256']:
                problems.append(f"{entry['snapshot_id']}: blob does not hash to its name")
            if entry.get('sensitive_review_required') and not entry.get('sensitive_hints'):
                problems.append(f"{entry['snapshot_id']}: flagged without a hint")
        if 'index_sha256' in document and self.index_sha256() != document['index_sha256']:
            problems.append('index_sha256 does not match the index body')
        return problems

    @staticmethod
    def _read_run_problems(read_run_record: dict) -> list[str]:
        problems = []
        if not isinstance(read_run_record, dict):
            return ['the read-run record is not a document']
        if read_run_record.get('outcome') != 'READ':
            problems.append(f"the read-run outcome is {read_run_record.get('outcome')!r}, not READ")
        if read_run_record.get('provider_entries') != 1:
            problems.append('the read-run record does not record exactly one provider entry')
        separation = read_run_record.get('run_separation') or {}
        if not separation.get('separated') or not separation.get('run_ids_distinct') \
                or not separation.get('session_ids_distinct'):
            problems.append('the read-run record does not prove the run separation')
        return problems


def _self_test() -> list[str]:
    import tempfile
    checks: list[str] = []
    record = {
        'read_run_id': 'RUN-selftest', 'outcome': 'READ', 'provider_entries': 1,
        'run_separation': {'separated': True, 'run_ids_distinct': True,
                           'session_ids_distinct': True},
        'read_evidence': {'requested_region': 'amd_iommu', 'requested_offset': 0,
                          'observed_length': 4, 'bytes_hex': '414d4420',
                          'output_sha256': sha256_bytes(b'AMD '), 'resolved_rva': '0x7ce9e9'},
    }
    with tempfile.TemporaryDirectory() as tmp:
        dataset = ResearchDataset(tmp)
        first = dataset.add_read(read_run_record=record, region_name='amd_iommu',
                                 kbase=0xffffffff998f4000, profile_sha256='a' * 64,
                                 boot_id='BOOT-selftest', timestamp='2026-10-06T00:00:00Z')
        second = dataset.add_read(read_run_record=record, region_name='amd_iommu',
                                  kbase=0xffffffff998f4000, profile_sha256='a' * 64,
                                  boot_id='BOOT-selftest', timestamp='2026-10-06T00:00:01Z')
        if not first['added'] or second['added'] or not second['deduplicated']:
            checks.append('duplicate snapshot was not deduplicated')
        checks += dataset.problems()
        if dataset.index_sha256() != dataset.index()['index_sha256']:
            checks.append('index hash is not stable')
        try:
            dataset.add_read(read_run_record=record, region_name='aperture_global',
                             kbase=0xffffffff998f4000, profile_sha256='a' * 64,
                             boot_id='BOOT-selftest')
            checks.append('a STRUCTURAL_ONLY region was accepted into the dataset')
        except DatasetError:
            pass
        if not sensitive_hints(b'password=hunter2'):
            checks.append('the sensitive scan misses a password marker')
        if sensitive_hints(b'\x55\x48\x89\xe5'):
            checks.append('the sensitive scan flags ordinary machine code')
    return checks


def main(argv: list[str]) -> int:                                          # pragma: no cover
    if '--self-test' in argv:
        problems = _self_test()
        if problems:
            print('dataset self-test: FAILED')
            for problem in problems:
                print(f'  - {problem}')
            return 1
        print('dataset self-test: OK (content-addressed, dedup, deterministic index, refusals)')
        return 0
    print('usage: dataset.py --self-test')
    return 0


if __name__ == '__main__':                                                 # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
