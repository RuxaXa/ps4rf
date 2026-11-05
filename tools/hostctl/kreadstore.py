#!/usr/bin/env python3
"""W12 verification-evidence store: the persisted, hash-frozen ``VerificationEvidence``.

The W12 two-phase flow runs as two uploads and two sessions. RUN A produces the first
``VerificationEvidence`` and persists it here; RUN B loads it again, **rehashes it** and only
then derives a session-scoped capability record from it. This module owns exactly that
persisted half:

* the record shape (schema ``ps4rf.kread.verification-evidence.v1``) and the canonical hash
  rule: ``evidence_sha256`` is the sha256 of the JCS-canonicalised record *without* that
  field -- the same canonicalizer the wire and the profile hashes use
  (``core.canonical.canonical_bytes``), so a post-hoc edit of any field (observed bytes,
  profile hash, run id, ...) is detected the moment the record is loaded;
* the load discipline: a record is only accepted when it parses, carries every mandated
  field and its ``evidence_sha256`` matches the recomputed canonical hash. A bare
  ``verified: true`` JSON flag is **never sufficient** -- a document whose assurance is a
  flag instead of the mandated content is refused with :data:`STORE_BARE_FLAG`, and a flag
  alongside otherwise complete content is only the informational extra, never the proof;
* the read-run record (schema ``ps4rf.kread.read-run.v1``) that phase B writes after its
  generic bounded read; it carries all four run/session ids of the flow, so the run
  separation (``verification_run_id != read_run_id`` and
  ``verification_session_id != read_session_id``) is visible in the persisted evidence and
  not only in a transient log.

Determinism: records are written as ``json.dumps(..., indent=1, sort_keys=True) + "\\n"``
like every other evidence document in this repository, and the canonical hash is computed
over the *parsed* object, so byte-level re-formatting does not change the hash while any
content change does. No timestamps are added here (the caller records time in its own run
record).

Store layout (ids are validated as filename-safe before any path is built -- no traversal)::

    <root>/verification/<verification_run_id>.json
    <root>/read-runs/<read_run_id>.json

Usage::

    python tools/hostctl/kreadstore.py --self-test
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:                       # pragma: no cover - import bootstrap
    sys.path.insert(0, str(REPO_ROOT))

from core.canonical import canonical_bytes                                # noqa: E402

SCHEMA_VERIFICATION = 'ps4rf.kread.verification-evidence.v1'
SCHEMA_READ_RUN = 'ps4rf.kread.read-run.v1'
#: W13 one-shot marker: a research read release is consumed exactly once (see the policy text).
SCHEMA_RELEASE_CONSUMPTION = 'ps4rf.w13.release-consumption.v1'

EVIDENCE_HASH_FIELD = 'evidence_sha256'
RECORD_HASH_FIELD = 'record_sha256'

#: every field the persisted VerificationEvidence must carry (the accepted W12 contract)
VERIFICATION_REQUIRED_FIELDS: tuple[str, ...] = (
    'schema',                       # ps4rf.kread.verification-evidence.v1
    'verification_run_id',          # the host verification run of phase A
    'verification_session_id',      # the session phase A ran in (the verification session)
    'operation',                    # verify.kernel.read
    'outcome',                      # PASS (only a passing verification is persisted)
    'capability',                   # kernel.read
    'provider',                     # ps4rfd-kread-privileged
    'provider_type',                # NATIVE
    'profile_sha256',               # the current real profile's canonical hash
    'boot_id',                      # the boot the verification is valid for
    'context',                      # JAILBROKEN_PROCESS
    'scope',                        # SESSION
    'region',                       # image_elf
    'offset',                       # 0
    'length',                       # 16
    'expected_bytes_hex',           # the pinned expectation
    'expected_sha256',
    'observed_bytes_hex',           # the host-re-derived observation
    'observed_sha256',
    'read_run_id',                  # the bootstrap read run the verification verified
    'read_session_id',              # its session (phase A; phase B must use a NEW one)
    EVIDENCE_HASH_FIELD,            # canonical hash of this object
)

#: the read-run record phase B persists (schema, ids, request, evidence and the proof flags)
READ_RUN_REQUIRED_FIELDS: tuple[str, ...] = (
    'schema',                       # ps4rf.kread.read-run.v1
    'read_run_id',                  # the generic read run (phase B)
    'read_session_id',              # the session phase B ran in (a NEW session)
    'verification_run_id',          # from the loaded verification evidence
    'verification_session_id',      # from the loaded verification evidence
    'verification_evidence_sha256',  # the rehashed record phase A persisted
    'request',                      # the kernel.read decision input (region/offset/length)
    'read_evidence_sha256',         # canonical hash of the assembled read evidence
    'run_separation',               # all four ids + the checked inequalities
    'provider_entries',             # exactly 1 for the read phase
    'outcome',                      # READ
    RECORD_HASH_FIELD,              # canonical hash of this object
)

# --- refusal vocabulary -------------------------------------------------------------------
STORE_MISSING = 'STORE_MISSING'
STORE_UNREADABLE = 'STORE_UNREADABLE'
STORE_INVALID = 'STORE_INVALID'
STORE_REHASH_MISMATCH = 'STORE_REHASH_MISMATCH'
STORE_BARE_FLAG = 'STORE_BARE_FLAG'
STORE_ID_INVALID = 'STORE_ID_INVALID'
STORE_CONFLICT = 'STORE_CONFLICT'
#: A consumption record that does not rehash to its own id, names another release, or is not a
#: consumption record at all. Fail closed: an unreadable consumption state is never "not consumed".
W13_RELEASE_CONSUMPTION_INVALID = 'W13_RELEASE_CONSUMPTION_INVALID'

STORE_REASONS = (STORE_MISSING, STORE_UNREADABLE, STORE_INVALID, STORE_REHASH_MISMATCH,
                 STORE_BARE_FLAG, STORE_ID_INVALID, STORE_CONFLICT,
                 W13_RELEASE_CONSUMPTION_INVALID)

_HEX64 = re.compile(r'^[0-9a-fA-F]{64}$')
_HEX_BYTES = re.compile(r'^(?:[0-9a-fA-F]{2})+$')
_RUN_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')


class StoreError(Exception):
    """Fail-closed store refusal: ``reason`` is the machine code, ``detail`` human context."""

    def __init__(self, reason: str, detail: str = '') -> None:
        super().__init__(f'{reason}: {detail}' if detail else reason)
        self.reason = reason
        self.detail = detail


def canonical_evidence_sha256(evidence: dict) -> str:
    """Canonical hash of a verification record: JCS bytes without the hash field itself."""
    body = {key: value for key, value in evidence.items() if key != EVIDENCE_HASH_FIELD}
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def canonical_record_sha256(record: dict) -> str:
    """Canonical hash of a read-run record: JCS bytes without the hash field itself."""
    body = {key: value for key, value in record.items() if key != RECORD_HASH_FIELD}
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


#: The one-shot policy, written into every consumption record so the semantics cannot drift.
CONSUMPTION_POLICY = ('the release is consumed at the moment the W12 provider entry happens (the '
                      'read is granted exactly once); a validation, preflight or gate refusal '
                      'before that consumes nothing; a retry with the same release_id is refused '
                      'with W13_RELEASE_ALREADY_CONSUMED')

_CONSUMPTION_REQUIRED = ('schema', 'release_id', 'release_sha256', 'approval_sha256',
                         'profile_sha256', 'boot_id', 'read_run_id', 'read_session_id', 'consumed',
                         'consumed_at', 'policy', RECORD_HASH_FIELD)


def consumption_record_sha256(record: dict) -> str:
    """Canonical hash of a consumption record: JCS bytes without the hash field itself."""
    body = {key: value for key, value in record.items() if key != RECORD_HASH_FIELD}
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def build_consumption_record(*, release_id: str, release_sha256: str, approval_sha256: str,
                             profile_sha256: str, boot_id: str, read_run_id: str,
                             read_session_id: str) -> dict:
    """Build the write-once consumption record for one release (never a capability, never a grant)."""
    record = {'schema': SCHEMA_RELEASE_CONSUMPTION, 'release_id': release_id,
              'release_sha256': release_sha256, 'approval_sha256': approval_sha256,
              'profile_sha256': profile_sha256, 'boot_id': boot_id, 'read_run_id': read_run_id,
              'read_session_id': read_session_id, 'consumed': True,
              'consumed_at': 'provider_entry', 'policy': CONSUMPTION_POLICY}
    record[RECORD_HASH_FIELD] = consumption_record_sha256(record)
    return record


def consumption_problems(record: dict) -> list[str]:
    """Structural problems of a consumption record (policy-free, like the other shape checks)."""
    problems: list[str] = []
    if not isinstance(record, dict):
        return ['the consumption record is not a document']
    for field in _CONSUMPTION_REQUIRED:
        if field not in record:
            problems.append(f'{field} is missing')
    if record.get('schema') != SCHEMA_RELEASE_CONSUMPTION:
        problems.append(f'schema {record.get("schema")!r} is not {SCHEMA_RELEASE_CONSUMPTION!r}')
    for field in ('release_id', 'read_run_id', 'read_session_id'):
        if field in record and (not isinstance(record[field], str) or not record[field]):
            problems.append(f'{field} must be a non-empty string')
    for field in ('release_sha256', 'approval_sha256', 'profile_sha256'):
        value = record.get(field)
        if not isinstance(value, str) or not _HEX64.fullmatch(value):
            problems.append(f'{field} must be a sha256 hex digest')
    if record.get('consumed') is not True:
        problems.append('consumed must be true')
    if record.get('consumed_at') != 'provider_entry':
        problems.append("consumed_at must be 'provider_entry'")
    if record.get('policy') != CONSUMPTION_POLICY:
        problems.append('the consumption policy text is not the frozen one')
    return problems


def consumption_rejection_reason(record) -> str | None:
    """The one refusal reason for a consumption record, or ``None`` when it is acceptable."""
    if not isinstance(record, dict):
        return W13_RELEASE_CONSUMPTION_INVALID
    if consumption_problems(record):
        return W13_RELEASE_CONSUMPTION_INVALID
    if record[RECORD_HASH_FIELD] != consumption_record_sha256(record):
        return W13_RELEASE_CONSUMPTION_INVALID
    return None


def _missing_fields(evidence: dict, required: tuple[str, ...]) -> list[str]:
    return [field for field in required if field not in evidence]


def _shape_problems(evidence: dict, required: tuple[str, ...]) -> list[str]:
    """Structural checks shared by both record kinds (types only, never policy)."""
    problems: list[str] = []
    for field in ('region', 'operation', 'capability', 'provider', 'provider_type', 'context',
                  'scope', 'boot_id', 'profile_sha256'):
        if field in evidence and not isinstance(evidence[field], str):
            problems.append(f'{field} must be a string')
    for field in ('verification_run_id', 'read_run_id', 'verification_session_id',
                  'read_session_id'):
        if field in evidence and (not isinstance(evidence[field], str) or not evidence[field]):
            problems.append(f'{field} must be a non-empty string')
    for field in ('offset', 'length'):
        if field in evidence and (isinstance(evidence[field], bool)
                                  or not isinstance(evidence[field], int)):
            problems.append(f'{field} must be an integer')
    return problems


def verification_rejection_reason(evidence) -> str | None:
    """The one refusal reason for a verification record, or ``None`` when it is acceptable.

    Order matters: a document whose only assurance is a ``verified`` flag and which lacks the
    mandated content is reported as :data:`STORE_BARE_FLAG` (the flag is never sufficient),
    a missing/garbled hash as :data:`STORE_INVALID`, and a content change that no longer
    matches the stored hash as :data:`STORE_REHASH_MISMATCH`.
    """
    if not isinstance(evidence, dict):
        return STORE_INVALID
    missing = _missing_fields(evidence, VERIFICATION_REQUIRED_FIELDS)
    if missing:
        # a `verified: true` flag is a W8-style marker, not verification content: a document
        # that leans on it must never pass as evidence
        if evidence.get('verified') is True:
            return STORE_BARE_FLAG
        return STORE_INVALID
    if evidence.get('schema') != SCHEMA_VERIFICATION:
        return STORE_INVALID
    if evidence.get('outcome') != 'PASS':
        return STORE_INVALID
    if 'verified' in evidence and evidence.get('verified') is not True:
        return STORE_INVALID
    if _shape_problems(evidence, VERIFICATION_REQUIRED_FIELDS):
        return STORE_INVALID
    if not isinstance(evidence.get('expected_bytes_hex'), str) \
            or not _HEX_BYTES.fullmatch(evidence['expected_bytes_hex']):
        return STORE_INVALID
    if not isinstance(evidence.get('observed_bytes_hex'), str) \
            or not _HEX_BYTES.fullmatch(evidence['observed_bytes_hex']):
        return STORE_INVALID
    for field in ('expected_sha256', 'observed_sha256', 'profile_sha256'):
        if not isinstance(evidence.get(field), str) or not _HEX64.fullmatch(evidence[field]):
            return STORE_INVALID
    sha = evidence.get(EVIDENCE_HASH_FIELD)
    if not isinstance(sha, str) or not _HEX64.fullmatch(sha):
        return STORE_INVALID
    if sha != canonical_evidence_sha256(evidence):
        return STORE_REHASH_MISMATCH
    return None


def verification_problems(evidence) -> list[str]:
    """Human-readable list form of :func:`verification_rejection_reason` (empty == valid)."""
    reason = verification_rejection_reason(evidence)
    if reason is None:
        return []
    if reason == STORE_REHASH_MISMATCH:
        return [f'{reason}: the stored {EVIDENCE_HASH_FIELD} does not match the recomputed '
                'canonical hash']
    if reason == STORE_BARE_FLAG:
        return [f'{reason}: a bare `verified: true` flag is never sufficient; the mandated '
                'verification content is missing']
    return [f'{reason}: the record is not a valid {SCHEMA_VERIFICATION} document']


def read_run_rejection_reason(record) -> str | None:
    """The refusal reason for one read-run record, or ``None`` (structure + rehash only)."""
    if not isinstance(record, dict):
        return STORE_INVALID
    missing = _missing_fields(record, READ_RUN_REQUIRED_FIELDS)
    if missing:
        return STORE_INVALID
    if record.get('schema') != SCHEMA_READ_RUN:
        return STORE_INVALID
    if record.get('outcome') != 'READ':
        return STORE_INVALID
    for field in ('read_run_id', 'read_session_id', 'verification_run_id',
                  'verification_session_id', 'verification_evidence_sha256',
                  'read_evidence_sha256'):
        if not isinstance(record.get(field), str) or not record[field]:
            return STORE_INVALID
    if not _HEX64.fullmatch(record['verification_evidence_sha256']) \
            or not _HEX64.fullmatch(record['read_evidence_sha256']):
        return STORE_INVALID
    if not isinstance(record.get('request'), dict) or not isinstance(
            record.get('run_separation'), dict):
        return STORE_INVALID
    if not isinstance(record.get('provider_entries'), int) \
            or isinstance(record.get('provider_entries'), bool):
        return STORE_INVALID
    sha = record.get(RECORD_HASH_FIELD)
    if not isinstance(sha, str) or not _HEX64.fullmatch(sha):
        return STORE_INVALID
    if sha != canonical_record_sha256(record):
        return STORE_REHASH_MISMATCH
    return None


class VerificationEvidenceStore:
    """Filesystem store for the two W12 evidence kinds. Offline; no locking, no network."""

    def __init__(self, root: str | pathlib.Path) -> None:
        self.root = pathlib.Path(root)

    # ---------------------------------------------------------------- paths
    def verification_path(self, verification_run_id: str) -> pathlib.Path:
        return self._path('verification', verification_run_id)

    def read_run_path(self, read_run_id: str) -> pathlib.Path:
        return self._path('read-runs', read_run_id)

    def _path(self, kind: str, run_id: str) -> pathlib.Path:
        if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id) or '..' in run_id:
            raise StoreError(STORE_ID_INVALID,
                             f'{run_id!r} is not a filename-safe run id '
                             '(letters, digits, dot, underscore, dash)')
        return self.root / kind / f'{run_id}.json'

    # ---------------------------------------------------------------- write
    def _write(self, path: pathlib.Path, doc: dict) -> pathlib.Path:
        payload = json.dumps(doc, indent=1, sort_keys=True) + '\n'
        if path.exists():
            if path.read_text() == payload:
                return path                    # idempotent re-store of the identical record
            raise StoreError(STORE_CONFLICT, f'{path} exists with different content')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload)
        return path

    def store_verification(self, evidence: dict) -> pathlib.Path:
        """Validate and persist one VerificationEvidence record; return its path."""
        reason = verification_rejection_reason(evidence)
        if reason is not None:
            raise StoreError(reason, '; '.join(verification_problems(evidence)))
        return self._write(self.verification_path(evidence['verification_run_id']), evidence)

    def store_read_run(self, record: dict) -> pathlib.Path:
        """Validate and persist one read-run record; return its path."""
        reason = read_run_rejection_reason(record)
        if reason is not None:
            raise StoreError(reason, f'the record is not a valid {SCHEMA_READ_RUN} document')
        return self._write(self.read_run_path(record['read_run_id']), record)

    def release_consumption_path(self, release_id: str) -> pathlib.Path:
        """Where the one-shot marker of a W13 release lives (write-once, like every record)."""
        return self._path('releases', release_id)

    def store_release_consumption(self, record: dict) -> pathlib.Path:
        """Persist the consumption marker of one release; refuse on any deviation."""
        reason = consumption_rejection_reason(record)
        if reason is not None:
            raise StoreError(reason, '; '.join(consumption_problems(record)))
        return self._write(self.release_consumption_path(record['release_id']), record)

    def load_release_consumption(self, release_id: str) -> dict | None:
        """The consumption marker of one release, rehashed on load, or ``None`` when unconsumed.

        A marker that does not rehash (edited after it was written) or that names another release is
        refused with :data:`W13_RELEASE_CONSUMPTION_INVALID` -- never silently treated as
        'not consumed'.
        """
        path = self.release_consumption_path(release_id)
        if not path.exists():
            return None
        doc = self._load(path)
        reason = consumption_rejection_reason(doc)
        if reason is not None:
            raise StoreError(reason, f'{path}: ' + '; '.join(consumption_problems(doc)))
        if doc.get('release_id') != release_id:
            raise StoreError(W13_RELEASE_CONSUMPTION_INVALID,
                             f'{path} names release {doc.get("release_id")!r}')
        return doc

    def release_is_consumed(self, release_id: str) -> bool:
        """True when this release was already used for a provider entry (fail closed on damage)."""
        return self.load_release_consumption(release_id) is not None

    # ---------------------------------------------------------------- read
    def _load(self, path: pathlib.Path) -> dict:
        if not path.exists():
            raise StoreError(STORE_MISSING, f'no record at {path}')
        try:
            doc = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            raise StoreError(STORE_UNREADABLE, f'{path}: {type(exc).__name__}: {exc}') from exc
        return doc

    def load_verification(self, verification_run_id: str) -> dict:
        """Load one verification record, rehash it and return it; refuse on any deviation.

        The rehash is the load contract: the parsed object must carry ``evidence_sha256``
        and it must equal the recomputed canonical hash, so a record edited after it was
        written (or a bare ``verified: true`` document) never reaches the caller.
        """
        doc = self._load(self.verification_path(verification_run_id))
        reason = verification_rejection_reason(doc)
        if reason is not None:
            raise StoreError(reason, '; '.join(verification_problems(doc)))
        return doc

    def load_read_run(self, read_run_id: str) -> dict:
        doc = self._load(self.read_run_path(read_run_id))
        reason = read_run_rejection_reason(doc)
        if reason is not None:
            raise StoreError(reason, f'the record is not a valid {SCHEMA_READ_RUN} document')
        return doc

    def load_verification_by_sha256(self, evidence_sha256: str) -> dict:
        """Load the ONE stored verification record addressed by its canonical evidence hash.

        This is the address the derivation gate uses (W12-A3): the caller names the hash, never a
        path or an object, so a prepared document cannot be slipped in. An address is honoured
        only when the record's file name, its run id and its canonical hash all agree:

        * a body that no longer matches its stored hash      -> :data:`STORE_REHASH_MISMATCH`;
        * a copy of a record under another file name          -> :data:`STORE_ID_INVALID`;
        * a record re-hashed under a new name (new run id)    -> :data:`STORE_MISSING` for the old
          address (the old hash no longer exists in the store);
        * several files claiming the same hash                -> :data:`STORE_CONFLICT`.
        """
        if not isinstance(evidence_sha256, str) or not _HEX64.fullmatch(evidence_sha256):
            raise StoreError(STORE_ID_INVALID, f'{evidence_sha256!r} is not a sha256 address')
        hits: list[dict] = []
        for path in self.verification_paths():
            doc = self._load(path)
            claims = doc.get(EVIDENCE_HASH_FIELD) if isinstance(doc, dict) else None
            reason = verification_rejection_reason(doc)
            if reason is not None:
                if claims == evidence_sha256:                  # the addressed record is invalid
                    raise StoreError(reason, '; '.join(verification_problems(doc)))
                continue
            if path.stem != doc.get('verification_run_id'):
                if claims == evidence_sha256:
                    raise StoreError(STORE_ID_INVALID,
                                     f'{path} does not carry its own run id '
                                     f'({doc.get("verification_run_id")!r}): a renamed copy is '
                                     'never addressable')
                continue
            if claims == evidence_sha256:
                hits.append(doc)
        if not hits:
            raise StoreError(STORE_MISSING,
                             f'no stored verification record with evidence sha256 '
                             f'{evidence_sha256}')
        if len(hits) > 1:
            raise StoreError(STORE_CONFLICT,
                             f'{len(hits)} stored records claim evidence sha256 '
                             f'{evidence_sha256}')
        return hits[0]

    # ---------------------------------------------------------------- listing
    def verification_paths(self) -> list[pathlib.Path]:
        """Every stored verification record path, in file-name order."""
        directory = self.root / 'verification'
        if not directory.is_dir():
            return []
        return sorted(path for path in directory.glob('*.json') if path.is_file())

    def verification_run_ids(self) -> list[str]:
        return sorted(path.stem for path in (self.root / 'verification').glob('*.json')) \
            if (self.root / 'verification').is_dir() else []

    def read_run_ids(self) -> list[str]:
        return sorted(path.stem for path in (self.root / 'read-runs').glob('*.json')) \
            if (self.root / 'read-runs').is_dir() else []


# --- self test -----------------------------------------------------------------------------
def _self_test() -> list[str]:
    """Deterministic offline checks: rehash detection, bare-flag refusal, id hygiene."""
    import tempfile

    problems: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        store = VerificationEvidenceStore(tmp)
        evidence = _sample_evidence()
        path = store.store_verification(evidence)
        if not path.exists():
            problems.append('a valid record was not written')
        loaded = store.load_verification(evidence['verification_run_id'])
        if loaded != evidence:
            problems.append('the loaded record differs from the stored one')
        # a post-hoc content edit must break the rehash
        tampered = dict(evidence, observed_bytes_hex='00' * 16)
        try:
            store.store_verification(tampered)
            problems.append('a tampered record was stored under a second id')
        except StoreError as exc:
            if exc.reason != STORE_REHASH_MISMATCH:
                problems.append(f'tamper detected as {exc.reason}, not {STORE_REHASH_MISMATCH}')
        # a bare verified flag is never sufficient
        try:
            store.store_verification({'verified': True, 'outcome': 'PASS'})
            problems.append('a bare verified flag was accepted')
        except StoreError as exc:
            if exc.reason != STORE_BARE_FLAG:
                problems.append(f'bare flag refused as {exc.reason}, not {STORE_BARE_FLAG}')
        # writing a tampered record to the original id must fail on rehash before I/O
        try:
            store.store_verification(dict(evidence, observed_sha256='0' * 64))
            problems.append('a record with a wrong observed hash was accepted')
        except StoreError as exc:
            if exc.reason != STORE_REHASH_MISMATCH:
                problems.append(f'wrong observed hash refused as {exc.reason}')
        # id hygiene: no path traversal
        try:
            store.load_verification('../escape')
            problems.append('a traversal run id was accepted')
        except StoreError as exc:
            if exc.reason != STORE_ID_INVALID:
                problems.append(f'traversal id refused as {exc.reason}')
    return problems


def _sample_evidence() -> dict:
    """A minimal structurally valid record for the self-test only (no console involved)."""
    evidence = {
        'schema': SCHEMA_VERIFICATION,
        'verification_run_id': 'RUN-self-test-verify',
        'verification_session_id': 'SES-' + '0' * 16,
        'operation': 'verify.kernel.read',
        'outcome': 'PASS',
        'capability': 'kernel.read',
        'provider': 'ps4rfd-kread-privileged',
        'provider_type': 'NATIVE',
        'profile_sha256': 'a' * 64,
        'boot_id': 'BOOT-' + '0' * 16,
        'context': 'JAILBROKEN_PROCESS',
        'scope': 'SESSION',
        'region': 'image_elf',
        'offset': 0,
        'length': 16,
        'expected_bytes_hex': 'ab' * 16,
        'expected_sha256': 'b' * 64,
        'observed_bytes_hex': 'ab' * 16,
        'observed_sha256': 'b' * 64,
        'read_run_id': 'RUN-self-test-read',
        'read_session_id': 'SES-' + '0' * 16,
    }
    evidence[EVIDENCE_HASH_FIELD] = canonical_evidence_sha256(evidence)
    return evidence


def main(argv: list[str]) -> int:
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: kreadstore.py --self-test')
        return 2
    problems = _self_test()
    for problem in problems:
        print(f'kread store: {problem}')
    print(f'kread store self-test: {"ok" if not problems else "FAILED"} '
          '(rehash on load, bare verified flag refused, id hygiene)')
    return 0 if not problems else 1


if __name__ == '__main__':                                # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
