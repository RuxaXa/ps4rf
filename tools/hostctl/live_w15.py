"""W15 offline rehearsal -- a research read inside a later resident session, executed.

The W14 sheet proved the *lifecycle*: one agent lifetime, several sessions, an authenticated end.
This sheet proves the W12/W13 *research* chain inside that lifetime, without a second read path:

* **V** -- a verification session: the frozen bootstrap read (`verify.kernel.read`) of the pinned
  window, whose evidence is persisted into the store (this is the object a later session leans on;
  it has to come from an *earlier* session, which is exactly why it is its own session here),
* **A** -- a plain session (`session.status`), no research,
* **B** -- a fresh session that loads+rehashes the stored evidence, re-derives its own SESSION
  capability, carries a fresh §70 approval and a fresh W13 release, performs **one** bounded read of
  `amd_iommu` (compiled index 1, offset 0, length 16) and closes normally,
* **C** -- a fresh session that (i) proves nothing of B was carried over, (ii) tries the *same*
  release again and must be refused with ``W13_RELEASE_ALREADY_CONSUMED`` **before** the provider
  entry, (iii) shuts down through the authenticated admin operation.

Everything the rehearsal claims is host-side and written to one evidence file. The read itself is
the production provider of the *same* daemon, linked against the simulated kernel image
(`tests/harness/ps4rf_kread_sim.c`), seeded with the profile's pinned bytes -- so the wire path,
the bounds, the containment, the LSTAR/kbase cross-check, the copy, the event and the whole host
verification chain are the real ones. What is simulated is only the kernel *underneath*.

After the read, the W13 research pipeline runs on the read the session just produced (owner's
§5/§6): the persisted read-run record becomes one content-addressed dataset snapshot (the same
read ingested twice deduplicates to one blob and one index row) and exactly one W6 differential
input, whose result stays `OBSERVATION`-only with W4 impact `NONE` -- analysis, never
authorization: the pinned profile file, the approval, the release and the read plan are hashed
before and after the differential and must not move.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import socket
import sys
import time
import traceback

REPO = pathlib.Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.differential import schema as DSC                                     # noqa: E402
from tools.hostctl import kreadlive as KL                                       # noqa: E402
from tools.hostctl import kreadstore as KS                                      # noqa: E402
from tools.hostctl.endpoint import SocketEndpoint                               # noqa: E402
from tools.hostctl import live_w14 as LW                                        # noqa: E402
from tools.hostctl.live_w14 import LiveController, LiveError, SessionFacts, compare_sessions
from tools.hostctl.session import HostSession, smoke_request_id                  # noqa: E402
from tools.profiles.schema import canonical_profile_sha256                       # noqa: E402
from tools.research import approval as AP                                        # noqa: E402
from tools.research import classification as C                                   # noqa: E402
from tools.research import dataset as DS                                         # noqa: E402
from tools.research import read_plan as RP                                       # noqa: E402
from tools.research import release as REL                                        # noqa: E402
from tools.research import w6_contract as W6                                     # noqa: E402

REGION = 'amd_iommu'
OFFSET = 0
LENGTH = 16
READ_SCOPE = AP.READ_SCOPE_RESEARCH

PSK_FILE = pathlib.Path.home() / '.hermes' / 'secrets' / 'ps4rf-w15-psk.bin'


def _h(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def _stamp() -> str:
    """The wave stamp of the fresh trust objects: second resolution.

    A rehearsal run takes longer than a second, and the two lifetimes of the second test run
    back to back -- a minute-resolution stamp could be shared by both, which would mint the
    *same* release id twice and hide a leaked trust object.
    """
    return dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')


# =============================================================================================
# fixtures: a *fresh* section 70 approval and a *fresh* W13 release for this wave
# =============================================================================================
def plan_fixtures(*, profile: dict, profile_sha256: str, boot_id: str, payload: dict,
                  evidence_sha256: str, verification_run_id: str, wave: str = 'W15',
                  now: str | None = None) -> dict:
    """The two separate trust objects a research read needs, freshly minted for this wave.

    The bytes and the compiled index are never written down here: both come from the profile's
    pinned locator, which is the same normative source the target table is generated from.
    """
    locator = C.profile_locator(profile, f'kernel.attest.{REGION}') or {}
    bytes_hex = str((locator.get('expected_bytes') or {}).get('hex') or '')
    if not bytes_hex:
        raise LiveError(f'the profile carries no pinned bytes for kernel.attest.{REGION}')
    index = KL.region_index(REGION)
    if index is None:
        raise LiveError(f'{REGION} has no row in the compiled table')
    stamp = now or _stamp()
    approval_id = f'\u00a770-{wave}-READ-1-{stamp}'
    release_id = f'{wave}-READ-1-{stamp}'
    approval = {
        'schema': AP.SCHEMA_APPROVAL,
        'id': approval_id,
        'state': 'APPROVED',
        'approved': True,
        'approver': 'owner',
        'read_scope': READ_SCOPE,
        'boot_id': boot_id,
        'profile_sha256': profile_sha256,
        'verification_run_id': verification_run_id,
        'evidence_sha256': evidence_sha256,
        'payload': payload,
        'source': f'owner W15 scope approval, transcribed verbatim for the {wave} rehearsal',
        'recorded_by': f'{wave} rehearsal sheet (offline)',
        'notes': [f'authorises exactly one bounded research read of {REGION} '
                  f'(index {index}, offset {OFFSET}, length {LENGTH})',
                  'the W13 release is a *separate* trust object and is consumed at the provider '
                  'entry; reuse is refused for the whole agent lifetime'],
    }
    approval_sha = AP.approval_sha256(approval)
    release = REL.release_document(
        release_id=release_id, region=REGION, offset=OFFSET, length=LENGTH,
        expected_bytes=bytes_hex, region_index=index,
        expected_sha256=hashlib.sha256(bytes.fromhex(bytes_hex)).hexdigest(),
        profile_sha256=profile_sha256, boot_id=boot_id, approval_sha256=approval_sha,
        classification=C.CLASS_APPROVED_READ, rva=(f'0x{int(locator["locator"]["value"]):x}'
                                                   if isinstance(locator.get('locator'), dict) else None),
        module=str(locator.get('module') or 'kernel'),
        permissions=str(locator.get('permissions') or 'r-x'), payload=payload,
        source=f'owner {wave} scope approval (transcribed)', notes=[
            'the request names the compiled table row for amd_iommu; no address, no rva and no '
            'pointer ever enters the request',
            'one read, one release: a consumed release is never read again in this lifetime'])
    problems = REL.release_problems(release, profile=profile, profile_sha256=profile_sha256,
                                    boot_id=boot_id, approval_sha256=approval_sha)
    if problems:
        raise LiveError('the fresh release is not acceptable: ' + '; '.join(problems))
    return {'approval': approval, 'approval_sha256': approval_sha, 'release': release,
            'release_sha256': REL.release_sha256(release), 'region_index': index,
            'expected_bytes': bytes_hex,
            'expected_sha256': hashlib.sha256(bytes.fromhex(bytes_hex)).hexdigest()}


def seed_file(path: pathlib.Path, windows: list[tuple[int, str]]) -> pathlib.Path:
    """The simulated image's seed: `<rva hex> <bytes hex>` lines (the compiler-independent form)."""
    lines = ['# PS4RF W15 rehearsal -- simulated kernel image, seeded with the profile\'s pinned bytes']
    for rva, bytes_hex in windows:
        lines.append(f'{int(rva):08x} {bytes_hex}')
    path.write_text('\n'.join(lines) + '\n')
    return path


def profile_windows(profile: dict, *, only: tuple[str, ...] = ('image_elf', REGION)) -> list[tuple[int, str]]:
    """The rva/bytes pairs the simulated image must serve: the pinned bootstrap and the read window."""
    out: list[tuple[int, str]] = []
    for name in only:
        locator = C.profile_locator(profile, f'kernel.attest.{name}') or {}
        raw = locator.get('locator') or {}
        bytes_hex = str((locator.get('expected_bytes') or {}).get('hex') or '')
        offset = int((locator.get('expected_bytes') or {}).get('offset') or 0)
        if raw.get('kind') != 'rva' or not bytes_hex:
            raise LiveError(f'the profile locator for {name} is not an rva window with bytes')
        out.append((int(raw['value']) + offset, bytes_hex))
    return out


# =============================================================================================
# owner's §5/§6 -- the read becomes a dataset snapshot and one W6 observation (analysis only)
# =============================================================================================
def _utc_stamp() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def _blob_names(dataset: DS.ResearchDataset) -> list[str]:
    """The blob names the dataset API exposes (no directory until the first blob exists)."""
    root = dataset.blob_root
    return sorted(path.name for path in root.iterdir()) if root.is_dir() else []


def pre_read_baseline(*, snapshot: dict) -> dict:
    """The *before* side of the one differential: this region had no observation yet.

    It states an absence -- nothing was read, so it carries no bytes, no locator value and no
    address -- and mirrors the identity fields of `w6_contract.read_inventory` so the two sides
    of the comparison are the same kind of document. The one fact it uses, the window length,
    comes from the snapshot this run just wrote.
    """
    return {
        'schema': W6.INVENTORY_SCHEMA,
        'kind': 'kernel-window',
        'fixture': False,
        'path': f'kernel/{REGION}',
        'module': 'fw13.52-kernel',
        'architecture': 'x86-64',
        'size': int(snapshot.get('length') or 0),
        'manifest_entries': {},
        'notes': ['pre-read baseline: the dataset had no observation for this region before '
                  'this read; this document states the absence, it carries no bytes and no '
                  'address'],
        'entries': [],
    }


def artifact_forbidden(document: dict) -> dict:
    """The W6 artifact contract's forbidden content, checked against one document.

    ``FORBIDDEN_IN_ARTIFACT`` fields (runtime addresses, kbase, boot id) must not appear as
    keys anywhere, and the document's values must not use the verdict-like status words.
    """
    blob = json.dumps(document, sort_keys=True)
    fields = [name for name in W6.FORBIDDEN_IN_ARTIFACT if f'"{name}"' in blob]
    words = sorted(DSC.string_tokens(document) & set(DSC.FORBIDDEN_STATUS_WORDS))
    return {'fields': fields, 'status_words': words}


def guarded_documents(plan: dict) -> dict:
    """The documents a W6 analysis run may never change, hashed from disk and memory.

    §6: no capability, region, profile or approval state may move because an observation was
    produced. Hashed here: the profile file, the classification matrix and the read plan (a
    region promotion or a new plan entry would move them), the approval and release documents
    (in memory and as the written fixtures).
    """
    fixtures = pathlib.Path(plan['out_dir']) / 'fixtures'
    state: dict[str, dict] = {
        'profile_file': {'path': str(C.PROFILE_PATH), 'sha256': _h(C.PROFILE_PATH.read_bytes())},
        'classification_matrix': {
            'sha256': _h(json.dumps(C.classification_matrix(), indent=1, sort_keys=True))},
        'read_plan': {'sha256': _h(json.dumps(RP.read_plan(), indent=1, sort_keys=True))},
    }
    for name, document in (('approval', plan.get('approval')), ('release', plan.get('release'))):
        if isinstance(document, dict):
            state[f'{name}_document'] = {
                'sha256': _h(json.dumps(document, indent=1, sort_keys=True))}
    for name, filename in (('approval_fixture', 'approval-w15-read1.json'),
                           ('release_fixture', 'release-w15-read1.json')):
        path = fixtures / filename
        if not path.exists():
            raise LiveError(f'the §6 guard cannot hash {name}: {path} does not exist (fail closed)')
        state[name] = {'path': str(path), 'sha256': _h(path.read_bytes())}
    return state


def unchanged_guards(before: dict, after: dict) -> dict:
    """Pair the two guard snapshots; any movement is a failure, not a pass."""
    entries: dict[str, dict] = {}
    changed: list[str] = []
    for name in sorted(set(before) | set(after)):
        first, second = before.get(name) or {}, after.get(name) or {}
        entries[name] = {'sha256_before': first.get('sha256'), 'sha256_after': second.get('sha256'),
                         'path': first.get('path') or second.get('path'),
                         'unchanged': first == second}
        if first != second:
            changed.append(name)
    return {'all_unchanged': not changed, 'changed': changed, 'entries': entries}


def ingest_read_snapshot(*, dataset_root, record: dict, kbase: int, profile_sha256: str,
                         boot_id: str) -> dict:
    """§5 -- persist the read as one dataset snapshot; prove the duplicate ingest deduplicates.

    The record is the *persisted* read-run record (`store.load_read_run`, rehashed on load).
    Every number returned here is read back through the dataset API in this run: the counts from
    `index()` and `blob_root`, the blob through `blob_path()`/`get_bytes()`, the index hash from
    `index_sha256()`, the invariant list from `problems()`. Nothing is assumed, and a dataset
    root that is not empty is refused: the rehearsal binds exactly one read.
    """
    dataset = DS.ResearchDataset(dataset_root)
    entries_before = len(dataset.index()['snapshots'])
    blobs_before = _blob_names(dataset)
    if entries_before or blobs_before:
        raise LiveError('the §5 dataset root is not empty: the rehearsal binds exactly one read '
                        f'({entries_before} snapshot(s), {len(blobs_before)} blob(s))')
    first = dataset.add_read(read_run_record=record, region_name=REGION, kbase=kbase,
                             profile_sha256=profile_sha256, boot_id=boot_id,
                             timestamp=_utc_stamp())
    entries_after_first = len(dataset.index()['snapshots'])
    blobs_after_first = _blob_names(dataset)
    duplicate = dataset.add_read(read_run_record=record, region_name=REGION, kbase=kbase,
                                 profile_sha256=profile_sha256, boot_id=boot_id,
                                 timestamp=_utc_stamp())
    entries_after = len(dataset.index()['snapshots'])
    blobs_after = _blob_names(dataset)
    snapshot = dict(first['snapshot'])
    digest = snapshot['sha256']
    blob = dataset.get_bytes(digest)
    raw = bytes.fromhex((record.get('read_evidence') or {}).get('bytes_hex') or '')
    problems = dataset.problems()
    checks = {
        'first_added': first['added'] is True,
        'duplicate_deduplicated': duplicate['deduplicated'] is True,
        'duplicate_not_added': duplicate['added'] is False,
        'exactly_one_entry': not entries_before and entries_after == 1,
        'exactly_one_blob': not blobs_before and len(blobs_after) == 1,
        'no_second_blob': blobs_after == blobs_after_first,
        'no_duplicate_snapshot_row': entries_after == entries_after_first,
        'duplicate_names_the_first_snapshot':
            duplicate['snapshot']['snapshot_id'] == snapshot['snapshot_id'],
        'blob_content_is_the_record_bytes': blob == raw,
        'problems_empty': not problems,
    }
    if not all(checks.values()):
        raise LiveError(f'the §5 dataset ingest is not clean: {checks}; problems={problems}')
    return {
        'root': str(dataset.root),
        'index_path': str(dataset.root / DS.INDEX_FILE),
        'blob_root': str(dataset.blob_root),
        'blob': {'sha256': digest, 'path': str(dataset.blob_path(digest)),
                 'length': len(blob), 'content_matches_record': blob == raw},
        'snapshot': snapshot,
        'snapshot_id': snapshot['snapshot_id'],
        'index_sha256': dataset.index_sha256(),
        'entries_before_ingest': entries_before,
        'entries_after_first_ingest': entries_after_first,
        'entries_after_duplicate': entries_after,
        'blobs_before_ingest': len(blobs_before),
        'blobs_after_first_ingest': len(blobs_after_first),
        'blobs_after_duplicate': len(blobs_after),
        'duplicate': {'added': duplicate['added'], 'deduplicated': duplicate['deduplicated'],
                      'no_second_blob': blobs_after == blobs_after_first,
                      'no_duplicate_snapshot_row': entries_after == entries_after_first,
                      'snapshot_id': duplicate['snapshot']['snapshot_id']},
        'checks': checks,
        'problems': problems,
    }


def differential_observation(*, plan: dict, record: dict, snapshot: dict) -> dict:
    """§6 -- exactly one differential input from exactly this snapshot; OBSERVATION only.

    The input is the normalized artifact of the read the snapshot points at (validated against
    the snapshot's own `read_run_id` and `sha256` first). Its before side is the pre-read
    baseline above: an absence, not an invented observation. The differential runs through the
    real W6 CLI; `candidates_of` refuses anything that is not `OBSERVATION` with W4 impact
    `NONE`, the replay must reproduce the result hash, and the guards must not move.
    """
    w6_dir = pathlib.Path(plan['w6_dir'])
    w6_dir.mkdir(parents=True, exist_ok=True)
    raw = bytes.fromhex((record.get('read_evidence') or {}).get('bytes_hex') or '')
    if snapshot.get('read_run_id') != record.get('read_run_id') or snapshot.get('sha256') != _h(raw):
        raise LiveError('the §6 input is not built from this snapshot: '
                        f"read_run_id {snapshot.get('read_run_id')!r} vs "
                        f"{record.get('read_run_id')!r}, sha256 {snapshot.get('sha256')!r} vs "
                        f'{_h(raw)!r}')
    guards_before = guarded_documents(plan)
    after_document = W6.read_inventory(read_run_record=record, region_name=REGION,
                                       profile=plan['profile'])
    before_document = pre_read_baseline(snapshot=snapshot)
    before_path = w6_dir / f'before-{REGION}.json'
    after_path = w6_dir / f'after-{REGION}.json'
    before_sha = W6.write_inventory(before_path, before_document)
    after_sha = W6.write_inventory(after_path, after_document)
    forbidden = {'fields': [], 'status_words': []}
    for document in (before_document, after_document):
        check = artifact_forbidden(document)
        forbidden['fields'] += [name for name in check['fields'] if name not in forbidden['fields']]
        forbidden['status_words'] = sorted(set(forbidden['status_words'])
                                           | set(check['status_words']))
    try:
        report = W6.run_differential(before_path, after_path)
        candidates = W6.candidates_of(report)
    except W6.ContractError as exc:
        raise LiveError(f'the §6 differential refused or is not observation-only: {exc}') from exc
    replay = W6.run_differential(before_path, after_path)
    if replay.get('output_sha256') != report.get('output_sha256'):
        raise LiveError('the §6 differential replay did not reproduce the result hash: '
                        f"{report.get('output_sha256')!r} vs {replay.get('output_sha256')!r}")
    result_path = w6_dir / 'w6-result.json'
    result_path.write_text(json.dumps(report, indent=1, sort_keys=True) + '\n')
    guards = unchanged_guards(guards_before, guarded_documents(plan))
    if not guards['all_unchanged']:
        raise LiveError(f'the §6 differential run moved guarded state: {guards["changed"]}')
    if forbidden['fields'] or forbidden['status_words']:
        raise LiveError(f'the §6 artifact carries forbidden content: {forbidden}')
    return {
        'input_path': str(after_path),
        'input_sha256': after_sha,
        'input_count': 1,
        'baseline_path': str(before_path),
        'baseline_sha256': before_sha,
        'baseline_note': 'pre-read baseline: no observation for this region existed before this '
                         'read (entries empty, no bytes)',
        'result_path': str(result_path),
        'result_sha256': _h(result_path.read_bytes()),
        'output_sha256': report.get('output_sha256'),
        'replay_output_sha256': replay.get('output_sha256'),
        'replay_stable': replay.get('output_sha256') == report.get('output_sha256'),
        'all_observation': all(candidate.get('status') == 'OBSERVATION'
                               for candidate in candidates),
        'all_w4_none': all((candidate.get('impact') or {}).get('w4') == 'NONE'
                           for candidate in candidates),
        'candidate_count': len(candidates),
        'candidates': candidates,
        'finding_count': len(report.get('findings') or []),
        'findings': report.get('findings'),
        'artifact_forbidden': forbidden,
        'snapshot_id': snapshot.get('snapshot_id'),
        'read_run_id': record.get('read_run_id'),
        'guards': guards,
    }


# =============================================================================================
# the rehearsal steps
# =============================================================================================
def _facts(label: str, session, *, connect_wait_s: float, bye: dict | None,
           research: dict | None = None) -> SessionFacts:
    """The session facts a run sheet needs, read from a session a *driver* brought up.

    The research operations own their session's handshake (`run_verification` and
    `run_generic_read` both bring the session up themselves, so the old session id can be refused
    against the stored evidence), which means the facts have to be read off the session object
    afterwards instead of being returned by `LiveController.run_session`.
    """
    facts = SessionFacts(label)
    hello = dict(session.hello_seen or {})
    facts.hello = hello
    facts.ready = dict(session.ready or {})
    facts.identity = dict(session.agent_identity or {})
    facts.session_id = str(session.session_id or '')
    facts.nonce_hash = LW._h(str(hello.get('nonce', '')))[:32]
    facts.transcript_hash = LW._h(bytes(session.transcript_hex or '', 'utf-8'))[:32]
    facts.keys_fingerprint = LW._keys_fingerprint(session.keys) if session.keys else ''
    facts.bye = bye
    facts.research = research
    facts.connect_wait_s = connect_wait_s
    return facts


def owned_session(ctl: LiveController, label: str, driver, *, expect_bye: str = 'CLIENT_CLOSE'):
    """Run one session whose bring-up belongs to `driver` (the research operations do that).

    The driver receives the raw session and returns its result -- which may carry the BYE it already
    drained. Everything the run sheet checks per session (the BYE reason, `cleanup COMPLETE`, no held
    resource) is checked here, exactly like `LiveController.run_session` checks it.
    """
    conn = ctl.accept()
    connect_wait_s = round(time.monotonic() - ctl.anchor, 3)
    session = HostSession(SocketEndpoint(conn, timeout=ctl.session_timeout), ctl.psk)
    try:
        result = driver(session)
        bye = (result or {}).get('bye') if isinstance(result, dict) else None
        if bye is None:
            bye = KL._finish_session(session)
        facts = _facts(label, session, connect_wait_s=connect_wait_s, bye=bye, research=result)
    finally:
        session.close()
    if facts.bye is None:
        raise LiveError(f'session {label} ended without a BYE')
    if facts.bye.get('reason') != expect_bye:
        raise LiveError(f'session {label}: BYE {facts.bye.get("reason")!r}, expected '
                        f'{expect_bye!r}')
    cleanup = facts.bye.get('cleanup') or {}
    if cleanup.get('state') != 'COMPLETE' or cleanup.get('resources') != []:
        raise LiveError(f'session {label}: cleanup {cleanup!r} is not COMPLETE with no held '
                        'resource')
    ctl.sessions.append(facts)
    return facts


def research_read(session, *, plan: dict) -> dict:
    """Session B: load+rehash, re-derive the SESSION capability, read once, persist the read.

    `run_generic_read` owns the session bring-up -- it handshakes itself so the session id of the
    reading session is the one the derived capability is bound to, and so the stored evidence can
    refuse a reused session id. That is why this is a *driver* and not a hook on an already
    established session.

    After the read verifies, the owner's §5/§6 pipeline runs on the *persisted* record: one
    dataset snapshot (the same read ingested twice deduplicates) and exactly one W6 differential
    input whose result is `OBSERVATION`-only with W4 impact `NONE`. A read that did not come back
    as a verified, persisted one-entry READ ingests nothing (fail closed).
    """
    store = plan['store']
    window_block = REL.released_window(plan['release'], profile=plan['profile'],
                                       profile_sha256=plan['profile_sha256'],
                                       boot_id=plan['boot_id'],
                                       approval_sha256=plan['approval_sha256'])
    if window_block.get('problems'):
        raise LiveError('the released window is not acceptable: '
                        + '; '.join(window_block['problems']))
    window = window_block['window']
    run_id = f"GRUN-{_h(plan['release_id'])[:16]}"
    result = KL.run_generic_read(session, profile=plan['profile'], boot_binding=plan['boot_binding'],
                                 store=store, verification_run_id=plan['verification_run_id'],
                                 evidence_sha256=plan['evidence_sha256'],
                                 approval=plan['approval'], provider=plan['provider'],
                                 context=plan['context'], generic_read_run_id=run_id,
                                 request_id=smoke_request_id(1), expected=window)
    evidence = {
        'verification_run_id': plan['verification_run_id'],
        'evidence_sha256': plan['evidence_sha256'],
        'approval_id': plan['approval']['id'], 'approval_sha256': plan['approval_sha256'],
        'release_id': plan['release_id'], 'release_sha256': plan['release_sha256'],
        'window': {'region': window.get('region'), 'region_index': window.get('region_index'),
                   'offset': window.get('offset'), 'length': window.get('length'),
                   'expected_bytes': window.get('bytes_hex'),
                   'expected_sha256': window.get('sha256'),
                   'release_id': window.get('release_id')},
        'outcome': result.get('outcome'), 'read_run_id': result.get('read_run_id'),
        'provider_entries': result.get('provider_entries'),
        'run_separation': result.get('run_separation'),
        'problems': result.get('problems'),
        'event_report': result.get('event_report'),
        'release_consumption': result.get('release_consumption'),
        'capability_session': (result.get('capability') or {}).get('session_id'),
        'capability_derivation': (result.get('derivation') or {}).get('receipt_id')
        if isinstance(result.get('derivation'), dict) else None,
    }

    # ---- owner's §5: the read becomes one dataset snapshot (content-addressed, deduplicated).
    # Only a verified, persisted one-entry READ is archived; anything else fails closed here.
    if result.get('outcome') != KL.OUTCOME_READ \
            or int(result.get('provider_entries') or 0) != 1 \
            or not (result.get('event_report') or {}).get('verified'):
        raise LiveError('the research read is not a verified, persisted one-entry READ; the §5/§6 '
                        'ingest refuses to run: '
                        + '; '.join(str(problem) for problem in (result.get('problems') or []))[:400])
    record = store.load_read_run(result['read_run_id'])          # rehashed on load
    kbase = (result.get('event_report') or {}).get('kbase')
    if not isinstance(kbase, int) or isinstance(kbase, bool):
        raise LiveError('the verified event report carries no runtime kernel base (kbase)')
    evidence['dataset'] = ingest_read_snapshot(
        dataset_root=plan['dataset_root'], record=record, kbase=kbase,
        profile_sha256=plan['profile_sha256'], boot_id=plan['boot_id'])

    # ---- owner's §6: exactly one differential input, built from exactly this snapshot.
    evidence['w6'] = differential_observation(plan=plan, record=record,
                                              snapshot=evidence['dataset']['snapshot'])

    result = dict(result)
    result['research'] = evidence
    return result


def reuse_session(session, *, plan: dict) -> dict:
    """Session C: the *same* release again -- it must be refused before the provider entry.

    The refusal is the whole point: a release consumed by another session must not reach the
    provider once more, even though this session is new (fresh id, nonce, keys, capability).
    Afterwards the session asks for the agent's own status and then ends the lifetime through the
    authenticated admin operation -- on a session that never read anything.
    """
    # the session is brought up by *this* driver: the one-shot refusal below happens host-side,
    # before any wire traffic, so the session has to be established here for the facts (fresh id,
    # nonce, keys) and for the two requests that follow the refusal
    session.handshake()
    session.recv_ready()
    window_block = REL.released_window(plan['release'], profile=plan['profile'],
                                       profile_sha256=plan['profile_sha256'],
                                       boot_id=plan['boot_id'],
                                       approval_sha256=plan['approval_sha256'])
    window = window_block.get('window') or {}
    result = KL.run_generic_read(session, profile=plan['profile'], boot_binding=plan['boot_binding'],
                                 store=plan['store'], verification_run_id=plan['verification_run_id'],
                                 evidence_sha256=plan['evidence_sha256'],
                                 approval=plan['approval'], provider=plan['provider'],
                                 context=plan['context'],
                                 generic_read_run_id=f"GRUN-REUSE-{_h(plan['release_id'])[:16]}",
                                 request_id=smoke_request_id(1), expected=window)
    problems = result.get('problems') or []
    reuse = {
        'outcome': result.get('outcome'), 'provider_entries': result.get('provider_entries'),
        'problems': problems,
        'refused_already_consumed': any('W13_RELEASE_ALREADY_CONSUMED' in str(p) for p in problems),
        'release_id': plan['release_id'],
        'consumed_marker': plan['store'].load_release_consumption(plan['release_id']),
        'consumed_query': plan['store'].release_is_consumed(plan['release_id']),
        'requests_after_refusal': [],
    }
    status = session.request('session.status', {}, request_id=smoke_request_id(2))
    reuse['requests_after_refusal'].append({'operation': 'session.status', **status})
    shutdown = session.request('session.shutdown', {'capability': 'session.admin'},
                               request_id=smoke_request_id(3))
    reuse['requests_after_refusal'].append({'operation': 'session.shutdown', **shutdown})
    reuse['shutdown_accepted'] = (shutdown.get('result') or {}).get('status') == 'ACCEPTED'
    out = dict(result)
    out['bye'] = KL._finish_session(session)
    out['reuse'] = reuse
    return out


def isolation_facts(ctl: LiveController, *, plan: dict) -> dict:
    """§4: what must be gone after every session, and what is allowed to survive."""
    store = plan['store']
    return {
        'session_secrets_are_born_per_session': True,
        'sessions': [{'session': s.label, 'cleanup': (s.bye or {}).get('cleanup'),
                      'bye': (s.bye or {}).get('reason')} for s in ctl.sessions],
        'read_run_ids': store.read_run_ids(),
        'verification_run_ids': store.verification_run_ids(),
        'consumed_release_ids': [rid for rid in [plan['release_id']]
                                 if store.release_is_consumed(rid)],
        'capability_scope': 'SESSION (one derivation per session, per the W14 ledger contract)',
    }


# =============================================================================================
# the run
# =============================================================================================
def rehearse(*, host: str, port: int, psk: bytes, out_dir: pathlib.Path, store_root: pathlib.Path,
             payload: dict, accept_timeout: float = 120.0, no_redial_sec: float = 10.0,
             target: str | None = None, health_check: bool = True, gap_sec: float = 0.0) -> dict:
    profile = C.DEFAULT_PROFILE
    profile_sha = canonical_profile_sha256(profile)
    plan: dict = {'profile': profile, 'profile_sha256': profile_sha, 'context': KL.CONTEXT,
                  'provider': KL.sim_provider(live_approved=True),
                  'boot_binding': KL.synthetic_boot_binding(profile),
                  'store': KS.VerificationEvidenceStore(store_root), 'payload': payload,
                  'out_dir': pathlib.Path(out_dir)}
    plan['boot_id'] = plan['boot_binding'].boot_id
    # owner's §5/§6: the read is archived under <out>/dataset and the one differential under <out>/w6
    plan['dataset_root'] = plan['out_dir'] / 'dataset'
    plan['w6_dir'] = plan['out_dir'] / 'w6'

    evidence: dict = {'stage': 'W15 resident research rehearsal', 'mode': 'offline (simulated image)',
                      'started_at': dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),
                      'controller': f'{host}:{port}', 'psk_fingerprint': _h(psk)[:16],
                      'profile_sha256': profile_sha, 'boot_id': plan['boot_id'],
                      'payload': payload, 'steps': [], 'notes': [
                          'the kernel underneath the read is simulated (tests/harness/'
                          'ps4rf_kread_sim.c), seeded with the profile\'s pinned bytes; the daemon, '
                          'the wire request, the bounds, the event and the whole host chain are the '
                          'production ones'],
                      'verdict': 'STOP'}
    ctl = LiveController(host, port, psk, out_dir=out_dir, accept_timeout=accept_timeout)
    try:
        ctl.open()
        # ---- session V: the verification a later session leans on (it owns its handshake)
        facts_v = owned_session(ctl, 'V', lambda session: KL.run_verification(
            session, profile=plan['profile'], boot_binding=plan['boot_binding'],
            store=plan['store'], provider=plan['provider'], context=plan['context']))
        verification = facts_v.research or {}
        persisted = verification.get('evidence') or {}
        evidence_sha = persisted.get('evidence_sha256')
        evidence['steps'].append({'step': 'session_v_verification', 'facts': facts_v.as_evidence(),
                                  'verification': {
            'outcome': verification.get('outcome'), 'verification_run_id':
                verification.get('verification_run_id'),
            'evidence_sha256': evidence_sha,
            'evidence_path': verification.get('evidence_path'),
            'provider_entries': verification.get('provider_entries'),
            'problems': verification.get('problems')}})
        if verification.get('outcome') not in ('VERIFIED', 'PASS') or not evidence_sha:
            raise LiveError('the verification session did not PASS: '
                            + '; '.join(verification.get('problems') or ['no persisted evidence']))
        plan['verification_run_id'] = verification['verification_run_id']
        plan['evidence_sha256'] = evidence_sha

        # ---- the fresh trust objects for this wave
        fixtures = plan_fixtures(profile=profile, profile_sha256=profile_sha,
                                 boot_id=plan['boot_id'],
                                 payload=payload, evidence_sha256=plan['evidence_sha256'],
                                 verification_run_id=plan['verification_run_id'])
        plan.update({'approval': fixtures['approval'], 'approval_sha256': fixtures['approval_sha256'],
                     'release': fixtures['release'], 'release_sha256': fixtures['release_sha256'],
                     'release_id': fixtures['release']['release_id'],
                     'region_index': fixtures['region_index']})
        evidence['fixtures'] = {'approval': fixtures['approval'], 'release': fixtures['release'],
                                'region_index': fixtures['region_index'],
                                'expected_bytes': fixtures['expected_bytes'],
                                'expected_sha256': fixtures['expected_sha256']}
        fixture_dir = pathlib.Path(out_dir) / 'fixtures'
        fixture_dir.mkdir(parents=True, exist_ok=True)
        (fixture_dir / 'approval-w15-read1.json').write_text(
            json.dumps(fixtures['approval'], indent=1, sort_keys=True) + '\n')
        (fixture_dir / 'release-w15-read1.json').write_text(
            json.dumps(fixtures['release'], indent=1, sort_keys=True) + '\n')

        # ---- session A: status only
        facts_a = ctl.run_session('A', (('session.status', {}),))
        evidence['steps'].append({'step': 'session_a', 'facts': facts_a.as_evidence()})

        # ---- the controller gap (optional): the agent must survive it
        if gap_sec > 0:
            ctl.close()
            evidence['steps'].append({'step': 'controller_gap', 'seconds': gap_sec})
            time.sleep(gap_sec)
            ctl.open()
            ctl.mark_ready()

        # ---- session B: the research read (its driver owns the session bring-up)
        facts_b = owned_session(ctl, 'B', lambda session: research_read(session, plan=plan))
        evidence['steps'].append({'step': 'session_b_research_read', 'facts': facts_b.as_evidence(),
                                  'research': (facts_b.research or {}).get('research')})

        # ---- session C: isolation, the consumed release, the authenticated end
        facts_c = owned_session(ctl, 'C', lambda session: reuse_session(session, plan=plan),
                                expect_bye='ADMIN_SHUTDOWN')
        reuse = (facts_c.research or {}).get('reuse') or {}
        if not reuse.get('shutdown_accepted'):
            raise LiveError(f'the admin shutdown was not accepted: {reuse.get("requests_after_refusal")}')
        evidence['steps'].append({'step': 'session_c_isolation', 'facts': facts_c.as_evidence(),
                                  'reuse': reuse, 'requests_after_refusal':
                                  reuse.get('requests_after_refusal'),
                                  'isolation': isolation_facts(ctl, plan=plan)})

        # ---- silence after the authenticated end
        silent_from = time.monotonic()
        dialled = ctl.wait_for_dial(no_redial_sec)
        evidence['steps'].append({'step': 'after_admin_shutdown',
                                  'redialled_within_s': round(time.monotonic() - silent_from, 3)
                                  if dialled is not None else None,
                                  'silent_for_s': no_redial_sec})
        if dialled is not None:
            raise LiveError('the agent dialled again after a successful admin shutdown')

        comparison = compare_sessions(ctl.sessions)
        evidence.update({'comparison': comparison, 'lifetime_id': ctl.lifetime_id,
                         'notes': ctl.notes + evidence['notes'],
                         'stray_connections': ctl.strays, 'busy_notices': ctl.busy_notices,
                         'connection_log': ctl.connection_log})
        if comparison['problems']:
            raise LiveError('; '.join(comparison['problems']))
        # the rehearsal's own post-conditions, checked here so a broken claim never reaches PASS
        read = (facts_b.research or {}).get('research') or {}
        if read.get('provider_entries') != 1:
            raise LiveError(f"session B reached {read.get('provider_entries')} provider entries, "
                            'expected exactly one')
        report = read.get('event_report') or {}
        if not report.get('verified'):
            raise LiveError(f"the read event did not verify: {read.get('problems')}")
        reuse = (facts_c.research or {}).get('reuse') or {}
        if not reuse.get('refused_already_consumed') or reuse.get('provider_entries') not in (0, None):
            raise LiveError('the consumed release was not refused before the provider entry: '
                            f'{reuse}')
        evidence['verdict'] = 'PASS'
    except LiveError as exc:
        evidence['verdict'] = 'STOP'
        evidence['stop_reason'] = str(exc)
    except Exception as exc:                    # a broken sheet must still leave evidence
        evidence['verdict'] = 'STOP'
        evidence['stop_reason'] = f'{exc.__class__.__name__}: {exc}'
        evidence['traceback'] = traceback.format_exc()
    finally:
        ctl.close()

    evidence['connection_log'] = ctl.connection_log
    evidence['busy_notices'] = ctl.busy_notices
    if evidence['verdict'] == 'PASS' and target and health_check:
        from tools.hostctl.live_w14 import health
        evidence['health_after_shutdown'] = health(target)
        if any(str(v).startswith('FAIL') for v in evidence['health_after_shutdown'].values()):
            evidence['verdict'] = 'STOP'
            evidence['stop_reason'] = 'target health is not green'
    out = pathlib.Path(out_dir) / 'w15-resident-research-evidence.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=1, sort_keys=True, default=str) + '\n')
    return evidence


def free_port() -> int:
    probe = socket.socket()
    probe.bind(('127.0.0.1', 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='W15 resident research rehearsal (offline)')
    parser.add_argument('--listen', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=0)
    parser.add_argument('--psk-file', type=pathlib.Path, default=PSK_FILE)
    parser.add_argument('--out', type=pathlib.Path, default=pathlib.Path('.'))
    parser.add_argument('--store', type=pathlib.Path, default=None,
                        help='verification evidence store root (default: <out>/store)')
    parser.add_argument('--payload-bin', default='')
    parser.add_argument('--payload-elf', default='')
    parser.add_argument('--payload-manifest', default='')
    parser.add_argument('--payload-build-id', default='')
    parser.add_argument('--payload-label', default='')
    parser.add_argument('--gap-sec', type=float, default=0.0)
    parser.add_argument('--no-redial-sec', type=float, default=10.0)
    parser.add_argument('--target', default=None)
    parser.add_argument('--no-health', action='store_true')
    args = parser.parse_args(argv)

    port = args.port or free_port()
    store_root = args.store or (pathlib.Path(args.out) / 'store')
    payload = {'bin_sha256': args.payload_bin, 'elf_sha256': args.payload_elf,
               'build_manifest_sha256': args.payload_manifest, 'build_id': args.payload_build_id,
               'label': args.payload_label}
    evidence = rehearse(host=args.listen, port=port, psk=pathlib.Path(args.psk_file).read_bytes(),
                        out_dir=pathlib.Path(args.out), store_root=pathlib.Path(store_root),
                        payload=payload, no_redial_sec=args.no_redial_sec, gap_sec=args.gap_sec,
                        target=args.target, health_check=not args.no_health)
    print(json.dumps({'verdict': evidence.get('verdict'), 'stop_reason': evidence.get('stop_reason'),
                      'out': str(pathlib.Path(args.out))}, sort_keys=True))
    return 0 if evidence.get('verdict') == 'PASS' else 3


if __name__ == '__main__':
    raise SystemExit(main())
