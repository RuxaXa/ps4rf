"""``ps4rfctl`` -- the W8 host controller.

Modes::

    selftest   offline end-to-end: listen on a local port, run the host build of the agent
               against it, drive the approved sequence, write evidence. No console contact.
    listen     the live mode: listen for the agent's reverse connection (arriving through
               the relay bridge), then drive the approved sequence.
    verify     re-hash an evidence pack and re-check its internal consistency.

The controller never contacts the console itself: the payload is delivered separately
(one single upload after the BinLoader rearm confirmation) and the agent connects out.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.rpc import wire                                    # noqa: E402
from core.rpc.handshake import ProtocolError                 # noqa: E402
from core.session.states import SessionState                  # noqa: E402
from tools.hostctl import attest, boot, bootpriv, smoke                  # noqa: E402
from tools.profiles import bootid                              # noqa: E402
from tools.profiles.binding import BootBinding                 # noqa: E402
from tools.profiles.schema import canonical_profile_sha256     # noqa: E402
from tools.hostctl.endpoint import (EndpointClosed, SocketEndpoint,       # noqa: E402
                                    connect_localhost, listen)
from tools.hostctl.evidence import (RunRecord, sha256_bytes, sha256_file,  # noqa: E402
                                    write_evidence)
from tools.hostctl.session import HostSession, SessionError, smoke_request_id  # noqa: E402

from tools.primitive_iface.validate import (InterfaceError,             # noqa: E402
                                            validate_response_envelope)


def read_psk(path: str) -> bytes:
    data = pathlib.Path(path).read_bytes()
    if len(data) < 32:
        raise SystemExit(f'{path}: expected at least 32 key bytes')
    return data[:32]


def local_utc() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def capture_events(rec, session, *, w9: bool = False, w11: bool = False) -> dict:
    """W11.1A: the one implementation of "what happens to captured EVENT frames".

    Called after a successful ``drive()`` and in the agent-stop branch of *every* runner
    (offline self test, listen, live). Before this change the live branch recorded a failed check
    and never copied the captured ``boot.binding`` event into the evidence -- exactly the
    ``boot_binding_event: null`` gap of the W11.1 live run, even though the console had sent the
    event. One shared function means the paths cannot diverge again.

    Returns the boot-binding verification report (empty when this is not a W11 run).
    """
    capture = session.event_capture_report()
    rec.doc['event_capture'] = capture
    if session.frame_trace:
        rec.doc['frame_trace'] = session.frame_trace
    if capture['schema_rejected']:
        rec.doc['event_schema_rejected'] = capture['schema_rejected']
        rec.check('event:no schema rejection', False, json.dumps(capture['schema_rejected'])[:400])
    elif session.events:
        rec.check('event:no schema rejection', True, '')
    if capture['unknown_events']:
        rec.doc['unknown_events'] = capture['unknown_events']
    if capture['duplicate_events']:
        rec.doc['duplicate_events'] = capture['duplicate_events']
    if capture['refused_events']:
        rec.doc['refused_events'] = capture['refused_events']

    report: dict = {}
    if not w11:
        return report

    event = session.boot_binding
    rec.doc['boot_binding_event'] = event
    if session.events_raw:
        rec.doc['boot_binding_frame_sha256'] = sha256_bytes(session.events_raw[-1])
    received_detail = 'no EVENT frame arrived before the session ended'
    if capture['schema_rejected']:
        received_detail = f"EVENT_SCHEMA_REJECTED: {json.dumps(capture['schema_rejected'])[:300]}"
    rec.check('w11:boot.binding event received', event is not None, received_detail)
    profile_path = REPO_ROOT / 'profiles' / 'fw1352' / 'profile-13.52.json'
    if not profile_path.exists():
        rec.check('w11:promoted profile present', False, f'missing {profile_path}')
        return report
    profile = json.loads(profile_path.read_text())
    profile_sha = canonical_profile_sha256(profile)
    report = boot.verify_boot_event(event, profile=profile, profile_sha256=profile_sha)
    rec.doc['boot_binding_verified'] = {k: v for k, v in report.items() if k != 'binding'}
    rec.doc['boot_binding_profile_sha256'] = profile_sha
    rec.check('w11:boot binding verified on the host side', bool(report.get('verified')),
              '; '.join(report.get('problems') or []))
    if report.get('no_boot_id'):
        rec.check('w11.1:no boot id was derived (fail closed)', True,
                  f"run status {report.get('diagnosis', {}).get('run_status_name')!r}")
        rec.check('w11.1:cause classified from measured values',
                  bool(report.get('diagnosis', {}).get('complete')),
                  f"classes {report.get('diagnosis', {}).get('classes')!r}")
    else:
        rec.check('w11:read1 == read2 inside this boot',
                  bool(report.get('stability', {}).get('reads_identical')),
                  'the source is not stable: BOOT_SOURCE_NOT_STABLE')
        view = report.get('binding_view') or {}
        rec.doc['boot_binding_view'] = view
        rec.check('w11:binding binds exactly this profile hash',
                  view.get('profile_sha256') == profile_sha and
                  bool(view.get('valid_for_this_boot')),
                  f'binding {view!r} does not bind the promoted profile')
    rec.check('w11:no simulated boot id in the evidence',
              bootid.LABEL_SIMULATED_REBOOT_VECTOR not in json.dumps(
                  {'label': (event or {}).get('label'), 'labels': report.get('labels')}),
              f"labels {report.get('labels')!r} label {(event or {}).get('label')!r}")
    return report


def capture_privileged_event(rec, session) -> dict:
    """W11.2: the sealed ``boot.binding.privileged`` event and the host-side verification.

    Same shared bookkeeping as the W11 path (schema rejections, unknown/duplicate/refused events,
    frame trace), because a privileged event is an event like any other. What differs is the
    verdict: the payload reports raw bytes and observed numbers only, and the host turns them into
    the boot identity -- re-deriving the base relation, decoding the timeval itself, applying the
    refusal rules and forming the canonical object, its digest and the public boot id. No boot id
    exists unless every one of those checks passed.
    """
    capture = session.event_capture_report()
    rec.doc['event_capture'] = capture
    if session.frame_trace:
        rec.doc['frame_trace'] = session.frame_trace
    if capture['schema_rejected']:
        rec.doc['event_schema_rejected'] = capture['schema_rejected']
        rec.check('event:no schema rejection', False, json.dumps(capture['schema_rejected'])[:400])
    elif session.events:
        rec.check('event:no schema rejection', True, '')
    for key in ('unknown_events', 'duplicate_events', 'refused_events'):
        if capture[key]:
            rec.doc[key] = capture[key]

    event = session.boot_binding_privileged
    rec.doc['boot_binding_privileged_event'] = event
    if session.events_raw:
        rec.doc['boot_binding_privileged_frame_sha256'] = sha256_bytes(session.events_raw[-1])
    received_detail = 'no EVENT frame arrived before the session ended'
    if capture['schema_rejected']:
        received_detail = f"EVENT_SCHEMA_REJECTED: {json.dumps(capture['schema_rejected'])[:300]}"
    rec.check('w11.2:boot.binding.privileged event received', event is not None, received_detail)
    if event is None:
        return {}

    profile_path = REPO_ROOT / 'profiles' / 'fw1352' / 'profile-13.52.json'
    if not profile_path.exists():
        rec.check('w11.2:promoted profile present', False, f'missing {profile_path}')
        return {}
    profile = json.loads(profile_path.read_text())
    profile_sha = canonical_profile_sha256(profile)
    report = bootpriv.verify_privileged_event(event, profile=profile, profile_sha256=profile_sha,
                                              host_wall_clock=int(time.time()))
    rec.doc['boot_binding_privileged_verified'] = {k: v for k, v in report.items()
                                                   if k != 'binding'}
    rec.doc['boot_binding_privileged_profile_sha256'] = profile_sha
    rec.check('w11.2:privileged boot read verified on the host side', bool(report.get('verified')),
              '; '.join(report.get('problems') or []))
    if report.get('verified') and report.get('outcome') == 'OK':
        view = report.get('binding_view') or {}
        rec.doc['boot_binding_privileged_view'] = view
        rec.check('w11.2:binding binds exactly this profile hash',
                  view.get('profile_sha256') == profile_sha and
                  bool(view.get('valid_for_this_boot')),
                  f'binding {view!r} does not bind the promoted profile')
        rec.check('w11.2:boot id formed host side from the measured bytes',
                  bool(report.get('boot_id')) and report.get('payload_claimed_boot_id') is False,
                  f"boot id {report.get('boot_id')!r} claimed {report.get('boot_id_claim')!r}")
    elif report.get('verified'):
        # a valid outcome without a boot id: the read was refused or never completed
        rec.check(f"w11.2:host classified the outcome ({report.get('outcome')})", True,
                  f"stop reason {report.get('stop_reason')!r}")
    else:
        rec.check('w11.2:no boot id without a verified privileged read (fail closed)', True,
                  f"run status {event.get('run_status_name')!r} cb {event.get('cb_status_name')!r}")
    return report


W12_PROFILE_PATH = REPO_ROOT / 'profiles' / 'fw1352' / 'profile-13.52.json'
W12_DEFAULT_STORE = str(pathlib.Path.home() / '.hermes/cache/scratch/ps4rf-w12/store')


def w12_options(parser) -> None:
    """W12 two-phase live flow: PHASE A (``--w12-verify-run``) / PHASE B (``--w12-read-run``).

    Two phases, two invocations, two uploads, two rearm confirmations: nothing hands off from
    phase A to phase B automatically, and phase B can only run against the record phase A wrote
    into the evidence store.
    """
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--w12-verify-run', action='store_true', dest='w12_verify_run',
                       help='W12 PHASE A: one upload and one session; the fixed bootstrap '
                            'verify.kernel.read, host re-derivation of the bytes/hash against the '
                            'pinned image_elf expectation, one persisted VerificationEvidence. '
                            'Zero generic provider entries.')
    group.add_argument('--w12-read-run', action='store_true', dest='w12_read_run',
                       help='W12 PHASE B: a SEPARATE upload and a NEW session; load and rehash the '
                            'persisted VerificationEvidence, resolve the capability (W4 gate, W5 '
                            'profile binding, boot binding, W7 router) and perform exactly one '
                            'generic bounded kernel.read. Needs --w12-verification-run-id and its '
                            'own rearm confirmation.')
    parser.add_argument('--w12-boot-id', default=None,
                        help='W12: the boot id of THIS boot (both phases must name the same boot; '
                             'a different boot refuses with KREAD_STALE_BOOT_ID)')
    parser.add_argument('--w12-verification-run-id', default=None,
                        help='W12 PHASE B: the verification run id of the persisted '
                             'VerificationEvidence phase A wrote')
    parser.add_argument('--w12-run-id', default=None,
                        help='W12: the run id of this phase (default: derived from the session)')
    parser.add_argument('--w12-store', default=W12_DEFAULT_STORE,
                        help='W12: the verification-evidence store shared by both phases')
    parser.add_argument('--w12-live-approved', action='store_true',
                        help='W12 PHASE B: the explicit live approval of the provider; without it '
                             'the W7 router defers (KREAD_LIVE_APPROVAL_REQUIRED) and no read '
                             'happens')
    parser.add_argument('--w12-approval', default=None,
                        help='W12 PHASE B: path to the section 70 approval record (JSON) the '
                             'capability decision needs')
    parser.add_argument('--w12-rearm-confirmed', action='store_true',
                        help='W12 (listen mode): the operator confirmed that exactly one payload '
                             'was delivered for THIS phase')
    parser.add_argument('--w13-release', default=None, dest='w13_release',
                        help='W13 PHASE B: path to the research read release record (JSON). The '
                             'release names the ONE window a research read may touch (region, '
                             'offset, length, expected bytes + sha256, profile, boot, state); the '
                             'window is built from it with the fail-closed cross-checks of '
                             'tools/research/release.py. Without this flag the read keeps the '
                             'frozen bootstrap window (W12 behaviour, unchanged).')


#: W13 separation messages (owner rules 1-3): an approval is not a release and a release is not an
#: approval; a research read needs both, bound to each other.
W13A_MISSING_MESSAGE = ('a W13 research read needs the section 70 approval (--w12-approval) BESIDE '
                        'the release: the release selects the window, the approval authorises the '
                        'provider -- neither stands in for the other')
W13R_REQUIRED_MESSAGE = ('this section 70 approval releases a W13 RESEARCH read, but no research '
                         'release record was given: a valid approval alone never authorises a '
                         'non-bootstrap window')


def w12_preflight(args) -> dict:
    """Validate the W12 phase configuration before anything is uploaded (fail closed).

    Returns ``{}`` for a non-W12 run. A missing phase input is a configuration error and stops the
    invocation before a bridge, a listener or an upload exists: the driver never starts a live
    phase on a half-configured flow.
    """
    phase = ('w12-verify-run' if getattr(args, 'w12_verify_run', False)
             else 'w12-read-run' if getattr(args, 'w12_read_run', False) else None)
    if phase is None:
        return {}
    mode = getattr(args, 'mode', '')
    boot_id = getattr(args, 'w12_boot_id', None)
    if not boot_id:
        raise SystemExit('W12: --w12-boot-id is required: name the boot this phase runs in (the '
                         'current boot binding both phases must agree on)')
    if phase == 'w12-read-run' and not getattr(args, 'w12_verification_run_id', None):
        raise SystemExit('W12 PHASE B: --w12-verification-run-id is required; it names the '
                         'persisted VerificationEvidence phase A wrote (there is no automatic '
                         'hand-off from phase A to phase B)')
    window = None
    release_summary = None
    approval_summary = None
    approval_path = getattr(args, 'w12_approval', None)
    approval_document = None
    approval_sha = None
    if approval_path:
        # the section 70 approval is its own trust object: read it once, for both paths below
        from tools.hostctl.kreadstore import canonical_evidence_sha256
        from tools.research import approval as W13A
        try:
            approval_document = W13A.load_approval(approval_path)
        except ValueError as exc:
            raise SystemExit(f'W12_APPROVAL_INVALID: {exc}') from exc
        approval_sha = W13A.approval_sha256(approval_document)
    if getattr(args, 'w13_release', None):
        from tools.hostctl.kreadstore import VerificationEvidenceStore
        from tools.profiles.schema import canonical_profile_sha256
        from tools.research import approval as W13A
        from tools.research import release as W13R
        if phase != 'w12-read-run':
            raise SystemExit('W13: --w13-release belongs to a research READ (--w12-read-run); '
                             'the verification phase never takes a release')
        approval_path = getattr(args, 'w12_approval', None)
        if not approval_path:
            raise SystemExit('W13_RELEASE_APPROVAL_MISSING: a research read needs the section 70 '
                             'approval (--w12-approval) BESIDE the release; the release never '
                             'stands in for the approval')
        release_file = pathlib.Path(args.w13_release)
        if pathlib.Path(approval_path).resolve() == release_file.resolve():
            raise SystemExit('W13_RELEASE_APPROVAL_NOT_SEPARATE: the approval record and the '
                             'research release record are the same file; they are two trust '
                             'objects (approval_sha256 != release_sha256)')
        try:
            document = W13R.load_release(args.w13_release)
        except ValueError as exc:
            raise SystemExit(f'W13_RELEASE_REFUSED: {exc}') from exc
        profile = json.loads(W12_PROFILE_PATH.read_text())
        profile_sha = canonical_profile_sha256(profile)
        store = VerificationEvidenceStore(getattr(args, 'w12_store', W12_DEFAULT_STORE))
        try:
            evidence = store.load_verification(getattr(args, 'w12_verification_run_id', None))
        except Exception as exc:                     # noqa: BLE001 - store refusals are fail closed
            raise SystemExit(f'W13_APPROVAL_EVIDENCE_MISMATCH: the store does not hold the '
                             f'verification this approval names ({type(exc).__name__}: {exc})') \
                from exc
        approval_problems_ = W13A.approval_problems(
            approval_document, profile_sha256=profile_sha, boot_id=boot_id,
            verification_run_id=getattr(args, 'w12_verification_run_id', None),
            evidence_sha256=canonical_evidence_sha256(evidence))
        if approval_problems_:
            raise SystemExit('W12_APPROVAL_REFUSED: ' + '; '.join(approval_problems_))
        built = W13R.released_window(document, profile=profile, profile_sha256=profile_sha,
                                     boot_id=boot_id, approval_sha256=approval_sha)
        if built['problems']:
            raise SystemExit('W13_RELEASE_REFUSED: ' + '; '.join(built['problems']))
        # W13-C1: when the release pins a payload, this run must carry exactly that build -- a
        # release for one payload never authorises another (the check runs before anything else
        # and before the bridge, the relay or any upload)
        payload_bin_ = getattr(args, 'payload_bin', None)
        if payload_bin_:
            delivered = pathlib.Path(payload_bin_)
            sibling_elf = delivered.with_suffix('.elf')
            sibling_manifest = delivered.parent.parent / 'build_manifest.json'
            payload_problems_ = W13R.payload_problems(
                document,
                bin_sha256=sha256_file(str(delivered)) if delivered.exists() else None,
                elf_sha256=sha256_file(str(sibling_elf)) if sibling_elf.exists() else None,
                build_manifest_sha256=(sha256_file(str(sibling_manifest))
                                       if sibling_manifest.exists() else None))
            if payload_problems_:
                raise SystemExit('W13_RELEASE_PAYLOAD_REFUSED: ' + '; '.join(payload_problems_))
        try:
            consumed = store.load_release_consumption(built['release']['release_id'])
        except Exception as exc:                     # noqa: BLE001
            raise SystemExit(f'W13_RELEASE_CONSUMPTION_INVALID: {exc}') from exc
        if consumed is not None:
            raise SystemExit(f"W13_RELEASE_ALREADY_CONSUMED: release "
                             f"{built['release']['release_id']!r} was consumed at the provider "
                             f"entry of read run {consumed.get('read_run_id')!r}; a release is "
                             'usable exactly once')
        window = built['window']
        release_summary = built['release']
        approval_summary = W13A.approval_summary(approval_document)
    elif approval_document is not None:
        from tools.research import approval as W13A
        if W13A.is_research_approval(approval_document):
            raise SystemExit('W13_RELEASE_REQUIRED: this section 70 approval releases a W13 '
                             'RESEARCH read; a valid approval alone never authorises a '
                             'non-bootstrap research window -- the release record is missing')
    if mode == 'live':
        if not getattr(args, 'rearm_confirmed', False):
            print(json.dumps({'verdict': 'BLOCKED', 'phase': phase, 'mode': mode,
                              'note': 'no --rearm-confirmed: this phase uploads nothing; rerun '
                                      'with --rearm-confirmed after reariming the BinLoader for '
                                      'exactly one payload'}, indent=1), flush=True)
    elif not getattr(args, 'w12_rearm_confirmed', False):
        raise SystemExit(f'W12 {phase} (listen mode): --w12-rearm-confirmed is required; this '
                         'phase needs its own explicit confirmation that exactly one payload was '
                         'delivered for it')
    return {'phase': phase, 'mode': mode, 'boot_id': boot_id,
            'store': getattr(args, 'w12_store', W12_DEFAULT_STORE),
            'run_id': getattr(args, 'w12_run_id', None),
            'verification_run_id': getattr(args, 'w12_verification_run_id', None),
            'expected_window': window, 'w13_release': release_summary,
            'w12_approval': approval_summary}


def w12_phase_run(session, rec, args, *, phase: str) -> dict:
    """Run ONE W12 phase (A or B) in this session and record it in the W8 evidence document.

    The phase logic itself lives in ``tools/hostctl/kreadlive.py`` (one entry point per phase);
    this function only supplies the profile, the boot binding, the provider identity, the approval
    record and the store, and records the outcome plus the provider-entry count.
    """
    from tools.hostctl import kreadlive as KL
    from tools.hostctl.kreadstore import VerificationEvidenceStore

    profile = json.loads(W12_PROFILE_PATH.read_text())
    profile_sha = canonical_profile_sha256(profile)
    boot_binding = BootBinding(boot_id=args.w12_boot_id, profile_sha256=profile_sha)
    store = VerificationEvidenceStore(args.w12_store)
    provider = {'name': KL.PROVIDER_NAME, 'provider_type': KL.PROVIDER_TYPE,
                'state': KL.PROVIDER_STATE_WIRED,
                'live_approved': bool(getattr(args, 'w12_live_approved', False))}
    # ---- the two trust objects, read separately (owner rule 1/2/3) --------------------------
    approval = None
    approval_document = None
    approval_sha = None
    if getattr(args, 'w12_approval', None):
        from tools.research import approval as W13A
        try:
            approval_document = W13A.load_approval(args.w12_approval)
        except ValueError as exc:
            rec.check(f'W12 {phase}: approval record readable', False, str(exc))
            return {'outcome': 'REFUSED', 'problems': [f'W12_APPROVAL_INVALID: {exc}'],
                    'generic_provider_entries': 0}
        approval = approval_document
        approval_sha = W13A.approval_sha256(approval_document)
    expected_window = None
    release_path = getattr(args, 'w13_release', None)
    if release_path and not approval_document:
        rec.check(f'W13 {phase}: approval beside the release', False, W13A_MISSING_MESSAGE)
        return {'outcome': 'REFUSED',
                'problems': [f'W13_RELEASE_APPROVAL_MISSING: {W13A_MISSING_MESSAGE}'],
                'generic_provider_entries': 0}
    if release_path:
        from tools.research import approval as W13A
        from tools.research import release as W13R
        if pathlib.Path(args.w12_approval).resolve() == pathlib.Path(release_path).resolve():
            rec.check(f'W13 {phase}: approval and release are separate records', False,
                      'the same file was handed in twice')
            return {'outcome': 'REFUSED',
                    'problems': ['W13_RELEASE_APPROVAL_NOT_SEPARATE: the approval record and the '
                                 'research release record are the same file'],
                    'generic_provider_entries': 0}
        try:
            _document = W13R.load_release(release_path)
        except ValueError as exc:
            rec.check(f'W13 {phase}: release record readable', False, str(exc))
            return {'outcome': 'REFUSED', 'problems': [f'W13_RELEASE_REFUSED: {exc}'],
                    'generic_provider_entries': 0}
        _evidence_sha = None
        try:
            _evidence = store.load_verification(args.w12_verification_run_id)
            from tools.hostctl.kreadstore import canonical_evidence_sha256 as _ces
            _evidence_sha = _ces(_evidence)
        except Exception as exc:                     # noqa: BLE001 - store refusals are fail closed
            rec.check(f'W13 {phase}: approval evidence present', False, str(exc))
            return {'outcome': 'REFUSED',
                    'problems': [f'W13_APPROVAL_EVIDENCE_MISMATCH: {exc}'],
                    'generic_provider_entries': 0}
        _approval_problems = W13A.approval_problems(
            approval_document, profile_sha256=profile_sha, boot_id=args.w12_boot_id,
            verification_run_id=args.w12_verification_run_id, evidence_sha256=_evidence_sha)
        if _approval_problems:
            rec.check(f'W13 {phase}: approval valid for this run', False,
                      '; '.join(_approval_problems))
            return {'outcome': 'REFUSED',
                    'problems': [f'W12_APPROVAL_REFUSED: {p}' for p in _approval_problems],
                    'generic_provider_entries': 0}
        _built = W13R.released_window(_document, profile=profile, profile_sha256=profile_sha,
                                      boot_id=args.w12_boot_id, approval_sha256=approval_sha)
        if _built['problems']:
            rec.check(f'W13 {phase}: release window accepted', False, '; '.join(_built['problems']))
            return {'outcome': 'REFUSED',
                    'problems': [f'W13_RELEASE_REFUSED: {p}' for p in _built['problems']],
                    'generic_provider_entries': 0}
        try:
            _consumed = store.load_release_consumption(_built['release']['release_id'])
        except Exception as exc:                     # noqa: BLE001
            rec.check(f'W13 {phase}: release consumption state readable', False, str(exc))
            return {'outcome': 'REFUSED',
                    'problems': [f'W13_RELEASE_CONSUMPTION_INVALID: {exc}'],
                    'generic_provider_entries': 0}
        if _consumed is not None:
            rec.check(f'W13 {phase}: release not consumed yet', False,
                      f"consumed by {_consumed.get('read_run_id')!r}")
            return {'outcome': 'REFUSED',
                    'problems': [f"W13_RELEASE_ALREADY_CONSUMED: release "
                                 f"{_built['release']['release_id']!r} was consumed at the "
                                 f"provider entry of read run {_consumed.get('read_run_id')!r}"],
                    'generic_provider_entries': 0}
        expected_window = _built['window']
        rec.doc['w13_release'] = _built['release']
        rec.doc['w12_approval'] = W13A.approval_summary(approval_document)
        rec.note(f"W13 release window: release_id={_built['release']['release_id']} "
                 f"sha256={_built['release']['sha256'][:16]}… region="
                 f"{_built['release']['region']} rva={_built['release']['rva']} "
                 f"offset={_built['release']['offset']} length={_built['release']['length']} "
                 f"expected_sha256={_built['release']['expected_sha256']} "
                 f"approval_sha256={str(_built['release']['approval_sha256'])[:16]}…")
    elif approval_document is not None:
        from tools.research import approval as W13A
        if W13A.is_research_approval(approval_document):
            rec.check(f'W13 {phase}: release record present', False, W13R_REQUIRED_MESSAGE)
            return {'outcome': 'REFUSED',
                    'problems': [f'W13_RELEASE_REQUIRED: {W13R_REQUIRED_MESSAGE}'],
                    'generic_provider_entries': 0}
    rec.note(f'W12 {phase}: profile={W12_PROFILE_PATH} sha256={profile_sha} '
             f'boot_id={args.w12_boot_id} store={args.w12_store} '
             f'provider={provider["name"]}/{provider["provider_type"]} '
             f'live_approved={provider["live_approved"]}')
    result = KL.run_phase(phase, session, profile=profile, boot_binding=boot_binding, store=store,
                          provider=provider, verification_run_id=args.w12_verification_run_id,
                          run_id=args.w12_run_id, approval=approval, expected=expected_window)
    rec.doc['w12'] = result
    rec.check(f'W12 {phase}: outcome {result["outcome"]}', result['ok'],
              '; '.join(str(problem) for problem in result['problems']))
    expected_entries = 0 if phase == KL.PHASE_VERIFY else 1
    rec.check(f'W12 {phase}: generic provider entries == {expected_entries}',
              result['generic_provider_entries'] == expected_entries,
              f'this phase counted {result["generic_provider_entries"]} generic provider entries '
              '(phase A must never enter the provider; phase B enters it exactly once)')
    for entry in result.get('checks') or ():
        if not entry.get('ok'):
            rec.check(f'W12 {phase}: {entry.get("name")}', False, str(entry.get('detail') or ''))
    rec.doc['w12_phase'] = phase
    rec.doc['w12_artifacts'] = {
        'verification_evidence_sha256': (result.get('evidence') or {}).get('evidence_sha256')
        if phase == KL.PHASE_VERIFY else result.get('evidence_sha256'),
        'evidence_path': result.get('evidence_path'),
        'read_run_record_path': result.get('read_run_record_path'),
        'run_separation': result.get('run_separation'),
        'decision': (result.get('decision') or {}).get('outcome'),
        'decision_stopped_at': (result.get('decision') or {}).get('stopped_at'),
        'decision_reasons': (result.get('decision') or {}).get('reasons'),
    }
    return result


def drive(session: HostSession, rec: RunRecord, *, actor_label: str,
          w9: bool = False, w11: bool = False, w112: bool = False) -> dict:
    """Handshake, READY, the approved sequence. Returns a summary dict with the verdicts."""
    session.handshake()
    rec.doc['handshake'] = {
        'transcript_sha256': session.transcript_hex,
        'session_id': session.session_id,
        'agent': session.hello_seen,
        'actor': actor_label,
    }
    attestation = session.recv_ready()
    rec.doc['attestation'] = attestation

    refs: dict[str, dict] = {}
    ok = True
    for step in (smoke.sequence_w9() if w9 else smoke.sequence()):
        arguments = {}
        for key, value in step.arguments.items():
            if isinstance(value, str) and value.startswith('@'):
                ref_step, _, field = value[1:].partition('.')
                arguments[key] = refs[ref_step][field]
            else:
                arguments[key] = value
        rid = smoke_request_id(len(rec.doc['requests']))
        requested = local_utc()
        try:
            response = session.request(step.op, arguments, request_id=rid)
        except SessionError as exc:
            # W9 fail-closed: the agent ends the session itself when the fixed attestation step
            # does not complete. That is a documented outcome, not a controller crash -- the
            # event it sent before the BYE is verified below.
            if not (w9 and session.bye is not None):
                raise
            rec.note(f'W9: the agent closed the session during {step.name}: '
                     f'{session.bye.get("reason")}')
            ok = False
            break
        responded = local_utc()
        route = smoke.expected_route(step.op)
        entry = smoke.provider_entry_observed(step.op, response)
        detail_false = smoke.detail_provider_entry_false(response)
        status = response.get('status')
        code = (response.get('error') or {}).get('code')

        outcome_matches = True
        problems = []
        if status != step.expect_status:
            problems.append(f'status {status!r} != {step.expect_status!r}')
        if step.expect_code is not None and code != step.expect_code:
            problems.append(f'code {code!r} != {step.expect_code!r}')
        if step.expect_detail_contains and step.expect_detail_contains not in (
                (response.get('error') or {}).get('detail') or ''):
            problems.append(f'detail missing {step.expect_detail_contains!r}')
        if step.check is not None:
            problem = step.check(response, refs)
            if problem:
                problems.append(problem)
        if status == 'OK':
            try:
                validate_response_envelope(step.op, response)
            except InterfaceError as exc:
                problems.append(f'frozen response schema: {exc}')
        expected_entry = route == 'stub' and code is None
        if step.op == 'kernel.read':
            expected_entry = False
        if entry != expected_entry:
            problems.append(f'provider_entry {entry} != expected {expected_entry}')
        if problems:
            ok = False
        outcome_matches = not problems

        rec.add_request(step=step.name, request=session_request(step, arguments, rid),
                        response=response, request_id=rid, route_expected=route,
                        provider_entry=entry, provider_entry_detail=detail_false,
                        outcome_matches=outcome_matches,
                        response_frame_sha256='',
                        requested_utc=requested, responded_utc=responded)
        refs[step.name] = response.get('result') or {}
        rec.check(f'step:{step.name}', outcome_matches, '; '.join(problems))

        if not ok:
            break

    if w9:
        # The kernel.attestation event: recorded raw, then verified against the host's own copy
        # of the expected table. A payload claim alone is never the verdict.
        event = session.attestation
        rec.doc['kernel_attestation_event'] = event
        if session.events_raw:
            rec.doc['kernel_attestation_frame_sha256'] = sha256_bytes(session.events_raw[-1])
        if event is None:
            rec.doc['kernel_attestation_verified'] = {
                'verified': False, 'problems': ['no kernel.attestation event was received']}
            ok = False
            rec.check('w9:kernel.attestation event received', False,
                      'no EVENT frame arrived before the session ended')
        else:
            report = attest.verify_attestation(event)
            rec.doc['kernel_attestation_verified'] = report
            event_ok = report['verified'] and event.get('status') == 'OK'
            ok = ok and event_ok
            rec.check('w9:kernel.attestation event received', True, '')
            rec.check('w9:kernel.attestation verified on the host side', report['verified'],
                      '; '.join(report['problems']))
            rec.check('w9:attestation status OK', event.get('status') == 'OK',
                      f"status {event.get('status')!r}")
            rec.check('w9:no resource change across the attestation',
                      (refs.get('status_before') or {}).get('held_resources') ==
                      (refs.get('status_after') or {}).get('held_resources'),
                      'held_resources differ between the two status responses')

    if w11:
        # W11 / W11.1: the boot.binding event. The console reports raw userland KERN_BOOTTIME reads
        # only; the host re-checks stability, re-derives the digest with the one agreed algorithm
        # (ps4rf.boot-binding.v1) and forms the runtime binding. A payload claim alone is never the
        # verdict, and a simulated value is never accepted here.
        report = capture_events(rec, session, w11=True)
        ok = ok and bool(report.get('verified'))

    if w112:
        # W11.2: the fixed privileged boot read. The payload measured the 16 bytes; the verdict,
        # the canonical object and the boot id are formed here, or not at all.
        report_priv = capture_privileged_event(rec, session)
        ok = ok and bool(report_priv.get('verified'))

    if session.bye is not None:
        # The agent already closed the session itself (W9: attestation failure). Recorded as is.
        session.close()
        return {'ok': ok, 'bye': session.bye}

    # Controlled exit: the host half-closes, the agent sees EOF and sends its BYE, then the
    # host closes. The BYE is best effort -- a missing BYE is recorded, not invented.
    session.ep.shutdown_write()
    bye = session.await_bye('host half close (SHUT_WR)')
    session.close()
    return {'ok': ok, 'bye': bye}


def session_request(step, arguments, rid) -> dict:
    return {'header': {'request_id': rid}, 'body': {'operation': step.op, 'arguments': arguments}}


def build_record(*, run_id: str, mode: str, psk_file: str, transport: dict,
                 payload: dict, repo: dict) -> RunRecord:
    rec = RunRecord(run_id=run_id, mode=mode, repo=repo, payload=payload, transport=transport)
    rec.note(f'psk source: {os.path.basename(psk_file)} (never stored, never hashed here)')
    return rec


def repo_state() -> dict:
    def git(*args):
        try:
            return subprocess.run(['git', *args], cwd=REPO_ROOT, capture_output=True,
                                  text=True, check=True).stdout.strip()
        except Exception:
            return ''
    return {
        'commit': git('rev-parse', 'HEAD'),
        'commit_short': git('rev-parse', '--short', 'HEAD'),
        'branch': git('rev-parse', '--abbrev-ref', 'HEAD'),
        'core_revision': 'R2 (F7)',
        'worktree_dirty': bool(git('status', '--porcelain')),
    }


def payload_state(elf: str | None, manifest: str | None, binfile: str | None) -> dict:
    state: dict = {'elf_path': elf, 'manifest_path': manifest, 'bin_path': binfile}
    for key, path in (('elf_sha256', elf), ('build_manifest_sha256', manifest), ('bin_sha256', binfile)):
        state[key] = sha256_file(path) if path and pathlib.Path(path).exists() else None
    state['reproducible'] = None
    return state


def verified_payload_state(binfile: str, *, expect_bin: str | None = None,
                           expect_elf: str | None = None,
                           expect_manifest: str | None = None) -> tuple[dict, list[str]]:
    """Resolve the delivery artefact and verify it against the released hashes.

    Fail closed: any mismatch is reported and the caller must not deliver. The sibling ELF and
    the build manifest are picked up next to the BIN (``build-a/ps4rfd.bin`` ->
    ``build-a/ps4rfd.elf`` and ``../build_manifest.json``) so the evidence records paths *and*
    hashes instead of one masquerading as the other.
    """
    problems: list[str] = []
    bin_path = pathlib.Path(binfile)
    if not bin_path.exists():
        return {'bin_path': str(bin_path), 'bin_sha256': None}, [f'missing artefact {bin_path}']
    elf_path = bin_path.with_suffix('.elf')
    manifest_path = bin_path.parent.parent / 'build_manifest.json'
    state = payload_state(str(elf_path) if elf_path.exists() else None,
                          str(manifest_path) if manifest_path.exists() else None,
                          str(bin_path))
    for label, got, expect in (('bin', state['bin_sha256'], expect_bin),
                               ('elf', state['elf_sha256'], expect_elf),
                               ('manifest', state['build_manifest_sha256'], expect_manifest)):
        if expect and got != expect:
            problems.append(f'{label} sha256 {got} != released {expect}')
    state['verified_against_release'] = not problems
    return state, problems


# ------------------------------------------------------------------------ modes

def live_agent_stop_outcome(rec, session, exc, *, w11: bool,
                           w112: bool = False) -> tuple[dict, bool]:
    """W11.1A: what a *live* run does when the agent stops itself.

    One implementation, used by both live modes and by the offline replay tool
    (``tools/hostctl/replay_live_capture.py``), so the live semantics can be exercised offline:
    everything the agent sent before its BYE -- including the sealed boot.binding event -- goes
    into the evidence *before* the outcome is decided. The pre-fix branch simply recorded a failed
    check here and dropped the captured event, which is the W11.1 live gap.

    A decisive diagnosis without a boot identity is the expected W11.1 outcome and counts as a
    successful run; anything else is a failed live session.
    """
    rec.doc['stopped_by_agent'] = {'reason': (session.bye or {}).get('reason'), 'detail': str(exc)}
    if w112:
        # W11.2: a stop after a *failed* privileged read is the designed fail-closed outcome and
        # counts as a successful run of the wave; the measured raw values are the finding. A stop
        # after a verified read is unexpected and is recorded as such.
        report_priv = capture_privileged_event(rec, session)
        verified = bool(report_priv.get('verified'))
        rec.check('live session (agent stopped after the privileged boot read)',
                  not verified,
                  'the session stopped even though the privileged boot read verified')
        return ({'ok': not verified and report_priv.get('no_boot_id', True) is True,
                 'diagnosis_only': not verified, 'bye': session.bye},
                bool(not verified))
    diagnosis_ok = False
    if w11 or session.events:
        report_capture = capture_events(rec, session, w11=w11)
        diagnosis_ok = bool(report_capture.get('no_boot_id') and report_capture.get('verified'))
        if diagnosis_ok:
            rec.check('w11.1:diagnosis complete without a boot id', True,
                      f"run status {report_capture.get('diagnosis', {}).get('run_status_name')!r}")
    if diagnosis_ok:
        rec.check('live session (agent stopped at the boot binding, expected)', True,
                  f"stopped by agent: {(session.bye or {}).get('reason')!r}")
        return {'ok': True, 'diagnosis_only': True, 'bye': session.bye}, True
    rec.check('live session', False, str(exc))
    return {'ok': False, 'bye': session.bye}, False


def mode_selftest(args) -> int:
    agent = args.agent_binary or str(REPO_ROOT / 'native/build/target-host/ps4rfd_host')
    if not pathlib.Path(agent).exists():
        raise SystemExit(f'agent binary not found: {agent} (run native/target/build_host.sh)')
    psk = read_psk(args.psk_file)
    with tempfile.TemporaryDirectory() as tmp:
        psk_path = os.path.join(tmp, 'psk.bin')
        pathlib.Path(psk_path).write_bytes(psk)
        srv = listen(0, timeout=120.0)
        port = srv.getsockname()[1]
        proc = subprocess.Popen([agent, '--connect', '127.0.0.1', str(port), '--psk-file', psk_path,
                                 '--label', 'selftest-agent', '--context', 'offline-loopback'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        conn, _ = srv.accept()
        ep = SocketEndpoint(conn, timeout=60.0)
        run_id = 'RUN-' + hashlib.sha256(f'selftest/{time.time()}'.encode()).hexdigest()[:16]
        rec = build_record(run_id=run_id, mode='offline-loopback', psk_file=args.psk_file,
                           transport={'kind': 'loopback', 'listener': f'127.0.0.1:{port}'},
                           payload={'kind': 'host-build', 'path': agent,
                                    'sha256': sha256_file(agent)},
                           repo=repo_state())
        w11 = bool(getattr(args, 'w11_boot_binding', False))
        w112 = bool(getattr(args, 'w112_privileged_boot_read', False))
        session = HostSession(ep, psk,
                              accept_event=bool(args.w9_attestation) or w11 or w112)
        try:
            result = drive(session, rec, actor_label='offline self test',
                           w9=bool(args.w9_attestation), w11=w11, w112=w112)
        except (SessionError, ProtocolError, EndpointClosed) as exc:
            # The agent stops itself when the boot binding cannot be formed (fail closed by design).
            # The stop is recorded, not hidden; whatever it reported first goes into the evidence as
            # it arrived. W11.1: a *decisive diagnosis* of a failed read is the expected outcome of
            # this wave and counts as a successful offline run.
            rec.doc['stopped_by_agent'] = {'reason': (session.bye or {}).get('reason'),
                                           'detail': str(exc)}
            diagnosis_ok = False
            if w112:
                # W11.2: a stop after a failed privileged read is the designed fail-closed
                # outcome of this wave and counts as a successful offline run; the measured raw
                # values are the finding. No boot id exists in that case, by construction.
                report_priv = capture_privileged_event(rec, session)
                diagnosis_ok = bool(report_priv.get('verified')
                                    and report_priv.get('no_boot_id') is True)
            elif w11 or session.events:
                # one shared implementation: captured events always reach the evidence, whether the
                # session ended by host half-close or because the agent stopped itself
                report_capture = capture_events(rec, session, w11=w11)
                diagnosis_ok = bool(report_capture.get('no_boot_id')
                                    and report_capture.get('verified'))
                if diagnosis_ok:
                    rec.check('w11.1:diagnosis complete without a boot id', True,
                              f"run status "
                              f"{report_capture.get('diagnosis', {}).get('run_status_name')!r}")
            if diagnosis_ok:
                rec.check('offline session (agent stopped at the boot binding, expected)', True,
                          f"stopped by agent: {(session.bye or {}).get('reason')!r}")
                result = {'ok': True, 'diagnosis_only': True, 'bye': session.bye}
            else:
                rec.check('offline session', False, str(exc))
                result = {'ok': False, 'bye': session.bye}
        finally:
            session.close()
            srv.close()
        out, err = proc.communicate(timeout=30)
        rec.doc['agent_process'] = {'exit_code': proc.returncode, 'stdout': out.strip()[:4000],
                                    'stderr': err.strip()[:4000]}
        # A diagnosis-only W11.1 run is *supposed* to end with the agent's own failure exit: the
        # agent refuses to keep a session whose boot identity it could not establish.
        exit_as_designed = proc.returncode == 0 or bool(result.get('diagnosis_only'))
        rec.check('agent exit code as designed', exit_as_designed,
                  f'exit={proc.returncode} (diagnosis_only={bool(result.get("diagnosis_only"))})')
        # W11.1: a decisive diagnosis ends with the agent's own failure exit by design, so that
        # exit is expected here and does not turn the run into a framework failure.
        verdict = 'PASS' if (result['ok'] and (proc.returncode == 0
                                               or bool(result.get('diagnosis_only')))) else 'FAIL'
        rec.check('offline end-to-end', verdict == 'PASS')
        doc = rec.finalize(session={'final_state': SessionState.CLOSED.value,
                                    'cleanup_state': (result['bye'] or {}).get('cleanup', {}).get('state')
                                    if result['bye'] else None},
                           bye=result['bye'], health=None, verdict=verdict)
        path = write_evidence(doc, args.out)
        print(json.dumps({'verdict': verdict, 'evidence': str(path),
                          'checks_failed': [c['name'] for c in doc['checks'] if not c['ok']],
                          'requests': len(doc['requests'])}, indent=1))
        return 0 if verdict == 'PASS' else 1


def mode_listen(args) -> int:
    w12 = w12_preflight(args)          # fail closed before the listener or any payload
    psk = read_psk(args.psk_file)
    srv = listen(args.bind_port, host=args.bind_host, timeout=args.accept_timeout)
    print(json.dumps({'listening': f'{args.bind_host}:{args.bind_port}',
                      'accept_timeout_s': args.accept_timeout}, indent=1), flush=True)
    conn, peer = srv.accept()
    ep = SocketEndpoint(conn, timeout=args.io_timeout)
    rec = build_record(run_id=args.run_id or ('RUN-' + hashlib.sha256(f'{peer}/{time.time()}'.encode()).hexdigest()[:16]),
                       mode='live', psk_file=args.psk_file,
                       transport={'kind': 'reverse-tcp-through-bridge', 'peer': str(peer),
                                  'listener': f'{args.bind_host}:{args.bind_port}',
                                  'payload_port': args.payload_port,
                                  'console': args.console},
                       payload=payload_state(args.expect_elf, args.expect_manifest, args.expect_bin),
                       repo=repo_state())
    w11 = bool(getattr(args, 'w11_boot_binding', False))
    w112 = bool(getattr(args, 'w112_privileged_boot_read', False))
    session = HostSession(ep, psk,
                          accept_event=bool(getattr(args, 'w9_attestation', False)) or w11 or
                          w112 or bool(w12))
    try:
        # W12: one invocation is exactly ONE phase (never both, never chained); phase B only ever
        # reads the record phase A persisted, loaded and rehashed by the evidence store.
        result = (w12_phase_run(session, rec, args, phase=w12['phase']) if w12
                  else drive(session, rec, actor_label='live target',
                             w9=bool(getattr(args, 'w9_attestation', False)), w11=w11,
                             w112=w112))
    except (SessionError, ProtocolError, EndpointClosed) as exc:
        # W11.1A: everything the agent sent before its BYE reaches the evidence first, then the
        # outcome is decided -- both live modes call the one shared implementation.
        result, _ = live_agent_stop_outcome(rec, session, exc, w11=w11, w112=w112)
    finally:
        session.close()
        srv.close()
    verdict = 'PASS' if result['ok'] else 'FAIL'
    rec.check('live session completed', result['ok'])
    doc = rec.finalize(session={'final_state': SessionState.CLOSED.value,
                                'held_resources': None,
                                'cleanup_state': (result['bye'] or {}).get('cleanup', {}).get('state')
                                if result['bye'] else None},
                       bye=result['bye'], health=None, verdict=verdict)
    path = write_evidence(doc, args.out)
    print(json.dumps({'verdict': verdict, 'evidence': str(path),
                      'checks_failed': [c['name'] for c in doc['checks'] if not c['ok']],
                      'requests': len(doc['requests'])}, indent=1))
    return 0 if verdict == 'PASS' else 1


def mode_live(args) -> int:
    """Live mode: bridge + tunnel + controller, then ONE payload upload.

    The upload is mechanically gated: it only happens after the operator confirms the
    BinLoader rearm on this command line (``--rearm-confirmed``) -- the controller never
    contacts the PayLoader port by itself and never probes it. Health checks afterwards use
    only the known safe read-only checks (FTP banner 2121, port 3232, ICMP); port 9090 is
    never touched again.
    """
    import socket as _socket
    import sys as _sys

    w12 = w12_preflight(args)          # fail closed before the bridge, the relay or any upload
    orbisprobe_root = pathlib.Path(args.orbisprobe_root)
    if not (orbisprobe_root / 'orbisprobe' / 'live' / 'transport.py').exists():
        raise SystemExit(f'orbisprobe not found at {orbisprobe_root}')
    _sys.path.insert(0, str(orbisprobe_root))
    from orbisprobe.live.transport import WorkerConfig, WorkerConsoleTransport

    config = WorkerConfig(console_ip=args.console_ip, payload_port=args.payload_port,
                          bridge_payload_port=args.bridge_payload_port,
                          bridge_host_port=args.bridge_host_port, local_port=args.local_port,
                          ssh_target=args.ssh_target)
    transport = WorkerConsoleTransport(config)
    psk = read_psk(args.psk_file)
    payload = pathlib.Path(args.payload_bin).read_bytes()

    # artefact verification happens before anything is started or sent (fail closed)
    payload_state_doc, payload_problems = verified_payload_state(
        args.payload_bin, expect_bin=args.expect_bin, expect_elf=args.expect_elf,
        expect_manifest=args.expect_manifest)
    if payload_problems:
        raise SystemExit('ARTEFACT_MISMATCH: ' + '; '.join(payload_problems))

    tunnel = None
    if args.relay:
        from tools.hostctl import relay
        started = relay.push_and_start(args.ssh_target, args.bridge_payload_port,
                                       args.bridge_host_port, args.bridge_lifetime)
        rec_extra = {'relay': started.get('log', ''), 'relay_script': started.get('script')}
    else:
        started = transport.start_bridge(lifetime=args.bridge_lifetime)
        rec_extra = {'bridge': started.get('output', '')}
    rec = build_record(run_id=args.run_id or ('RUN-live-' + hashlib.sha256(
                           f'{args.console_ip}/{time.time()}'.encode()).hexdigest()[:16]),
                       mode='live', psk_file=args.psk_file,
                       transport={'kind': 'reverse-tcp-through-bridge',
                                  'console': args.console_ip,
                                  'payload_port': args.payload_port,
                                  'bridge_payload_port': args.bridge_payload_port,
                                  'bridge_host_port': args.bridge_host_port,
                                  'local_port': args.local_port,
                                  'ssh_target': args.ssh_target,
                                  **rec_extra},
                       payload=payload_state_doc,
                       repo=repo_state())
    rec.doc['wire_parity'] = {
        'agent_wire_variant': False,
        'frozen_sources': True,
        'catalogue_replay': 'proven by the W8 gate (native/target/build_ps4.sh, '
                            'tests/test_target_build.py) over the identical frozen sources',
    }
    rec.note('delivery: single HTTP POST /payload (connect == send), no probe connection')
    rec.note(f'binary to deliver: {args.payload_bin} sha256={hashlib.sha256(payload).hexdigest()}')

    if args.relay:
        tunnel = relay.open_tunnel(args.ssh_target, args.local_port, args.bridge_host_port)
    else:
        transport.open_tunnel()
    # The tunnel owns the local port and forwards to the relay on the relay host; the
    # controller *connects* through it. The relay pairs this side with the agent's reverse
    # connection when the payload attaches.

    def cleanup() -> None:
        if args.relay:
            relay.stop(args.ssh_target)
            relay.close_tunnel(tunnel)
        else:
            transport.stop_bridge()
            transport.close()

    log_tail = (relay.relay_log(args.ssh_target) if args.relay
                else started.get('output', '')).strip()
    print(json.dumps({'state': 'RELAY_UP', 'relay': log_tail,
                      'local_port': args.local_port,
                      'note': 'agent-side connection is expected through the relay'},
                     indent=1), flush=True)

    # Hard gate: the upload only happens with the operator's explicit rearm confirmation.
    deliver = None
    if not args.rearm_confirmed:
        rec.note('no --rearm-confirmed: no upload attempted (W8 rule: no automatic live send)')
        rec.check('upload gated by operator confirmation', True, 'not confirmed, nothing sent')
        verdict = 'BLOCKED'
        doc = rec.finalize(session=None, bye=None, health=None, verdict=verdict)
        path = write_evidence(doc, args.out)
        print(json.dumps({'verdict': verdict, 'evidence': str(path),
                          'note': 'relay is up; rerun with --rearm-confirmed after reariming '
                                  'the BinLoader to deliver exactly one payload'}, indent=1))
        cleanup()
        return 2

    rec.check('operator confirmed BinLoader rearm', args.rearm_confirmed is True)
    deliver = transport.send_payload(payload, timeout=args.deliver_timeout)
    rec.doc['delivery'] = deliver
    rec.check('single upload accepted', bool(deliver.get('ok')),
              f"status={deliver.get('status')} sha256={deliver.get('sha256')}")
    if not deliver.get('ok'):
        doc = rec.finalize(session=None, bye=None, health=None, verdict='FAIL')
        path = write_evidence(doc, args.out)
        rec.doc['transport']['session_log'] = _ssh_cat(
            args.ssh_target, '/tmp/ps4rf_relay.log' if args.relay else '/tmp/console_bridge.log')
        doc = rec.finalize(session=None, bye=None, health=None, verdict='FAIL')
        path = write_evidence(doc, args.out)
        print(json.dumps({'verdict': 'FAIL', 'evidence': str(path), 'delivery': deliver}, indent=1))
        cleanup()
        return 1

    ep = connect_localhost(args.local_port)
    rec.note('controller connected through the tunnel to the relay bridge; waiting for the agent')
    w11 = bool(getattr(args, 'w11_boot_binding', False))
    w112 = bool(getattr(args, 'w112_privileged_boot_read', False))
    session = HostSession(ep, psk,
                          accept_event=bool(getattr(args, 'w9_attestation', False)) or w11 or
                          w112 or bool(w12))
    try:
        # W12: one invocation is exactly ONE phase (never both, never chained); phase B only ever
        # reads the record phase A persisted, loaded and rehashed by the evidence store.
        result = (w12_phase_run(session, rec, args, phase=w12['phase']) if w12
                  else drive(session, rec, actor_label='live target',
                             w9=bool(getattr(args, 'w9_attestation', False)), w11=w11,
                             w112=w112))
    except (SessionError, ProtocolError, EndpointClosed) as exc:
        # W11.1A: everything the agent sent before its BYE reaches the evidence first, then the
        # outcome is decided -- both live modes call the one shared implementation.
        result, _ = live_agent_stop_outcome(rec, session, exc, w11=w11, w112=w112)
    finally:
        session.close()

    health = live_health(args.console_ip, args.payload_port)
    rec.doc['health'] = health
    for check_name, ok, detail in health['checks']:
        rec.check(f'health:{check_name}', ok, detail)
    verdict = 'PASS' if (result['ok'] and all(c[1] for c in health['checks'])) else 'FAIL'
    # the relay log is the peer proof: it names the console address and the byte counts
    rec.doc['transport']['session_log'] = _ssh_cat(
        args.ssh_target, '/tmp/ps4rf_relay.log' if args.relay else '/tmp/console_bridge.log')
    doc = rec.finalize(session={'final_state': SessionState.CLOSED.value,
                                'cleanup_state': (result['bye'] or {}).get('cleanup', {})
                                .get('state') if result['bye'] else None},
                       bye=result['bye'], health=health, verdict=verdict)
    path = write_evidence(doc, args.out)
    cleanup()
    print(json.dumps({'verdict': verdict, 'evidence': str(path),
                      'checks_failed': [c['name'] for c in doc['checks'] if not c['ok']],
                      'requests': len(doc['requests']), 'health': health['summary']}, indent=1))
    return 0 if verdict == 'PASS' else 1


def _ssh_cat(ssh_target: str, path: str) -> str:
    try:
        proc = subprocess.run(['ssh', '-o', 'BatchMode=yes', ssh_target, f'cat {path}'],
                              capture_output=True, text=True, timeout=30)
        return proc.stdout
    except Exception as exc:  # pragma: no cover - ssh transport failure
        return f'log unavailable: {type(exc).__name__}: {exc}'


def _probe_tcp_port(console_ip: str, port: int, *,
                   read_timeout: float = 2.0) -> tuple[bool, bool, str]:
    """Bounded TCP connect probe. Returns ``(connected, data_seen, detail)``.

    ``connected`` is the health-bearing fact: a service that accepts a connection is up. Whether it
    sends anything is *informational* only -- GoldHEN's port 3232 is a passive log stream that stays
    silent while the console idles, and treating that as a health failure was a probe design issue
    (deviation ``W11.2-D1: PASSIVE_LOG_STREAM_NO_BANNER``, disposition
    ``ACCEPTED_PROBE_DESIGN_ISSUE``).
    """
    import socket as _socket

    try:
        with _socket.create_connection((console_ip, port), timeout=5) as sock:
            sock.settimeout(read_timeout)
            try:
                data = sock.recv(64)
            except _socket.timeout:
                return True, False, (f'connect OK, no data within {read_timeout:g} s '
                                     '(passive log stream; not a health failure)')
            if not data:
                return True, False, 'connect OK, peer closed without data'
            first = data.decode('utf-8', 'replace').strip()[:64]
            return True, True, f'connect OK; first line {first!r}'
    except OSError as exc:
        return False, False, f'{type(exc).__name__}: {exc}'


def live_health(console_ip: str, payload_port: int, *,
                ports: dict | None = None) -> dict:
    """Known safe, read-only checks after the agent exited. The PayLoader port is never
    among them.

    * ``ftp-2121-banner``: the FTP server speaks first, so a banner is still expected.
    * ``port-3232-connect``: bounded TCP connect. Port 3232 is GoldHEN's passive log stream, so a
      silent stream is not a health failure (W11.2-D1). ``log_activity_observed`` reports whether a
      line happened to arrive and is deliberately kept **outside** ``checks`` so it can never
      influence the target health verdict.
    * ``icmp``: reachability.
    * ``payload-port-untouched``: the loader port is excluded from every health check.
    """
    import socket as _socket

    ports = {'ftp': 2121, 'log': 3232, **(ports or {})}
    checks: list[tuple[str, bool, str]] = []
    try:
        with _socket.create_connection((console_ip, ports['ftp']), timeout=5) as sock:
            sock.settimeout(3)
            banner = sock.recv(64)
        checks.append(('ftp-2121-banner', True, banner.decode('utf-8', 'replace').strip()[:64]))
    except OSError as exc:
        checks.append(('ftp-2121-banner', False, f'{type(exc).__name__}: {exc}'))
    connected, observed, detail = _probe_tcp_port(console_ip, ports['log'])
    checks.append(('port-3232-connect', connected, detail))
    try:
        import subprocess as _sp
        ping = _sp.run(['ping', '-c', '1', '-W', '2', console_ip], capture_output=True, text=True,
                       timeout=10)
        checks.append(('icmp', ping.returncode == 0, ping.stdout.strip().splitlines()[-1][:96]))
    except Exception as exc:  # pragma: no cover - ping may be unavailable
        checks.append(('icmp', False, f'{type(exc).__name__}: {exc}'))
    checks.append(('payload-port-untouched', payload_port == 9090 and True,
                   'the loader port is not part of any health check'))
    return {'checks': checks,
            # informational only: never part of `checks`, so it cannot flip the verdict
            'observed': {'log_activity_observed': observed},
            'summary': {name: ok for name, ok, _ in checks}}


def mode_verify(args) -> int:
    doc = json.loads(pathlib.Path(args.evidence).read_text())
    problems = []
    for req in doc.get('requests', []):
        if req.get('outcome_matches_frozen_route') is not True:
            problems.append(f"{req['request_id']}: route mismatch")
        if req['operation'] == 'kernel.read':
            # W14: kernel.read is wired on the target as the single bounded privileged provider,
            # so its request is expected to enter the provider exactly once on a target that
            # carries that provider. A build without it refuses fail-closed on the same wired
            # route ("not implemented by the native stub provider") and still records the entry.
            # What must never happen is a silent no-op, so the entry is required.
            if req.get('provider_entry') is not True:
                problems.append('kernel.read: the wired route must record its provider entry')
    if doc.get('verdict') != 'PASS':
        problems.append(f"verdict {doc.get('verdict')!r}")
    print(json.dumps({'evidence': args.evidence, 'verdict': doc.get('verdict'),
                      'problems': problems}, indent=1))
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog='ps4rfctl', description='PS4RF W8 host controller')
    sub = ap.add_subparsers(dest='mode', required=True)

    p = sub.add_parser('selftest')
    p.add_argument('--w11-boot-binding', action='store_true',
                   help='W11: expect the sealed boot.binding event and derive the boot id')
    p.add_argument('--w112-privileged-boot-read', action='store_true',
                   help='W11.2: expect the sealed boot.binding.privileged event and verify the '
                        'fixed privileged boot read host side')
    p.add_argument('--w9-attestation', action='store_true',
                   help='W9: drive the attestation sequence against the host agent build')
    p.add_argument('--psk-file', default=str(REPO_ROOT / '.psk-w8.bin'))
    p.add_argument('--agent-binary')
    p.add_argument('--out', default=str(pathlib.Path.home() / '.hermes/cache/scratch/ps4rf-w8/selftest'))
    p.set_defaults(func=mode_selftest)

    p = sub.add_parser('listen')
    p.add_argument('--psk-file', required=True)
    p.add_argument('--bind-host', default='127.0.0.1')
    p.add_argument('--bind-port', type=int, required=True)
    p.add_argument('--accept-timeout', type=float, default=600.0)
    p.add_argument('--io-timeout', type=float, default=60.0)
    p.add_argument('--run-id')
    p.add_argument('--console', default='')
    p.add_argument('--payload-port', type=int, default=9090)
    p.add_argument('--expect-elf')
    p.add_argument('--expect-bin')
    p.add_argument('--expect-manifest')
    p.add_argument('--out', default=str(pathlib.Path.home() / '.hermes/cache/scratch/ps4rf-w8/live'))
    w12_options(p)
    p.set_defaults(func=mode_listen)

    p = sub.add_parser('live')
    p.add_argument('--w11-boot-binding', action='store_true',
                   help='W11: expect the sealed boot.binding event and derive the boot id')
    p.add_argument('--w112-privileged-boot-read', action='store_true',
                   help='W11.2: expect the sealed boot.binding.privileged event and verify the '
                        'fixed privileged boot read host side')
    p.add_argument('--w9-attestation', action='store_true',
                   help='W9: accept the sealed kernel.attestation EVENT and run the '
                        'read-only attestation sequence (status, attestation, status)')
    p.add_argument('--psk-file', required=True)
    p.add_argument('--payload-bin', required=True)
    p.add_argument('--console-ip', default='192.168.1.141')
    p.add_argument('--payload-port', type=int, default=9090)
    p.add_argument('--bridge-payload-port', type=int, default=9028)
    p.add_argument('--bridge-host-port', type=int, default=9029)
    p.add_argument('--local-port', type=int, default=19029)
    p.add_argument('--ssh-target', default='neo@192.168.1.148')
    p.add_argument('--orbisprobe-root', default=str(pathlib.Path.home() / 'projects/orbisprobe'))
    p.add_argument('--bridge-lifetime', type=float, default=1200.0)
    p.add_argument('--accept-timeout', type=float, default=300.0)
    p.add_argument('--io-timeout', type=float, default=60.0)
    p.add_argument('--deliver-timeout', type=float, default=20.0)
    p.add_argument('--relay', action='store_true',
                   help='use the half-close aware relay (tools/relay/half_close_bridge.py) '
                        'instead of the OrbisProbe bridge; the agent BYE needs the half close')
    p.add_argument('--rearm-confirmed', action='store_true',
                   help='set ONLY after the owner confirmed the BinLoader rearm; '
                        'without it no payload is uploaded')
    p.add_argument('--run-id')
    p.add_argument('--expect-elf')
    p.add_argument('--expect-bin')
    p.add_argument('--expect-manifest')
    p.add_argument('--out', default=str(pathlib.Path.home() / '.hermes/cache/scratch/ps4rf-w8/live'))
    w12_options(p)
    p.set_defaults(func=mode_live)

    p = sub.add_parser('verify')
    p.add_argument('evidence')
    p.set_defaults(func=mode_verify)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    raise SystemExit(main())
