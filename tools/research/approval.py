#!/usr/bin/env python3
"""W13 — the section 70 approval: ONE trust object, and it only answers ONE question.

Owner separation rule (W13 read 1 review):

* the **section 70 approval** answers *"may the already verified ``kernel.read`` provider run at all
  in this run?"* — existing approval schema, existing approval contract
  (:data:`SCHEMA_APPROVAL`, the vocabulary of :mod:`tools.primitive_iface.gate`);
* the **W13 research release** (:mod:`tools.research.release`) answers *"which concrete research
  window may be read exactly once?"*.

Neither may stand in for the other: a release document fails this module's schema check
(``W12_APPROVAL_SCHEMA_INVALID``) and an approval document fails the release's schema check
(``W13_RELEASE_INVALID``). The release additionally carries ``approval_sha256`` — the canonical hash
of this approval document — so a release is bound to the exact approval it was released under.

This module never approves anything itself: it only *reads* the owner's record, checks it against
the current run context and refuses otherwise. An agent must never self-approve.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from tools.hostctl.kreadstore import canonical_bytes                        # noqa: E402

SCHEMA_APPROVAL = 'ps4rf.w12.section70-approval.v1'

#: An approval that declares this read scope makes a W13 release MANDATORY: a valid approval alone
#: must never authorise a non-bootstrap research read (owner rule 3).
READ_SCOPE_RESEARCH = 'w13-research-read'

APPROVAL_INVALID = 'W12_APPROVAL_INVALID'
APPROVAL_SCHEMA_INVALID = 'W12_APPROVAL_SCHEMA_INVALID'
APPROVAL_MISSING = 'APPROVAL_MISSING'                    # the gate's own vocabulary
APPROVAL_PROFILE_MISMATCH = 'KREAD_WRONG_PROFILE'
APPROVAL_BOOT_MISMATCH = 'KREAD_STALE_BOOT_ID'
APPROVAL_EVIDENCE_MISMATCH = 'W13_APPROVAL_EVIDENCE_MISMATCH'
APPROVAL_VERIFICATION_MISMATCH = 'W13_APPROVAL_VERIFICATION_MISMATCH'

REFUSALS = (APPROVAL_INVALID, APPROVAL_SCHEMA_INVALID, APPROVAL_MISSING, APPROVAL_PROFILE_MISMATCH,
            APPROVAL_BOOT_MISMATCH, APPROVAL_EVIDENCE_MISMATCH, APPROVAL_VERIFICATION_MISMATCH)


def approval_sha256(document: dict) -> str:
    """The immutable identifier of an approval document (JCS bytes, nothing excluded).

    The release binds to exactly this value, so the identifier must cover every field the owner
    wrote — including the note that says who recorded it.
    """
    return hashlib.sha256(canonical_bytes(document)).hexdigest()


def load_approval(path: str | pathlib.Path) -> dict:
    """Read the approval document (fail closed: a malformed record is a refusal, not a traceback)."""
    try:
        document = json.loads(pathlib.Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise ValueError(f'{APPROVAL_INVALID}: {exc}') from exc
    if not isinstance(document, dict):
        raise ValueError(f'{APPROVAL_INVALID}: the approval is not a JSON object')
    return document


def is_research_approval(approval: dict) -> bool:
    """True when this approval declares the W13 research read scope (then a release is required)."""
    return str((approval or {}).get('read_scope') or '').strip().lower() == READ_SCOPE_RESEARCH


def approval_problems(approval: dict, *, profile_sha256: str | None = None,
                      boot_id: str | None = None, verification_run_id: str | None = None,
                      evidence_sha256: str | None = None) -> list[str]:
    """Every cross-check of the approval record. An empty list means the provider may run."""
    problems: list[str] = []
    if not isinstance(approval, dict):
        return [f'{APPROVAL_INVALID}: the approval is not a document']

    schema = approval.get('schema')
    if schema != SCHEMA_APPROVAL:
        problems.append(f'{APPROVAL_SCHEMA_INVALID}: schema {schema!r} is not {SCHEMA_APPROVAL!r} '
                        '(a W13 research release is not an approval, and an approval is not a '
                        'release)')
    if not approval.get('approved') or str(approval.get('state') or '').upper() != 'APPROVED':
        problems.append(f'{APPROVAL_MISSING}: the section 70 record is not approved '
                        f'(state: {approval.get("state", "absent")!r})')
    if not str(approval.get('id') or '').strip():
        problems.append(f'{APPROVAL_INVALID}: the approval carries no id')
    if not str(approval.get('approver') or '').strip():
        problems.append(f'{APPROVAL_INVALID}: the approval names no approver')
    if not str(approval.get('recorded_by') or '').strip():
        problems.append(f'{APPROVAL_INVALID}: the approval does not say who recorded it')

    if profile_sha256 is not None and approval.get('profile_sha256') not in (None, profile_sha256):
        problems.append(f'{APPROVAL_PROFILE_MISMATCH}: the approval names profile '
                        f'{str(approval.get("profile_sha256"))[:16]}…, the current profile is '
                        f'{profile_sha256[:16]}…')
    if boot_id is not None and approval.get('boot_id') not in (None, boot_id):
        problems.append(f'{APPROVAL_BOOT_MISMATCH}: the approval names boot '
                        f'{approval.get("boot_id")!r}, the current binding is {boot_id!r}')
    if verification_run_id is not None and approval.get('verification_run_id') not in (
            None, verification_run_id):
        problems.append(f'{APPROVAL_VERIFICATION_MISMATCH}: the approval names verification run '
                        f'{approval.get("verification_run_id")!r}, this run uses '
                        f'{verification_run_id!r}')
    if evidence_sha256 is not None and approval.get('evidence_sha256') not in (None, evidence_sha256):
        problems.append(f'{APPROVAL_EVIDENCE_MISMATCH}: the approval names Evidence '
                        f'{str(approval.get("evidence_sha256"))[:16]}…, the store holds '
                        f'{evidence_sha256[:16]}…')
    return problems


def approval_summary(approval: dict) -> dict:
    """The read-only summary recorded in the run evidence (never an authorisation)."""
    return {'id': approval.get('id'), 'state': approval.get('state'),
            'approver': approval.get('approver'), 'read_scope': approval.get('read_scope'),
            'profile_sha256': approval.get('profile_sha256'), 'boot_id': approval.get('boot_id'),
            'verification_run_id': approval.get('verification_run_id'),
            'evidence_sha256': approval.get('evidence_sha256'),
            'sha256': approval_sha256(approval)}


def _self_test() -> list[str]:
    checks: list[str] = []
    context = {'profile_sha256': 'a' * 64, 'boot_id': 'BOOT-selftest',
               'verification_run_id': 'VRUN-selftest', 'evidence_sha256': 'b' * 64}
    approval = {'schema': SCHEMA_APPROVAL, 'id': '§70-SELFTEST', 'state': 'APPROVED',
                'approved': True, 'approver': 'owner', 'recorded_by': 'transcription',
                'read_scope': READ_SCOPE_RESEARCH, **context}
    if approval_problems(approval, **context):
        checks.append(f'the reference approval was refused: '
                      f'{approval_problems(approval, **context)}')
    mutations = {
        APPROVAL_SCHEMA_INVALID: dict(approval, schema='ps4rf.w13.research-read-release.v1'),
        APPROVAL_MISSING: dict(approval, state='PENDING', approved=False),
        APPROVAL_PROFILE_MISMATCH: dict(approval, profile_sha256='c' * 64),
        APPROVAL_BOOT_MISMATCH: dict(approval, boot_id='BOOT-other'),
        APPROVAL_VERIFICATION_MISMATCH: dict(approval, verification_run_id='VRUN-other'),
        APPROVAL_EVIDENCE_MISMATCH: dict(approval, evidence_sha256='d' * 64),
    }
    for expected, mutated in mutations.items():
        reasons = {problem.split(':', 1)[0] for problem in approval_problems(mutated, **context)}
        if expected not in reasons:
            checks.append(f'the mutation for {expected} reported {sorted(reasons)}')
    if not is_research_approval(approval) or is_research_approval({'schema': SCHEMA_APPROVAL}):
        checks.append('the research read scope marker is not recognised reliably')
    if approval_sha256(approval) == approval_sha256(dict(approval, id='§70-OTHER')):
        checks.append('two different approvals share one canonical hash')
    return checks


def main(argv: list[str]) -> int:                                           # pragma: no cover
    if '--self-test' in argv:
        problems = _self_test()
        if problems:
            print('approval self-test: FAILED')
            for problem in problems:
                print(f'  - {problem}')
            return 1
        print('approval self-test: OK (schema separation, context binding, canonical hash)')
        return 0
    if '--check' in argv:
        document = load_approval(argv[argv.index('--check') + 1])
        problems = approval_problems(document)
        print(json.dumps({'approval': approval_summary(document), 'problems': problems},
                         indent=1, sort_keys=True, ensure_ascii=False))
        return 0 if not problems else 1
    print(__doc__)
    return 0


if __name__ == '__main__':                                                  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
