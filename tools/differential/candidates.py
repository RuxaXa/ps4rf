#!/usr/bin/env python3
"""PS4RF P4/W6 candidate generator: diffs become observations, never authorization.

A candidate is a *lead*, not a fact. Every candidate carries status ``OBSERVATION``,
names the evidence it came from (input and finding hashes), and names the path that
would have to be walked before it could influence anything:

    W6 diff -> candidate -> review/verification -> W5 profile update
            -> new profile_sha256 -> new boot/runtime binding

Candidates can never satisfy the W4 gate: ``impact.w4`` is ``NONE``, and the generator
imports no gate or profile *write* function - it cannot remove a W4 reason, allow a
provider, raise assurance, or remove ``NOT_WIRED``. A candidate also cannot become
``PROVEN``: the W6 vocabulary has no such status, and the validator refuses it.

Usage::

    python tools/differential/candidates.py --self-test
"""

from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from tools.differential import schema as SC  # noqa: E402
from core.canonical import canonical_sha256  # noqa: E402
from tools.differential.normalize import NormalizationError  # noqa: E402

REQUIRED_PATH = (
    'review by the owner (research lead)',
    'verification via the frozen evidence path (expected vs observed, hash-bound)',
    'W5 profile update -> new canonical_sha256',
    'new boot/runtime binding for the updated profile',
)

CLASS_TO_KIND = {
    SC.MOVED: 'locator_candidate',
    SC.SIGNATURE_CHANGED: 'expected_bytes_candidate',
    SC.PERMISSION_CHANGED: 'section_candidate',
    SC.CHANGED: 'profile_candidate',
    SC.ADDED: 'profile_candidate',
    SC.REMOVED: 'profile_candidate',
    SC.UNRESOLVED: 'research_note',
}

LAYER_KIND_OVERRIDE = {
    (SC.LAYER_OPERATION, SC.CHANGED): 'policy_candidate',
    (SC.LAYER_ARTIFACT, SC.SIGNATURE_CHANGED): 'section_candidate',
    (SC.LAYER_ARTIFACT, SC.MOVED): 'section_candidate',
    (SC.LAYER_EXTERNAL, SC.CHANGED): 'research_note',
}

IMPACT = {
    'w4': 'NONE',
    'w4_note': 'no W4 reason is removed, no provider allowed, no assurance raised, NOT_WIRED stays',
    'w5': 'PROFILE_UPDATE_REQUIRES_REVIEW',
    'w5_note': 'candidate is not a profile fact; it needs verification before a profile update',
    'executable': False,
}


def candidate_from_finding(finding: dict, inputs: list[dict]) -> dict | None:
    """One candidate per *difference* finding; UNCHANGED and INCOMPARABLE produce none."""
    if finding['class'] in (SC.UNCHANGED, SC.INCOMPARABLE, SC.ARTIFACT_MISSING):
        return None
    kind = LAYER_KIND_OVERRIDE.get((finding['layer'], finding['class'])) \
        or CLASS_TO_KIND.get(finding['class'])
    if kind is None:
        return None
    evidence = [
        {'kind': 'finding', 'id': finding['id'], 'class': finding['class'],
         'confidence': finding['confidence'], 'sha256': canonical_sha256(finding)},
        *[{'kind': 'input', 'role': item['role'], 'path': item.get('path'),
           'sha256': item.get('sha256')} for item in inputs if item.get('sha256')],
    ]
    candidate = {
        'schema': SC.CANDIDATE_SCHEMA,
        'id': '',
        'status': SC.CANDIDATE_STATUS[0],
        'kind': kind,
        'subject': finding['subject'],
        'operation': finding.get('operation'),
        'layer': finding['layer'],
        'class': finding['class'],
        'confidence': finding['confidence'],
        'before': finding['before'],
        'after': finding['after'],
        'evidence': evidence,
        'requires': list(REQUIRED_PATH),
        'impact': dict(IMPACT),
        'not_a_fact': True,
    }
    errors = SC.validate_candidate(candidate)
    if errors:
        raise NormalizationError(f'produced candidate is invalid: {errors}')
    return candidate


def generate(findings: list[dict], inputs: list[dict]) -> list[dict]:
    """Deterministic candidate list (ordered by subject, class, kind)."""
    candidates = [c for c in (candidate_from_finding(f, inputs) for f in findings) if c]
    candidates.sort(key=lambda c: (c['subject'], c['class'], c['kind']))
    for index, candidate in enumerate(candidates, start=1):
        candidate['id'] = f'C{index:04d}'
    return candidates


def handoff() -> dict:
    return {
        'status_vocabulary': list(SC.CANDIDATE_STATUS),
        'path': list(REQUIRED_PATH),
        'forbidden': ['removing a W4 reason', 'allowing a provider', 'raising assurance',
                      'removing NOT_WIRED', 'mutating an active profile'],
        'w4_impact': IMPACT['w4'],
    }


def _self_test() -> list[str]:
    checks: list[str] = []
    finding = {'id': 'F0001', 'layer': SC.LAYER_PROFILE, 'class': SC.MOVED,
               'confidence': SC.STRONG, 'subject': 'locators.kernel.read.locator.value',
               'operation': None, 'before': '0x0000000000001000',
               'after': '0x0000000000002000', 'provenance': {}}
    candidate = candidate_from_finding(finding, [{'role': 'before', 'path': 'a', 'sha256': 'a' * 64}])
    if candidate is None or candidate['status'] != 'OBSERVATION':
        checks.append('a differencing finding must produce an OBSERVATION candidate')
    if candidate and candidate['impact']['w4'] != 'NONE':
        checks.append('candidate impact on W4 must be NONE')
    if candidate_from_finding(dict(finding, class_=SC.UNCHANGED, **{'class': SC.UNCHANGED}), []):
        checks.append('an UNCHANGED finding must not produce a candidate')
    if not handoff()['forbidden']:
        checks.append('the handoff must name the forbidden shortcuts')
    return checks


def self_test() -> list[str]:
    return _self_test()


def main(argv: list[str]) -> int:
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: candidates.py --self-test')
        return 2
    failures = _self_test()
    if failures:
        print(f'candidates self-test: {len(failures)} FAILED')
        for item in failures:
            print(f'  - {item}')
        return 1
    print('candidates self-test: OK (OBSERVATION only, W4 impact NONE, review path named)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
