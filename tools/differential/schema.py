#!/usr/bin/env python3
"""PS4RF P4/W6 differential schema: classifications, confidence, findings, candidates.

A differential run produces *findings* and, at most, *candidates* with status
``OBSERVATION``. The vocabulary is deliberately narrow: no finding, and no candidate,
can ever say "vulnerability", "fixed", "exploitable", "BUG", "PRIMITIVE" or "PROVEN" -
those words are not part of the schema at all.

Report shape (``ps4rf.differential.run.v1``)::

    schema, run_id, timestamp, tool{name,version}, normalization_version, config_sha256,
    inputs[{role,kind,path,sha256,architecture}],
    findings[{id,layer,class,confidence,operation,before,after,provenance{input_sha256…}}],
    candidates[{schema,id,status,kind,subject,evidence,requires,impact}],
    summary{counts:{class…},findings,candidates,capped},
    output_sha256

Fail-closed input rules live in ``normalize``; this module owns the vocabulary and the
validation of produced objects.

Usage::

    python tools/differential/schema.py --self-test
    python tools/differential/schema.py --vocabulary
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

REPORT_SCHEMA = 'ps4rf.differential.run.v1'
CANDIDATE_SCHEMA = 'ps4rf.differential.candidate.v1'
INVENTORY_SCHEMA = 'ps4rf.differential.inventory.v1'
EXTERNAL_SCHEMA = 'ps4rf.external-analysis.v1'
TOOL_NAME = 'ps4rf-differential'
TOOL_VERSION = '0.1.0'

# --- classifications (exactly these, machine readable) --------------------------------
UNCHANGED = 'UNCHANGED'
ADDED = 'ADDED'
REMOVED = 'REMOVED'
MOVED = 'MOVED'
CHANGED = 'CHANGED'
PERMISSION_CHANGED = 'PERMISSION_CHANGED'
SIGNATURE_CHANGED = 'SIGNATURE_CHANGED'
UNRESOLVED = 'UNRESOLVED'
INCOMPARABLE = 'INCOMPARABLE'
ARTIFACT_MISSING = 'ARTIFACT_MISSING'

CLASSES = (UNCHANGED, ADDED, REMOVED, MOVED, CHANGED, PERMISSION_CHANGED,
           SIGNATURE_CHANGED, UNRESOLVED, INCOMPARABLE, ARTIFACT_MISSING)
DIFFERENCE_CLASSES = tuple(c for c in CLASSES if c != UNCHANGED)

# --- confidence -----------------------------------------------------------------------
EXACT = 'EXACT'
STRONG = 'STRONG'
WEAK = 'WEAK'
UNKNOWN = 'UNKNOWN'
CONFIDENCES = (EXACT, STRONG, WEAK, UNKNOWN)
CONFIDENCE_RANK = {EXACT: 3, STRONG: 2, WEAK: 1, UNKNOWN: 0}

# --- layers ---------------------------------------------------------------------------
LAYERS = ('identity', 'profile', 'artifact', 'operation', 'external')
LAYER_TARGET_IDENTITY = 'identity'
LAYER_PROFILE = 'profile'
LAYER_ARTIFACT = 'artifact'
LAYER_OPERATION = 'operation'
LAYER_EXTERNAL = 'external'

# --- candidate status -----------------------------------------------------------------
CANDIDATE_STATUS = ('OBSERVATION',)
CANDIDATE_KINDS = ('profile_candidate', 'locator_candidate', 'expected_bytes_candidate',
                   'policy_candidate', 'section_candidate', 'research_note')
# deliberately absent: any verdict-like state
FORBIDDEN_STATUS_WORDS = ('PROVEN', 'BUG', 'VULNERABILITY', 'EXPLOITABLE', 'PRIMITIVE',
                          'FIXED', 'VERIFIED')

EXTERNAL_TOOLS = ('ghidra', 'rizin', 'angr', 'aflplusplus', 'other')


class DifferentialError(Exception):
    """Fail-closed refusal while building differential objects."""


def class_counts(findings: list[dict]) -> dict:
    counts = {name: 0 for name in CLASSES}
    for finding in findings:
        counts[finding['class']] = counts.get(finding['class'], 0) + 1
    return {name: value for name, value in sorted(counts.items()) if value}


def cap_confidence(confidence: str, cap: str | None) -> str:
    """Apply the configured confidence cap (never raises a confidence)."""
    if cap is None:
        return confidence
    if CONFIDENCE_RANK[confidence] <= CONFIDENCE_RANK[cap]:
        return confidence
    return cap


def validate_finding(finding: dict) -> list[str]:
    errors: list[str] = []
    for key in ('id', 'layer', 'class', 'confidence', 'before', 'after', 'provenance'):
        if key not in finding:
            errors.append(f'finding: missing {key!r}')
    if finding.get('class') not in CLASSES:
        errors.append(f'finding: unknown class {finding.get("class")!r}')
    if finding.get('confidence') not in CONFIDENCES:
        errors.append(f'finding: unknown confidence {finding.get("confidence")!r}')
    if finding.get('layer') not in LAYERS:
        errors.append(f'finding: unknown layer {finding.get("layer")!r}')
    tokens = string_tokens(finding)
    for word in FORBIDDEN_STATUS_WORDS:
        if word in tokens:
            errors.append(f'finding: verdict-like wording {word!r} is not allowed')
    return errors


def string_tokens(obj) -> set[str]:
    """Every word used in a document's *values* (keys are structural, not claims)."""
    tokens: set[str] = set()
    if isinstance(obj, dict):
        for value in obj.values():
            tokens |= string_tokens(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            tokens |= string_tokens(value)
    elif isinstance(obj, str):
        tokens |= {t for t in re.findall(r'[A-Za-z_]+', obj.upper()) if t}
    return tokens


def validate_candidate(candidate: dict) -> list[str]:
    errors: list[str] = []
    if candidate.get('schema') != CANDIDATE_SCHEMA:
        errors.append(f'candidate: schema must be {CANDIDATE_SCHEMA!r}')
    if candidate.get('status') not in CANDIDATE_STATUS:
        errors.append(f'candidate: status must be {list(CANDIDATE_STATUS)}')
    if candidate.get('kind') not in CANDIDATE_KINDS:
        errors.append(f'candidate: unknown kind {candidate.get("kind")!r}')
    for key in ('id', 'subject', 'evidence', 'requires', 'impact'):
        if key not in candidate:
            errors.append(f'candidate: missing {key!r}')
    if not candidate.get('requires'):
        errors.append('candidate: requires must name the review/verification path')
    if (candidate.get('impact') or {}).get('w4') != 'NONE':
        errors.append('candidate: impact.w4 must be NONE (W6 is analysis, not authorization)')
    if candidate.get('evidence') and not all(e.get('sha256') for e in candidate['evidence']):
        errors.append('candidate: every evidence item needs a sha256')
    tokens = string_tokens(candidate)
    for word in FORBIDDEN_STATUS_WORDS:
        if word in tokens:
            errors.append(f'candidate: verdict-like wording {word!r} is not allowed')
    return errors


def validate_report(report: dict) -> list[str]:
    errors: list[str] = []
    if report.get('schema') != REPORT_SCHEMA:
        errors.append(f'report: schema must be {REPORT_SCHEMA!r}')
    for key in ('run_id', 'timestamp', 'tool', 'normalization_version', 'config_sha256',
                'inputs', 'findings', 'candidates', 'summary', 'output_sha256'):
        if key not in report:
            errors.append(f'report: missing {key!r}')
    for item in report.get('inputs', ()):
        if item.get('missing'):
            if item.get('sha256') is not None:
                errors.append(f'report: missing input {item.get("path")} must not claim a hash')
        elif not item.get('sha256'):
            errors.append(f'report: input {item.get("path")} carries no sha256')
    for finding in report.get('findings', ()):
        errors.extend(validate_finding(finding))
    for candidate in report.get('candidates', ()):
        errors.extend(f'candidate {candidate.get("id")}: {err}' for err in validate_candidate(candidate))
    return errors


def vocabulary() -> dict:
    return {
        'schema': REPORT_SCHEMA,
        'candidate_schema': CANDIDATE_SCHEMA,
        'inventory_schema': INVENTORY_SCHEMA,
        'external_schema': EXTERNAL_SCHEMA,
        'classes': list(CLASSES),
        'confidences': list(CONFIDENCES),
        'layers': list(LAYERS),
        'candidate_status': list(CANDIDATE_STATUS),
        'candidate_kinds': list(CANDIDATE_KINDS),
        'forbidden_words': list(FORBIDDEN_STATUS_WORDS),
        'external_tools': list(EXTERNAL_TOOLS),
    }


def _self_test() -> list[str]:
    checks: list[str] = []
    if 'EXPLOITABLE' in CLASSES or 'BUG' in CANDIDATE_STATUS:
        checks.append('the vocabulary must not contain verdict-like states')
    bad = {'id': 'F1', 'layer': 'profile', 'class': 'BUG', 'confidence': 'EXACT',
           'before': {}, 'after': {}, 'provenance': {}}
    if not validate_finding(bad):
        checks.append('unknown classes must be rejected')
    verdict = dict(bad, **{'class': CHANGED})
    verdict['provenance'] = {'note': 'vulnerability found'}
    if not validate_finding(verdict):
        checks.append('verdict-like wording must be rejected')
    if cap_confidence(EXACT, WEAK) != WEAK or cap_confidence(UNKNOWN, WEAK) != UNKNOWN:
        checks.append('confidence caps must only lower confidence')
    candidate = {'schema': CANDIDATE_SCHEMA, 'id': 'C1', 'status': 'OBSERVATION',
                 'kind': 'locator_candidate', 'subject': 'kernel.read', 'evidence': [],
                 'requires': ['review'], 'impact': {'w4': 'NONE'}}
    if validate_candidate(candidate):
        checks.append('a minimal observation candidate must validate')
    if not validate_candidate(dict(candidate, status='PROVEN')):
        checks.append('verdict-like candidate status must be rejected')
    if not validate_candidate(dict(candidate, **{'kind': 'exploit'})):
        checks.append('unknown candidate kinds must be rejected')
    return checks


def main(argv: list[str]) -> int:
    if '--vocabulary' in argv:
        print(json.dumps(vocabulary(), indent=1, sort_keys=True))
        return 0
    if '--self-test' not in argv:
        print((__doc__ or '').strip().splitlines()[0])
        print('usage: schema.py --self-test | --vocabulary')
        return 2
    failures = _self_test()
    if failures:
        print(f'differential schema self-test: {len(failures)} FAILED')
        for item in failures:
            print(f'  - {item}')
        return 1
    print(f'differential schema self-test: OK ({len(CLASSES)} classes, {len(CONFIDENCES)} '
          f'confidences, candidates stay {CANDIDATE_STATUS[0]})')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
