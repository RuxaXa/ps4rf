#!/usr/bin/env python3
"""W13 — the research read plan: built *exclusively* from ``APPROVED_READ`` regions.

Every entry is one bounded read of one approved window. The plan carries no address, only relative
locators, and it is not a release: ``live_status`` stays ``NOT_RELEASED`` until the owner approves a
first region in the offline review and a separate live gate opens.

Per entry (owner's §4): region, offset, length, purpose, expected datatype, max length, profile
provenance and the reason the read is safe.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from tools.profiles import regions as R                                    # noqa: E402
from tools.profiles.schema import canonical_profile_sha256                 # noqa: E402
from tools.research import classification as C                             # noqa: E402

SCHEMA_PLAN = 'ps4rf.research.read-plan.v1'
LIVE_STATUS_NOT_RELEASED = 'NOT_RELEASED'

#: The rules every entry of this plan obeys. A plan that breaks one of them is refused.
PLAN_RULES = (
    'one bounded read per entry; region + offset + length only, never an address',
    'only regions whose W13 class is APPROVED_READ may appear',
    'offset + length stays inside the region, length <= region max_size <= MAX_READ_LEN (4096)',
    'the read is bound to the active profile and to the boot the session proved',
    'a read is authorised by stored VerificationEvidence plus a W4 approval, per read, per session',
    'the plan itself authorises nothing: it is a reviewed proposal, not a capability',
)

#: What the entry's provenance must contain to count as "profile provenance".
PROVENANCE_REQUIRED = ('profiles/fw1352/profile-13.52.json',)


class ReadPlanError(Exception):
    """A malformed or over-reaching plan (fail closed)."""


def plan_entries(profile: dict | None = None) -> list[dict]:
    """One proposal per ``APPROVED_READ`` region, in the owner's §11 priority order."""
    profile = C.DEFAULT_PROFILE if profile is None else profile
    classification = {row['region']: row for row in C.classification_matrix(profile)['rows']}
    entries = []
    for region in C.approved_read_regions(profile):
        row = classification[region.name]
        review = row['review'] or {}
        max_length = min(region.length or 0, R.MAX_READ_LEN)
        entries.append({
            'region': region.name,
            'locator': region.locator,
            'rva': region.rva,
            'rva_hex': None if region.rva is None else hex(region.rva),
            'offset': 0,
            'length': max_length,
            'max_length': max_length,
            'region_max_size': region.length,
            'expected_datatype': review.get('expected_datatype', ''),
            'permissions': row['permissions'],
            'purpose': review.get('purpose', ''),
            'priority': review.get('priority'),
            'profile_provenance': list(region.provenance),
            'profile_requirement': region.profile_requirement,
            'why_read_safe': (
                'W13 APPROVED_READ: real W5 locator and W9 attest entry at the same rva, all '
                'provenance files present, one unambiguous profile binding, declared permissions '
                'plausible for the attested kind, no known instability, pinned bounds without '
                'overlap, and a documented review decision'
            ),
            'approval_needed': 'separate live release (owner) + W4 approval + fresh VerificationEvidence',
        })
    entries.sort(key=lambda entry: (entry['priority'] is None, entry['priority'] or 0,
                                    entry['region']))
    return entries


def read_plan(profile: dict | None = None) -> dict:
    active: dict = C.DEFAULT_PROFILE if profile is None else profile
    entries = plan_entries(active)
    body = {'schema': SCHEMA_PLAN, 'phase': 'W13 offline (read-only research baseline)',
            'live_status': LIVE_STATUS_NOT_RELEASED,
            'profile': {'path': str(C.PROFILE_PATH.relative_to(REPO_ROOT)),
                        'sha256': canonical_profile_sha256(active)},
            'rules': list(PLAN_RULES),
            'entries': entries}
    plan_id = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(',', ':')).encode())
    body['plan_id'] = plan_id.hexdigest()
    return body


def plan_problems(plan: dict | None = None, profile: dict | None = None) -> list[str]:
    """Every invariant of the plan, checked; a live status other than NOT_RELEASED is a problem."""
    profile = C.DEFAULT_PROFILE if profile is None else profile
    plan = read_plan(profile) if plan is None else plan
    problems: list[str] = []
    registry = R.regions()
    classes = {row['region']: row['class']
               for row in C.classification_matrix(profile)['rows']}
    if plan.get('live_status') != LIVE_STATUS_NOT_RELEASED:
        problems.append(f"live_status is {plan.get('live_status')!r}: W13 is offline only")
    seen = set()
    for entry in plan.get('entries', ()):
        name = entry['region']
        region = registry.get(name)
        if region is None:
            problems.append(f'{name}: in the plan but not registered')
            continue
        if name in seen:
            problems.append(f'{name}: listed twice')
        seen.add(name)
        if classes.get(name) != C.CLASS_APPROVED_READ:
            problems.append(f'{name}: in the plan with class {classes.get(name)}')
        offset, length = entry['offset'], entry['length']
        if not isinstance(offset, int) or not isinstance(length, int):
            problems.append(f'{name}: offset/length must be integers')
            continue
        if offset < 0 or length <= 0:
            problems.append(f'{name}: offset/length must be positive')
        if region.length is None or offset + length > region.length:
            problems.append(f'{name}: offset+length leaves the region window')
        if length > R.MAX_READ_LEN:
            problems.append(f'{name}: length {length} above MAX_READ_LEN')
        for field in ('purpose', 'expected_datatype', 'why_read_safe', 'profile_provenance'):
            if not entry.get(field):
                problems.append(f'{name}: {field} is empty')
        missing = [source for source in PROVENANCE_REQUIRED
                   if source not in entry.get('profile_provenance', ())]
        if missing:
            problems.append(f'{name}: profile provenance does not name {missing}')
        blob = json.dumps(entry)
        for forbidden in ('runtime_va', 'address', 'slide'):
            if f'"{forbidden}"' in blob:
                problems.append(f'{name}: the entry carries a {forbidden} field')
        conflict = C.datatype_section_conflict(
            region, ' '.join((entry.get('expected_datatype', ''), entry.get('purpose', ''),
                              entry.get('why_read_safe', ''))), profile)
        if conflict:
            problems.append(f'{name}: section/permission wording: {conflict}')
    approved = {region.name for region in C.approved_read_regions(profile)}
    if seen != approved:
        problems.append(f'the plan covers {sorted(seen)}, the class covers {sorted(approved)}')
    return problems


def plan_summary(plan: dict | None = None) -> dict:
    plan = read_plan() if plan is None else plan
    return {'plan_id': plan['plan_id'], 'live_status': plan['live_status'],
            'regions': [entry['region'] for entry in plan['entries']],
            'first_proposed_live_region': plan['entries'][0]['region'] if plan['entries'] else None,
            'total_bounded_bytes': sum(entry['length'] for entry in plan['entries'])}


def _self_test() -> list[str]:
    checks = list(plan_problems())
    plan = read_plan()
    if not plan['entries']:
        checks.append('the plan is empty')
    if plan['entries'] and plan['entries'][0]['region'] != 'amd_iommu':
        checks.append('the first priority entry is not the owner\'s priority A region')
    for entry in plan['entries']:
        if entry['length'] > entry['max_length'] or entry['max_length'] > R.MAX_READ_LEN:
            checks.append(f"{entry['region']}: length above the cap")
    return checks


def main(argv: list[str]) -> int:                                          # pragma: no cover
    if '--self-test' in argv:
        problems = _self_test()
        if problems:
            print('read plan self-test: FAILED')
            for problem in problems:
                print(f'  - {problem}')
            return 1
        print(f"read plan self-test: OK ({plan_summary()['regions']})")
        return 0
    print(json.dumps(read_plan(), indent=1, sort_keys=True))
    return 0


if __name__ == '__main__':                                                 # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
