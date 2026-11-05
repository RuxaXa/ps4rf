#!/usr/bin/env python3
"""W13 — the bounded pointer-follow policy.

A pointer may only be *followed* when it came out of an ``APPROVED_READ`` result, it maps into a
region that is *itself* separately approved, and the target satisfies the expected address class and
(optionally) an expected range. Anything else stops:

``UNRESOLVED_TARGET``
    the target does not exist in the profile/region model -- STOP, no address improvisation.

A follow never reads anything by itself. It produces a *candidate request* (region, offset, length)
that needs its own approval, session and evidence, exactly like any other read; there is no
automatic chasing, no walking a list, no loop.
"""
from __future__ import annotations

import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from tools.hostctl.bootpriv import KERNEL_MIN                              # noqa: E402
from tools.profiles import regions as R                                    # noqa: E402
from tools.research import classification as C                             # noqa: E402

SCHEMA_POLICY = 'ps4rf.research.pointer-follow-policy.v1'

REASON_SOURCE_NOT_APPROVED = 'POINTER_SOURCE_NOT_APPROVED_READ'
REASON_NOT_CANONICAL = 'POINTER_NOT_CANONICAL'
REASON_UNRESOLVED_TARGET = 'UNRESOLVED_TARGET'
REASON_TARGET_NOT_APPROVED = 'TARGET_REGION_NOT_APPROVED_READ'
REASON_REGION_MISMATCH = 'TARGET_REGION_MISMATCH'
REASON_OUT_OF_BOUNDS = 'TARGET_OUT_OF_REGION_BOUNDS'
REASON_CLASS_MISMATCH = 'POINTER_CLASS_MISMATCH'
REASON_NO_SOURCE = 'POINTER_NOT_FROM_READ_RESULT'
REASONS = (REASON_SOURCE_NOT_APPROVED, REASON_NOT_CANONICAL, REASON_UNRESOLVED_TARGET,
           REASON_TARGET_NOT_APPROVED, REASON_REGION_MISMATCH, REASON_OUT_OF_BOUNDS,
           REASON_CLASS_MISMATCH, REASON_NO_SOURCE)

#: Expected pointer classes and the permissions the target region must declare for them.
CLASS_PERMISSIONS = {
    'code': ('r-x',),
    'read_only': ('r--', 'r-x'),        # any non-writable target, whatever its pinned section
    'data': ('rw-',),
}

POLICY_RULES = (
    'a pointer is followed only when it comes from an APPROVED_READ result of this W13 plan',
    'the pointer must be canonical: a relative rva inside the image window, or a kernel-half '
    'address that the verified kbase maps back to an rva',
    'the mapped target must fall into a registered region whose W13 class is APPROVED_READ; '
    'otherwise UNRESOLVED_TARGET and STOP',
    'the target region must be approved separately: a follow never inherits the approval of the '
    'read that produced the pointer',
    'an expected class or range, when given, must hold; a follow is refused otherwise',
    'a follow produces a candidate request only -- one bounded read, its own session, its own '
    'evidence, its own approval. No loops, no chaining, no list walking',
)


class PointerFollowRefused(Exception):
    """The follow is refused; ``reason`` is one of :data:`REASONS` and means STOP."""

    def __init__(self, reason: str, detail: str = '') -> None:
        if reason not in REASONS:
            raise ValueError(f'{reason!r} is not a pointer-follow reason')
        super().__init__(f'{reason}: {detail}' if detail else reason)
        self.reason = reason
        self.detail = detail


def region_for_rva(rva: int, registry: dict | None = None) -> R.Region | None:
    """The registered region whose window contains *rva*, if any."""
    registry = R.regions() if registry is None else registry
    for region in registry.values():
        if region.rva is None or region.length is None:
            continue
        if region.rva <= rva < region.rva + region.length:
            return region
    return None


def to_rva(pointer_value: int, kbase: int) -> tuple[int, str]:
    """Map a pointer value to a relative rva, or refuse as non-canonical."""
    if isinstance(pointer_value, bool) or not isinstance(pointer_value, int):
        raise PointerFollowRefused(REASON_NOT_CANONICAL, f'{pointer_value!r} is not an integer')
    if 0 <= pointer_value < R.IMAGE_WINDOW_MAX_RVA:
        return pointer_value, 'relative rva (already inside the image window)'
    if pointer_value >= KERNEL_MIN:
        if pointer_value & 0xFFFFFFFFFFFFFFFF != pointer_value:
            raise PointerFollowRefused(REASON_NOT_CANONICAL,
                                       f'{pointer_value:#x} is not a canonical 64-bit value')
        if kbase <= 0 or pointer_value < kbase:
            raise PointerFollowRefused(REASON_NOT_CANONICAL,
                                       f'{pointer_value:#x} is below the verified kbase '
                                       f'{kbase:#x}')
        rva = pointer_value - kbase
        if rva >= R.IMAGE_WINDOW_MAX_RVA:
            raise PointerFollowRefused(REASON_NOT_CANONICAL,
                                       f'{pointer_value:#x} maps to rva {rva:#x}, outside the '
                                       f'pinned image window')
        return rva, f'kernel address minus the verified kbase {kbase:#x}'
    raise PointerFollowRefused(REASON_NOT_CANONICAL,
                               f'{pointer_value:#x} is neither a relative rva nor a kernel-half '
                               'address')


def evaluate(*, pointer_value: int, pointer_source: dict, kbase: int,
             target_region: str | None = None, expected_class: str | None = None,
             expected_range: tuple[int, int] | None = None, registry: dict | None = None,
             profile: dict | None = None) -> dict:
    """Evaluate one pointer follow. Returns the candidate request or raises (STOP)."""
    registry = R.regions() if registry is None else registry
    profile = C.DEFAULT_PROFILE if profile is None else profile
    classes = {row['region']: row['class'] for row in C.classification_matrix(profile)['rows']}

    if not isinstance(pointer_source, dict) or not pointer_source.get('read_run_id') \
            or not pointer_source.get('region'):
        raise PointerFollowRefused(REASON_NO_SOURCE,
                                   'the pointer names no read result (read_run_id + region)')
    source_region = pointer_source['region']
    if classes.get(source_region) != C.CLASS_APPROVED_READ:
        raise PointerFollowRefused(
            REASON_SOURCE_NOT_APPROVED,
            f'the pointer came from {source_region!r}, whose class is {classes.get(source_region)}')

    rva, how = to_rva(pointer_value, kbase)
    resolved = region_for_rva(rva, registry)
    if resolved is None:
        raise PointerFollowRefused(
            REASON_UNRESOLVED_TARGET,
            f'rva {rva:#x} is not inside any registered region: no address improvisation, STOP')
    if classes.get(resolved.name) != C.CLASS_APPROVED_READ:
        raise PointerFollowRefused(
            REASON_TARGET_NOT_APPROVED,
            f'the target region {resolved.name!r} is {classes.get(resolved.name)}, not '
            'APPROVED_READ: the follow would need its own promotion and review')
    if target_region is not None and target_region != resolved.name:
        raise PointerFollowRefused(
            REASON_REGION_MISMATCH,
            f'the caller expected {target_region!r}, the pointer maps into {resolved.name!r}')

    region_rva, region_length = resolved.rva, resolved.length
    if region_rva is None or region_length is None:
        raise PointerFollowRefused(REASON_UNRESOLVED_TARGET,
                                   f'{resolved.name} carries no pinned window')
    offset = rva - region_rva
    length = min(8, region_length - offset)
    if length <= 0:
        raise PointerFollowRefused(REASON_OUT_OF_BOUNDS,
                                   f'offset {offset} leaves no readable window in {resolved.name}')

    if expected_class is not None:
        allowed = CLASS_PERMISSIONS.get(expected_class)
        if allowed is None:
            raise ValueError(f'{expected_class!r} is not a pointer class')
        permissions = (C.profile_locator(profile, resolved.locator) or {}).get('permissions')
        if permissions not in allowed:
            raise PointerFollowRefused(
                REASON_CLASS_MISMATCH,
                f'the target declares permissions {permissions!r}, expected one of {allowed} '
                f'for class {expected_class!r}')
    if expected_range is not None:
        low, high = expected_range
        if not low <= rva < high:
            raise PointerFollowRefused(
                REASON_OUT_OF_BOUNDS,
                f'rva {rva:#x} outside the expected range [{low:#x}, {high:#x})')

    return {
        'schema': SCHEMA_POLICY,
        'candidate_request': {'region': resolved.name, 'offset': offset, 'length': length},
        'resolved_rva': rva,
        'rva_source': how,
        'target_region': resolved.name,
        'target_class': classes[resolved.name],
        'automatic': False,
        'requires': ['its own live approval', 'its own session', 'its own stored VerificationEvidence'],
        'note': 'a follow produces a candidate request, never a permission; nothing is chased '
                'automatically and no loop is allowed',
    }


def policy_document() -> dict:
    return {'schema': SCHEMA_POLICY, 'rules': list(POLICY_RULES), 'reasons': list(REASONS),
            'classes': {name: list(values) for name, values in CLASS_PERMISSIONS.items()},
            'kernel_min': hex(KERNEL_MIN), 'image_window_max_rva': R.IMAGE_WINDOW_MAX_RVA}


def policy_problems(profile: dict | None = None) -> list[str]:
    """The policy's own invariants (self-checked; any hit is a bug)."""
    problems: list[str] = []
    profile = C.DEFAULT_PROFILE if profile is None else profile
    if 'UNRESOLVED_TARGET' not in policy_document()['reasons']:
        problems.append('UNRESOLVED_TARGET is not a refusal reason any more')
    source = {'read_run_id': 'RUN-x', 'region': 'amd_iommu'}
    try:
        evaluate(pointer_value=0x1000, pointer_source=source, kbase=0xFFFF_FFFF_998F_4000)
        problems.append('a pointer into an unregistered rva was accepted')
    except PointerFollowRefused as exc:
        if exc.reason != REASON_UNRESOLVED_TARGET:
            problems.append(f'unregistered target reported {exc.reason}, expected UNRESOLVED_TARGET')
    try:
        evaluate(pointer_value=0x1, pointer_source=source, kbase=0xFFFF_FFFF_998F_4000)
        problems.append('a pointer into the identity window was accepted')
    except PointerFollowRefused as exc:
        if exc.reason != REASON_TARGET_NOT_APPROVED:
            problems.append(f'the identity window reported {exc.reason}')
    try:
        evaluate(pointer_value=0x1, pointer_source={'read_run_id': 'RUN-x', 'region': 'image_elf'},
                 kbase=0xFFFF_FFFF_998F_4000)
        problems.append('a pointer from an IDENTITY_ONLY region was accepted')
    except PointerFollowRefused as exc:
        if exc.reason != REASON_SOURCE_NOT_APPROVED:
            problems.append(f'identity-only source reported {exc.reason}')
    return problems


def _self_test() -> list[str]:
    checks = list(policy_problems())
    kbase = 0xFFFFFFFF998F4000
    source = {'read_run_id': 'RUN-selftest', 'region': 'prison0_static', 'sha256': 'ab' * 32}
    # a pointer that maps into an approved region must produce a candidate request, not a read
    target = C.approved_read_regions()[0]
    assert target.rva is not None
    follow = evaluate(pointer_value=kbase + target.rva, pointer_source=source, kbase=kbase,
                      expected_class='read_only' if target.name == 'amd_iommu' else None)
    if follow['automatic'] is not False or 'region' not in follow['candidate_request']:
        checks.append('the follow result is not a candidate-only request')
    if follow['target_region'] != target.name:
        checks.append('the follow resolved the wrong target region')
    # a pointer into a STRUCTURAL_ONLY region must stop
    structural = R.regions()['aperture_global']
    assert structural.rva is not None
    try:
        evaluate(pointer_value=kbase + structural.rva, pointer_source=source, kbase=kbase)
        checks.append('a follow into aperture_global was accepted')
    except PointerFollowRefused as exc:
        if exc.reason != REASON_TARGET_NOT_APPROVED:
            checks.append(f'aperture_global follow reported {exc.reason}')
    return checks


def main(argv: list[str]) -> int:                                          # pragma: no cover
    if '--self-test' in argv:
        problems = _self_test()
        if problems:
            print('pointer-follow self-test: FAILED')
            for problem in problems:
                print(f'  - {problem}')
            return 1
        print('pointer-follow self-test: OK (source gate, canonical map, target approval, STOP)')
        return 0
    print(json.dumps(policy_document(), indent=1, sort_keys=True))
    return 0


if __name__ == '__main__':                                                 # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
