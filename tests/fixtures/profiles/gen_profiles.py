#!/usr/bin/env python3
"""Generate the W5 profile fixtures and the machine-readable operation/profile matrix.

Everything here is a **fixture**: the placeholder skeletons keep unknown on-site values
``UNRESOLVED``, and the concrete variants use deliberately non-address-like placeholder
locators (small integers, never a real firmware RVA). No real FW13.52 address is
invented anywhere in this package - real locators come from the on-site evidence pass
and are bound in P5/W7, not from a fixture.

Usage::

    python tests/fixtures/profiles/gen_profiles.py            # (re)write the fixtures
    python tests/fixtures/profiles/gen_profiles.py --check    # fail if they are stale
"""

from __future__ import annotations

import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.profiles.schema import (  # noqa: E402
    canonical_profile_sha256, empty_profile, operation_matrix, privilege_gated_ops,
    validate_profile,
)

FIXTURE_DIR = pathlib.Path(__file__).resolve().parent
# placeholder locator values: small round numbers, unmistakably fixtures
PLACEHOLDER_BASE = 4096
PLACEHOLDER_STEP = 4096


def _concrete_locators() -> dict:
    return {op: PLACEHOLDER_BASE + i * PLACEHOLDER_STEP
            for i, op in enumerate(sorted(privilege_gated_ops()))}


def _finalize(doc: dict) -> dict:
    body = dict(doc)
    body['canonical_sha256'] = canonical_profile_sha256(body)
    errors = validate_profile(body)
    if errors:
        raise SystemExit('generated profile is invalid:\n  - ' + '\n  - '.join(errors))
    return body


def build() -> dict[str, dict]:
    skeleton_1352 = empty_profile('fw1352-fixture', firmware_version='13.52', fixture=True)
    skeleton_900 = empty_profile('fw900-fixture', firmware_version='9.00', fixture=True)

    concrete = empty_profile('concrete-fixture', firmware_version='13.52', fixture=True,
                             locator_values=_concrete_locators())
    concrete['target'].update({'model_family': 'PS4', 'firmware_build_id': 'FIXTURE-BUILD',
                               'hardware_revision': 'FIXTURE-REV'})
    for loc in concrete['locators'].values():
        loc['section'] = '.text'
        loc['permissions'] = 'r-x'
    concrete['notes'] = ('W5 test fixture: placeholder locators (small integers, not firmware RVAs), '
                         'fixture provenance, no evidence claim. Real values come from the on-site '
                         'evidence pass.')

    return {
        'fw1352-fixture.json': _finalize(skeleton_1352),
        'fw900-fixture.json': _finalize(skeleton_900),
        'concrete-fixture.json': _finalize(concrete),
    }


def render(document: dict) -> str:
    return json.dumps(document, indent=1, sort_keys=True) + '\n'


def render_matrix() -> str:
    return json.dumps({
        'schema': 'ps4rf.profile-operation-matrix.v1',
        'generated_by': 'tests/fixtures/profiles/gen_profiles.py',
        'note': 'every gated operation has an explicit profile policy (no implicit defaults)',
        'operations': operation_matrix(),
    }, indent=1, sort_keys=True) + '\n'


def check() -> int:
    problems = []
    for name, document in build().items():
        path = FIXTURE_DIR / name
        if not path.exists():
            problems.append(f'{name}: missing')
        elif path.read_text(encoding='utf-8') != render(document):
            problems.append(f'{name}: differs from the generator')
    matrix_path = FIXTURE_DIR / 'operation-matrix.json'
    if not matrix_path.exists():
        problems.append('operation-matrix.json: missing')
    elif matrix_path.read_text(encoding='utf-8') != render_matrix():
        problems.append('operation-matrix.json: differs from the generator')
    if problems:
        print('profile fixtures are stale:')
        for item in problems:
            print(f'  - {item}')
        return 1
    print('profile fixtures match the generator (3 profiles + operation matrix)')
    return 0


def main(argv: list[str]) -> int:
    if '--check' in argv:
        return check()
    written = []
    for name, document in build().items():
        (FIXTURE_DIR / name).write_text(render(document), encoding='utf-8')
        written.append((name, document['canonical_sha256']))
    (FIXTURE_DIR / 'operation-matrix.json').write_text(render_matrix(), encoding='utf-8')
    for name, sha in written:
        print(f'{name}: canonical_sha256 {sha}')
    print(f'operation-matrix.json: {len(operation_matrix())} operations')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
