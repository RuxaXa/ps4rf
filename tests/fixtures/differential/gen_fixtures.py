#!/usr/bin/env python3
"""Generate the W6 differential fixtures (deterministic, clearly marked).

Fixture set:

* ``section-inventory-{before,after}.json`` - offline section metadata for the artifact
  engine: a section moved, one permission change, one signature change, one resize, one
  section added and one removed. Entry hashes are real sha256 values of the fixture
  content strings; there is no address anywhere (only ``file_offset``).
* ``operation-inventory-{before,after}.json`` - the 14 gated operations with explicit
  differences: a requirement added/removed, a locator moved, a verification requirement
  changed, a profile policy changed and an unresolved<->resolved pair.
* ``external-ghidra-before.json`` / ``external-rizin-after.json`` - optional external
  analysis inputs for the adapter ingestion path (no adapter implemented), each bound to
  the sha256 of the section inventory it analyses.

No firmware address is invented. Firmware *images* stay absent on purpose: the harness
must report ``ARTIFACT_MISSING`` for them rather than invent content (W6 section 6).

Usage::

    python tests/fixtures/differential/gen_fixtures.py            # write the fixtures
    python tests/fixtures/differential/gen_fixtures.py --check    # fail if stale
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.differential.schema import EXTERNAL_SCHEMA, INVENTORY_SCHEMA  # noqa: E402
from tools.primitive_iface.gate import REQ_BY_OP, privilege_gated_ops  # noqa: E402

FIXTURE_DIR = pathlib.Path(__file__).resolve().parent
UNRESOLVED = 'UNRESOLVED'


def _h(*parts) -> str:
    return hashlib.sha256('|'.join(str(p) for p in parts).encode()).hexdigest()


def section_inventory(variant: str) -> dict:
    """Section metadata fixture. Offsets are *file* offsets, never addresses."""
    # each entry exercises exactly one phenomenon on purpose:
    #   .text      content unchanged, file offset moves      -> MOVED
    #   .rodata    untouched                                 -> (no finding)
    #   .data      content unchanged, permissions change     -> PERMISSION_CHANGED
    #   .text.hot  resized and changed                       -> CHANGED + SIGNATURE_CHANGED
    #   .sig       known expected bytes change               -> SIGNATURE_CHANGED
    moved = 0x2000 if variant == 'before' else 0x2400
    entries = [
        _section('.text', moved, 0x2000, 'r-x', _h('text')),
        _section('.rodata', 0x5000, 0x800, 'r--', _h('rodata')),
        _section('.data', 0x5800, 0x400, 'rw-' if variant == 'before' else 'r--', _h('data')),
        _section('.text.hot', 0x5c00, 0x400 if variant == 'before' else 0x600, 'r-x',
                 _h('hot', variant)),
        _section('.sig', 0x6000, 0x40, 'r--', _h('sig', variant)),
    ]
    if variant == 'after':
        entries.append(_section('.new.guard', 0x6400, 0x100, 'r-x', _h('guard', variant)))
    else:
        entries.append(_section('.legacy', 0x6400, 0x100, 'r-x', _h('legacy', variant)))
    return {
        'schema': INVENTORY_SCHEMA, 'kind': 'elf', 'fixture': True,
        'path': f'tests/fixtures/differential/section-inventory-{variant}.json',
        'module': 'fixture-image.elf', 'architecture': 'x86-64', 'size': 0x8000,
        'manifest_entries': {}, 'notes': [
            'W6 fixture section inventory: offsets are file offsets, not addresses',
            'fixture facts are capped at WEAK confidence by the harness',
        ],
        'entries': entries,
    }


def _section(name: str, offset: int, size: int, perms: str, sha: str) -> dict:
    return {'path': name, 'kind': 'section', 'file_offset': offset, 'size': size,
            'sha256': sha, 'permissions': perms, 'hash_scope': 'full'}


def operation_inventory(variant: str) -> dict:
    """The 14 gated operations with deliberate, documented differences."""
    operations = {}
    for op in privilege_gated_ops():
        req = REQ_BY_OP[op]
        operations[op] = {
            'profile_required': bool(req.profile_required),
            'profile_policy': req.defer_reason,
            'verification_requirement': req.verification_op,
            'requirement': req.capability or req.namespace,
            'locator': {
                'module': 'kernel', 'kind': 'rva',
                'value': 0x1000 if variant == 'before' else 0x1000,
                'section': '.text', 'permissions': 'r-x',
            },
        }
    # 1. locator moved
    operations['kernel.read']['locator']['value'] = 0x1000 if variant == 'before' else 0x1400
    # 2. unresolved <-> resolved
    operations['gpuvm.map']['locator']['value'] = UNRESOLVED if variant == 'before' else 0x2000
    # 3. verification requirement changed
    operations['verify.kernel.read']['verification_requirement'] = (
        'verify.kernel.read' if variant == 'before' else 'verify.kernel.copyout')
    # 4. profile policy changed
    operations['ccp.submit']['profile_policy'] = (
        'profile-bound values required' if variant == 'before'
        else 'profile-bound values required (reviewed)')
    # 5. requirement added/removed
    if variant == 'after':
        operations['keymgr.snapshot']['requirement'] = 'keymgr.snapshot'
    else:
        operations.pop('verify.samu.access', None)
    return {'schema': 'ps4rf.differential.operation-inventory.v1', 'fixture': True,
            'path': f'tests/fixtures/differential/operation-inventory-{variant}.json',
            'operations': operations}


def external_analysis(tool: str, inventory: dict) -> dict:
    # the analysis references the *file* hash of the inventory it analyses
    artifact_sha256 = hashlib.sha256(render(inventory).encode()).hexdigest()
    return {
        'schema': EXTERNAL_SCHEMA, 'tool': tool, 'version': 'fixture-0.1',
        'artifact_sha256': artifact_sha256,
        'entries': [
            {'kind': 'function', 'name': 'fixture_entry_a', 'size': 0x80,
             'locator': {'kind': 'rva', 'value': 0x1000}},
            {'kind': 'function', 'name': 'fixture_entry_b', 'size': 0x40 if tool == 'ghidra' else 0x80,
             'locator': {'kind': 'rva', 'value': 0x1400}},
            {'kind': 'string_ref', 'name': 'fixture_note', 'size': 0x10, 'locator': None},
        ],
        'notes': ['fixture analysis output; no adapter is implemented (W6 section 12)',
                  f'produced by a {tool} fixture, capped at WEAK confidence'],
    }


def build() -> dict[str, dict]:
    documents: dict[str, dict] = {}
    before = section_inventory('before')
    after = section_inventory('after')
    documents['section-inventory-before.json'] = before
    documents['section-inventory-after.json'] = after
    documents['operation-inventory-before.json'] = operation_inventory('before')
    documents['operation-inventory-after.json'] = operation_inventory('after')
    documents['external-ghidra-before.json'] = external_analysis('ghidra', before)
    documents['external-rizin-after.json'] = external_analysis('rizin', after)
    return documents


def render(document: dict) -> str:
    return json.dumps(document, indent=1, sort_keys=True) + '\n'


def check() -> int:
    problems = []
    for name, document in build().items():
        path = FIXTURE_DIR / name
        if not path.exists():
            problems.append(f'{name}: missing')
        elif path.read_text(encoding='utf-8') != render(document):
            problems.append(f'{name}: differs from the generator')
    if problems:
        print('differential fixtures are stale:')
        for item in problems:
            print(f'  - {item}')
        return 1
    print(f'differential fixtures match the generator ({len(build())} files)')
    return 0


def main(argv: list[str]) -> int:
    if '--check' in argv:
        return check()
    for name, document in build().items():
        (FIXTURE_DIR / name).write_text(render(document), encoding='utf-8')
        print(f'{name}: sha256 {hashlib.sha256(render(document).encode()).hexdigest()[:16]}…')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
