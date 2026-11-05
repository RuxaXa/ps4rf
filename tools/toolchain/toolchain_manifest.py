#!/usr/bin/env python3
"""PS4RF toolchain manifest validator (W0/D4 + W0/D16, fail-closed).

The repository is source of truth for how a native artifact was built. This
validator turns the pinning rule into a gate: an unpinned external SDK, a missing
artifact hash or a non-`ET_DYN` ELF fails validation, so "hash-pinned" cannot
degrade into a comment.

Usage::

    python tools/toolchain/toolchain_manifest.py path/to/manifest.json
    python tools/toolchain/toolchain_manifest.py --self-test   # validate the example

Exit codes: 0 = valid, 1 = invalid (errors printed), 2 = usage/IO error.
No network, no subprocess, no side effects beyond reading files.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

KIND = 'ps4rf.toolchain-manifest'
HEX64 = re.compile(r'^[0-9a-f]{64}$')
COMMIT = re.compile(r'^[0-9a-f]{40}$')
ARTIFACT_KINDS = ('elf', 'bin')
EXAMPLE_PATH = (pathlib.Path(__file__).resolve().parent
                / 'examples' / 'toolchain-manifest.example.json')


def _require(condition: bool, message: str, errors: list) -> None:
    if not condition:
        errors.append(message)


def validate(manifest: dict) -> list:
    """Return a list of validation errors (empty list = valid)."""
    errors: list = []
    if not isinstance(manifest, dict):
        return ['manifest must be a JSON object']

    _require(manifest.get('kind') == KIND, f'kind must be {KIND!r}', errors)
    _require(isinstance(manifest.get('manifest_version'), int),
             'manifest_version must be an integer', errors)

    inputs = manifest.get('external_inputs')
    _require(isinstance(inputs, list) and bool(inputs),
             'external_inputs must be a non-empty list', errors)
    for index, entry in enumerate(inputs if isinstance(inputs, list) else []):
        where = f'external_inputs[{index}]'
        if not isinstance(entry, dict):
            errors.append(f'{where} must be an object')
            continue
        for field in ('name', 'version', 'source_id', 'sha256'):
            _require(bool(entry.get(field)), f'{where}.{field} is required', errors)
        digest = entry.get('sha256')
        if digest is not None:
            _require(isinstance(digest, str) and bool(HEX64.match(digest)),
                     f'{where}.sha256 must be a full lowercase sha256 '
                     f'(unpinned external input is not allowed, W0/D4)', errors)
        _require(entry.get('pinned') is True,
                 f'{where}.pinned must be true (W0/D4: unpinned SDK cannot '
                 f'produce a reproducible build)', errors)

    build = manifest.get('build')
    _require(isinstance(build, dict), 'build must be an object', errors)
    if isinstance(build, dict):
        for field in ('compiler', 'linker'):
            tool = build.get(field)
            _require(isinstance(tool, dict) and bool(tool.get('name'))
                     and bool(tool.get('version')),
                     f'build.{field} must carry name and version', errors)
        _require(isinstance(build.get('flags'), list), 'build.flags must be a list', errors)
        commit = build.get('source_commit')
        _require(isinstance(commit, str) and bool(COMMIT.match(commit)),
                 'build.source_commit must be a 40-char hex git commit', errors)
        timestamp = build.get('timestamp')
        if timestamp is not None:
            _require(isinstance(timestamp, dict), 'build.timestamp must be an object', errors)
            if isinstance(timestamp, dict):
                _require(timestamp.get('value') is not None,
                         'build.timestamp.value is required', errors)
                _require(timestamp.get('hash_authority') is False,
                         'build.timestamp.hash_authority must be false '
                         '(D16: timestamp is metadata, not hash authority)', errors)

    artifacts = manifest.get('artifacts')
    _require(isinstance(artifacts, list) and bool(artifacts),
             'artifacts must be a non-empty list', errors)
    seen = {}
    for index, artifact in enumerate(artifacts if isinstance(artifacts, list) else []):
        where = f'artifacts[{index}]'
        if not isinstance(artifact, dict):
            errors.append(f'{where} must be an object')
            continue
        name = artifact.get('name')
        _require(bool(name), f'{where}.name is required', errors)
        kind = artifact.get('kind')
        _require(kind in ARTIFACT_KINDS, f'{where}.kind must be one of {ARTIFACT_KINDS}', errors)
        digest = artifact.get('sha256')
        _require(isinstance(digest, str) and bool(HEX64.match(digest or '')),
                 f'{where}.sha256 must be a full lowercase sha256 (both artifacts are '
                 f'hashed, W0/D2)', errors)
        _require(bool(artifact.get('path')), f'{where}.path is required', errors)
        if kind == 'elf':
            _require(artifact.get('elf_type') == 'ET_DYN',
                     f'{where}.elf_type must be ET_DYN (W0/D2 build check)', errors)
        if name:
            seen[name] = digest

    pins = manifest.get('pins')
    if pins is not None:
        _require(isinstance(pins, dict), 'pins must be an object', errors)
        for name, digest in (pins.items() if isinstance(pins, dict) else []):
            if name not in seen:
                errors.append(f'pins.{name} does not name an artifact')
            elif digest != seen[name]:
                errors.append(f'pins.{name} disagrees with the artifact hash')

    return errors


def validate_file(path: pathlib.Path) -> tuple:
    """Return ``(errors, manifest_or_None)``."""
    try:
        manifest = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        return [f'{path}: {exc}'], None
    return validate(manifest), manifest


def main(argv: list) -> int:
    args = [a for a in argv[1:] if not a.startswith('--')]
    if '--self-test' in argv[1:]:
        target = EXAMPLE_PATH
    elif len(args) == 1:
        target = pathlib.Path(args[0])
    else:
        print(__doc__.strip())
        return 2
    errors, manifest = validate_file(target)
    if errors:
        print(f'TOOLCHAIN MANIFEST: INVALID ({len(errors)} error(s)) - {target}')
        for error in errors:
            print(f'  - {error}')
        return 1
    assert manifest is not None
    artifacts = ', '.join(f"{a['name']}={a['kind']}" for a in manifest['artifacts'])
    print(f'TOOLCHAIN MANIFEST: VALID - {target}')
    print(f'  artifacts: {artifacts}')
    print(f'  external inputs pinned: {len(manifest["external_inputs"])}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
