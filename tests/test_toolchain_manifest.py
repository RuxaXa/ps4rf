"""Gate checks for the toolchain manifest validator (W0/D4, W0/D2, W0/D16).

The example manifest must validate, and every violation class the decision
record forbids must be refused: an unpinned external input, a missing artifact
hash, a non-``ET_DYN`` ELF, a timestamp claiming hash authority, missing
compiler/linker versions, a bad source commit and disagreeing pins.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
VALIDATOR = REPO_ROOT / 'tools' / 'toolchain' / 'toolchain_manifest.py'
EXAMPLE = REPO_ROOT / 'tools' / 'toolchain' / 'examples' / 'toolchain-manifest.example.json'


def _load_module():
    spec = importlib.util.spec_from_file_location('ps4rf_toolchain_manifest', VALIDATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load_module()
EXAMPLE_MANIFEST = json.loads(EXAMPLE.read_text(encoding='utf-8'))


def _manifest(**changes) -> dict:
    manifest = copy.deepcopy(EXAMPLE_MANIFEST)
    manifest.update(changes)
    return manifest


def test_example_manifest_is_valid():
    assert EXAMPLE_MANIFEST['example'] is True, 'the example must be marked as such'
    assert MODULE.validate(EXAMPLE_MANIFEST) == []


def test_example_is_valid_through_the_cli():
    assert MODULE.main(['toolchain_manifest.py', '--self-test']) == 0


def test_unpinned_external_input_is_refused():
    manifest = _manifest()
    manifest['external_inputs'][0]['pinned'] = False
    errors = MODULE.validate(manifest)
    assert any('pinned' in error for error in errors), errors

    manifest = _manifest()
    del manifest['external_inputs'][0]['sha256']
    assert any('sha256 is required' in error or 'sha256' in error
               for error in MODULE.validate(manifest))

    manifest = _manifest()
    manifest['external_inputs'][1]['sha256'] = 'abc123'  # not a full digest
    assert MODULE.validate(manifest), 'a short hash must not count as a pin'


def test_artifact_hashes_and_elf_type_are_enforced():
    manifest = _manifest()
    manifest['artifacts'][0]['elf_type'] = 'ET_EXEC'
    errors = MODULE.validate(manifest)
    assert any('ET_DYN' in error for error in errors), errors

    manifest = _manifest()
    del manifest['artifacts'][1]['sha256']
    errors = MODULE.validate(manifest)
    assert any('both artifacts are hashed' in error or 'sha256' in error for error in errors)

    manifest = _manifest()
    manifest['artifacts'][0]['kind'] = 'so'
    assert any('kind' in error for error in MODULE.validate(manifest))


def test_timestamp_is_metadata_not_hash_authority():
    manifest = _manifest()
    manifest['build']['timestamp']['hash_authority'] = True
    errors = MODULE.validate(manifest)
    assert any('hash_authority must be false' in error for error in errors), errors


def test_build_tooling_fields_are_required():
    for field in ('compiler', 'linker'):
        manifest = _manifest()
        del manifest['build'][field]['version']
        assert any(field in error for error in MODULE.validate(manifest)), field

    manifest = _manifest()
    manifest['build']['source_commit'] = 'deadbeef'
    assert any('source_commit' in error for error in MODULE.validate(manifest))

    manifest = _manifest()
    manifest['build']['flags'] = '-O2'
    assert any('flags' in error for error in MODULE.validate(manifest))


def test_pins_must_agree_with_artifacts():
    manifest = _manifest()
    manifest['pins']['ps4rfd'] = '9' * 64
    errors = MODULE.validate(manifest)
    assert any('disagrees' in error for error in errors), errors

    manifest = _manifest()
    manifest['pins']['unknown'] = '9' * 64
    assert any('does not name an artifact' in error for error in MODULE.validate(manifest))


def test_kind_and_structure_of_the_manifest_itself():
    assert MODULE.validate(_manifest(kind='ps4rf.something-else'))
    assert MODULE.validate({'kind': MODULE.KIND, 'manifest_version': '1'})
    assert MODULE.validate([]) == ['manifest must be a JSON object']


def test_w1_artifacts_are_not_ignored_and_are_tracked():
    """Packaging guard: an ignore rule must never silently drop a deliverable.

    A directory named ``build/`` is ignored in this repository (build outputs),
    which once swallowed the W1 validator path while every local run stayed green.
    """
    import subprocess

    if not (REPO_ROOT / '.git').exists():
        pytest.skip('not a git work tree')
    paths = ['tools/toolchain/toolchain_manifest.py',
             'tools/toolchain/examples/toolchain-manifest.example.json',
             'tests/test_toolchain_manifest.py',
             'docs/P4-W1-TOOLCHAIN.md']
    for rel in paths:
        ignored = subprocess.run(['git', 'check-ignore', '-q', rel], cwd=REPO_ROOT).returncode == 0
        assert not ignored, f'{rel} is git-ignored - it would never be committed'
        tracked = subprocess.run(['git', 'ls-files', '--error-unmatch', rel],
                                 cwd=REPO_ROOT, capture_output=True).returncode == 0
        assert tracked, f'{rel} exists on disk but is not tracked by git'


def test_no_source_path_in_the_working_tree_is_invisible_to_git():
    """Generalised guard: nothing under core/tools/tests/docs/native may be ignore-hidden.

    Only ``__pycache__``/``*.pyc`` and the generated ``native/build/`` output
    directory may be ignored - any other invisible source path means a deliverable
    could silently never reach a commit.
    """
    import subprocess

    if not (REPO_ROOT / '.git').exists():
        pytest.skip('not a git work tree')
    proc = subprocess.run(['git', 'status', '--porcelain', '--ignored', '--',
                           'core/', 'tools/', 'tests/', 'docs/', 'native/'],
                          cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    ignored = [line[3:].strip() for line in proc.stdout.splitlines() if line.startswith('!! ')]

    def allowed(path: str) -> bool:
        if '__pycache__' in path or path.endswith('.pyc'):
            return True
        return path in ('native/build', 'native/build/') or path.startswith('native/build/')

    suspicious = [path for path in ignored if not allowed(path)]
    assert not suspicious, f'ignored source paths found: {suspicious}'
