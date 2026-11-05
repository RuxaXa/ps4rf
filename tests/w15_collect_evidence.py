#!/usr/bin/env python3
"""W15 evidence pack -- collect the offline proof of the resident research rehearsal.

Runs the rehearsal through its own test (fixed basetemp, so the artefacts have known paths), copies
what the run produced into one directory and hashes it. Nothing is invented: a missing input is a
loud failure, never a silent gap -- an evidence pack that quietly lacks the rehearsal is worse than
no pack, because it looks complete.

Usage: python3 collect_evidence_w15.py <pack-dir>
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path('/home/hermes/projects/ps4rf')
W15 = pathlib.Path('/home/hermes/.hermes/cache/scratch/ps4rf-w15')


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    done = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if done.returncode != 0:
        raise SystemExit(f'command failed ({done.returncode}): {" ".join(cmd)}\n'
                         f'{done.stdout[-2000:]}\n{done.stderr[-2000:]}')
    return done


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):          # <pack-dir> [console-artefact-dir]
        raise SystemExit(__doc__)
    pack = pathlib.Path(argv[1])
    if pack.exists():
        raise SystemExit(f'the pack directory already exists: {pack}')
    artefact = pathlib.Path(argv[2]) if len(argv) == 3 else W15 / 'console-w15'
    if not artefact.is_dir():
        raise SystemExit(f'the console artefact directory does not exist: {artefact}')
    (pack / 'artefacts' / 'logs').mkdir(parents=True)
    basetemp = pack / 'run'

    # ---- 1. the rehearsal: its own test, with a fixed basetemp so the artefacts are addressable
    suite_log = pack / 'artefacts' / 'logs' / 'w15-suite.log'
    done = subprocess.run([str(REPO / '.venv' / 'bin' / 'python'), '-m', 'pytest', '-q',
                           '-p', 'no:randomly', 'tests/test_w15_resident_research.py',
 'tests/test_w15_mutants.py', 'tests/test_w15_build_gates.py',
 'tests/test_w15_build_gates_final.py',
 'tests/test_w15_response_forms.py', 'tests/test_w15_dataset_w6.py',
 'tests/test_w15_release_schema_strict.py',
 'tests/test_w15_index_bounds.py',
                           f'--basetemp={basetemp}'],
                          cwd=REPO, capture_output=True, text=True, timeout=1800)
    suite_log.write_text(done.stdout + done.stderr)
    if done.returncode != 0:
        raise SystemExit(f'the W15 suite did not pass; see {suite_log}\n{done.stdout[-3000:]}')

    evidence = sorted(basetemp.glob('**/evidence/w15-resident-research-evidence.json'))
    if not evidence:
        raise SystemExit('the rehearsal wrote no evidence file')
    shutil.copy(evidence[-1], pack / 'artefacts' / 'w15-resident-research-evidence.json')
    for fixture in sorted(evidence[-1].parent.glob('fixtures/*.json')):
        shutil.copy(fixture, pack / 'artefacts' / fixture.name)
    dataset = evidence[-1].parent / 'dataset'
    if dataset.exists():
        shutil.copytree(dataset, pack / 'artefacts' / 'dataset')
    store = evidence[-1].parent.parent / 'store'
    if store.exists():
        shutil.copytree(store, pack / 'artefacts' / 'store')
    traces = sorted(evidence[-1].parent.parent.glob('**/sim-trace.json'))
    if traces:
        shutil.copy(traces[-1], pack / 'artefacts' / 'sim-trace.json')

    # ---- 2. the console artefact (the pinned W15 payload) and the dev-host rehearsal build
    console = artefact
    for name in ('build_manifest.json', 'SHA256SUMS.ps4.txt', 'ps4rf_target_config.h',
                 'ps4rf_kread_regions.h'):
        source = console / name
        if not source.exists():
            raise SystemExit(f'the console artefact is incomplete: {source} is missing')
        shutil.copy(source, pack / 'artefacts' / f'console-{name}')
    for name in ('ps4rfd.bin', 'ps4rfd.elf'):          # the build keeps the images under build-a/
        source = console / name if (console / name).exists() else console / 'build-a' / name
        if not source.exists():
            raise SystemExit(f'the console artefact is incomplete: {source} is missing')
        shutil.copy(source, pack / 'artefacts' / f'console-{name}')
    for name, path in (('console-build.log', W15 / 'console-w15-final2.log'),
                       ('console-build-first.log', W15 / 'console-w15-final.log'),
                       ('final-artifact-checks.txt', W15 / 'final-artifact-checks2.txt'),
                       ('final-artifact-checks-first.txt', W15 / 'final-artifact-checks.txt'),
                       ('suite-w15-full.log', W15 / 'suite-w15-d1d2.log'),
                       ('suite-w15-first.log', W15 / 'suite-w15-full.log')):
        if path.exists():
            shutil.copy(path, pack / 'artefacts' / 'logs' / name)

    # ---- 3. the pinned facts, read from the artefacts (never retyped)
    ELF = console / 'ps4rfd.elf' if (console / 'ps4rfd.elf').exists() else console / 'build-a' / 'ps4rfd.elf'
    BINPATH = console / 'ps4rfd.bin' if (console / 'ps4rfd.bin').exists() else console / 'build-a' / 'ps4rfd.bin'
    manifest = json.loads((console / 'build_manifest.json').read_text())
    regions = (console / 'ps4rf_kread_regions.h').read_text()
    facts = {
        'console_build_id': manifest.get('build_id'),
        'console_manifest_sha256': sha256(console / 'build_manifest.json'),
        'console_bin_sha256': sha256(BINPATH),
        'console_elf_sha256': sha256(ELF),
        'agent_version_gate': (manifest.get('gates') or {}).get('agent_version'),
        'console_label': manifest.get('label'),
        'verdict': manifest.get('verdict'),
        'relocations': len(manifest.get('relocations') or []),
        'undefined_symbols': len(manifest.get('undefined_symbols') or []),
        'loader_port_gate': (manifest.get('gates') or {}).get('loader_port'),
        'kread_gate_ok': (manifest.get('gates') or {}).get('kread', {}).get('ok'),
        'simulated_image_in_console_build': 'ps4rf_kread_sim' in regions
        or bool(manifest.get('rehearsal')),
        'amd_iommu_row_present': 'amd_iommu' in regions,
        'suite': done.stdout.strip().splitlines()[-1] if done.stdout.strip() else '',
    }
    (pack / 'artefacts' / 'pins.json').write_text(json.dumps(facts, indent=1, sort_keys=True) + '\n')

    # ---- 4. hashes of everything in the pack (except the manifest that will carry them)
    lines = []
    for path in sorted(pack.rglob('*')):
        if path.is_file() and path.name != 'SHA256SUMS.txt':
            lines.append(f'{sha256(path)}  {path.relative_to(pack)}')
    (pack / 'SHA256SUMS.txt').write_text('\n'.join(lines) + '\n')
    print(json.dumps({'pack': str(pack), 'files': len(lines),
                      'pack_sha256': sha256(pack / 'SHA256SUMS.txt'),
                      'suite': facts['suite']}, indent=1, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
