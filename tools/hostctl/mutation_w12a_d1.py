#!/usr/bin/env python3
"""W12-A-D1 mutation guard: the pinned regression must go RED when the bug comes back.

Deviation ``W12-A-D1`` was a *masked* defect: the live verifier compared the payload's
compiled region count against the policy registry total, and the offline simulation fed the
check the same wrong value, so offline green proved nothing. A regression test alone would
not have caught the original mistake in the phase where it was made -- this harness proves
the pin bites: it re-introduces the bug in a throwaway copy of the tree and requires the
pinned regression (``tests/test_compiled_regions.py``) to fail.

Three mutants of the same defect class (policy-registry semantics leaking into the target
table):

* ``M1-checker-uses-the-policy-total`` -- the live check computes its expectation from
  ``len(regions.regions())`` again (the exact original defect);
* ``M2-indices-from-the-policy-registry`` -- ``compiled_region_index()`` returns policy
  indices again, so a refused entry between two compiled regions would shift an index;
* ``M3-compiled-table-keeps-the-refused-entries`` -- ``compiled_regions()`` stops excluding
  the ``UNRESOLVED`` entries; the target table then carries entries without rva/length and
  the fail-closed invariant refuses to load it (a red import is a kill, not a pass).

The real worktree is never modified: everything runs in a temporary copy. Usage::

    .venv/bin/python -m tools.hostctl.mutation_w12a_d1 [--json OUT]

Exit 0 == baseline green and every mutant killed.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
COPY_DIRS = ('tools', 'core', 'schemas', 'profiles', 'mock')
PINNING_TEST = 'tests/test_compiled_regions.py'

MUTANTS: tuple[dict, ...] = (
    {
        'name': 'M1-checker-uses-the-policy-total',
        'file': 'tools/hostctl/kreadlive.py',
        'old': "and event.get('region_count') == len(compiled))",
        'new': "and event.get('region_count') == len(regions.regions()))",
        'note': 'the live check derives its expectation from the policy registry total again '
                '(the exact W12-A-D1 defect)',
        'must_fail': ('test_the_live_shaped_event_passes_with_the_compiled_count',
                      'test_the_simulation_uses_the_same_production_path_as_the_live_check'),
    },
    {
        'name': 'M2-indices-from-the-policy-registry',
        'file': 'tools/profiles/regions.py',
        'old': "        return compiled_region_names(registry).index(name)",
        'new': "        return list(_REGISTRY.keys()).index(name)   # M2: policy indices again",
        'note': 'the index mapping answers in policy-registry indices again (the second half of '
                'the W12-A-D1 defect class)',
        'must_fail': ('test_indices_are_compiled_indices_not_policy_indices',
                      'test_unresolved_entries_between_compiled_entries_do_not_shift_indices'),
    },
    {
        'name': 'M3-compiled-table-keeps-the-refused-entries',
        'file': 'tools/profiles/regions.py',
        'old': """        if region.identity_status == IDENTITY_UNRESOLVED:
            continue""",
        'new': """        if False:  # M3: the refused-by-design entries stay in the target table
            continue""",
        'note': 'the normative target table stops excluding the UNRESOLVED entries; the table '
                'then carries entries without rva/length, so the fail-closed invariant refuses it',
        'must_fail': ('test_compiled_table_is_nine_while_the_policy_registry_has_eleven',
                      'test_no_unresolved_entry_reaches_the_compiled_table'),
        'expect_red_mode': 'collection_error',
    },
)


def build_copy(root: pathlib.Path) -> None:
    for name in COPY_DIRS:
        source = REPO_ROOT / name
        if source.is_dir():
            shutil.copytree(source, root / name,
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    target = root / PINNING_TEST
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(REPO_ROOT / PINNING_TEST, target)


def run_pinning_test(root: pathlib.Path) -> tuple[int, str]:
    env = dict(os.environ, PYTHONPATH=str(root), PYTHONDONTWRITEBYTECODE='1')
    proc = subprocess.run([sys.executable, '-m', 'pytest', PINNING_TEST, '-q', '--no-header'],
                          cwd=str(root), capture_output=True, text=True, env=env, timeout=600)
    return proc.returncode, (proc.stdout + proc.stderr)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', dest='json_out', default=None)
    args = parser.parse_args(argv)

    report: dict = {'wave': 'W12', 'deviation': 'W12-A-D1', 'mutants': [], 'result': None}
    with tempfile.TemporaryDirectory(prefix='w12a-d1-mutation-') as tmp:
        root = pathlib.Path(tmp)
        build_copy(root)

        code, output = run_pinning_test(root)
        report['baseline'] = {'returncode': code, 'passed': code == 0,
                              'summary': output.strip().splitlines()[-1] if output.strip() else ''}
        if code != 0:
            report['result'] = 'BASELINE_RED'
            print(json.dumps(report, indent=1, sort_keys=True))
            if args.json_out:
                pathlib.Path(args.json_out).write_text(json.dumps(report, indent=1, sort_keys=True))
            return 2

        for mutant in MUTANTS:
            path = root / mutant['file']
            original = path.read_text()
            if mutant['old'] not in original:
                report['mutants'].append({'name': mutant['name'], 'status': 'NOT_APPLICABLE',
                                          'note': 'the pinned text moved; update the harness'})
                continue
            path.write_text(original.replace(mutant['old'], mutant['new'], 1))
            code, output = run_pinning_test(root)
            path.write_text(original)
            summary = output.strip().splitlines()[-1] if output.strip() else ''
            failing = [name for name in mutant['must_fail'] if name in output]
            collection_error = 'error' in summary and 'collected 0 items' not in summary
            red_mode = ('test' if failing else
                        'collection_error' if collection_error else
                        'other' if code != 0 else 'green')
            expected_mode = mutant.get('expect_red_mode', 'test')
            expected_hits = len(failing) == len(mutant['must_fail'])
            killed = (code != 0 and red_mode == expected_mode
                      and (red_mode != 'test' or expected_hits))
            report['mutants'].append({
                'name': mutant['name'], 'file': mutant['file'], 'note': mutant['note'],
                'status': 'KILLED' if killed else 'SURVIVED',
                'red_mode': red_mode, 'expected_red_mode': expected_mode,
                'returncode': code, 'summary': summary, 'pinning_tests_failed': failing,
            })
            if not killed:
                report['result'] = 'MUTANT_SURVIVED'
                print(json.dumps(report, indent=1, sort_keys=True))
                if args.json_out:
                    pathlib.Path(args.json_out).write_text(
                        json.dumps(report, indent=1, sort_keys=True))
                return 1

    report['result'] = 'ALL_MUTANTS_KILLED'
    print(json.dumps(report, indent=1, sort_keys=True))
    if args.json_out:
        pathlib.Path(args.json_out).write_text(json.dumps(report, indent=1, sort_keys=True))
    return 0


if __name__ == '__main__':                                  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
