#!/usr/bin/env python3
"""W13 offline CLI — the read-only research baseline, no live step, no console contact.

    python -m tools.research.cli --matrix      # the region classification matrix
    python -m tools.research.cli --plan        # the research read plan (APPROVED_READ only)
    python -m tools.research.cli --contract    # the W6 integration contract
    python -m tools.research.cli --pointer-policy
    python -m tools.research.cli --classify <region>
    python -m tools.research.cli --self-test   # every W13 module self-test
"""
from __future__ import annotations

import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.research import classification as C                            # noqa: E402
from tools.research import dataset as D                                   # noqa: E402
from tools.research import pointer_follow as P                            # noqa: E402
from tools.research import read_plan as RP                                # noqa: E402
from tools.research import w6_contract as W6                              # noqa: E402

SELF_TESTS = (('classification', C._self_test), ('read plan', RP._self_test),
              ('dataset', D._self_test), ('pointer follow', P._self_test),
              ('w6 contract', W6._self_test))


def main(argv: list[str]) -> int:
    if not argv or '--help' in argv:
        print(__doc__)
        return 0
    if '--self-test' in argv:
        failed = False
        for name, test in SELF_TESTS:
            problems = test()
            print(f'{name}: {"OK" if not problems else "FAILED"}')
            for problem in problems:
                print(f'  - {problem}')
            failed = failed or bool(problems)
        return 1 if failed else 0
    if '--matrix' in argv:
        print(json.dumps(C.classification_matrix(), indent=1, sort_keys=True))
        return 0
    if '--plan' in argv:
        print(json.dumps(RP.read_plan(), indent=1, sort_keys=True))
        return 0
    if '--contract' in argv:
        print(json.dumps(W6.contract(), indent=1, sort_keys=True))
        return 0
    if '--pointer-policy' in argv:
        print(json.dumps(P.policy_document(), indent=1, sort_keys=True))
        return 0
    if '--classify' in argv:
        name = argv[argv.index('--classify') + 1]
        region = C.R.regions().get(name)
        if region is None:
            print(f'{name}: not registered')
            return 1
        row = {r['region']: r for r in C.classification_matrix()['rows']}[name]
        print(f'{name}: {C.classify(region)}')
        for criterion, result in sorted(row['criteria'].items()):
            print(f"  [{'PASS' if result['pass'] else 'FAIL'}] {criterion}: {result['evidence']}")
        return 0
    print(__doc__)
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
