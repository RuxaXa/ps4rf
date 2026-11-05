"""The live wave's closing summary: read the attempt's own evidence directory and print the facts
an operator needs (verdict, both classifications, the binding observation, the recipe cells, the
device call). No interpretation beyond what the payload and the run recorded."""
from __future__ import annotations

import json
import os
import pathlib
import sys

SUF = os.environ.get('W17_SUF', '')
OUT = pathlib.Path('evidence/live-w17' + SUF)


def main() -> int:
    summary = OUT / 'w17-live-summary.json'
    if not summary.is_file():
        print('no summary at', summary)
        if OUT.is_dir():
            for stage in sorted(OUT.glob('stage-*.json')):
                print('  present:', stage.name)
            for name in ('stage-3-recipe.json',):
                path = OUT / name
                if path.is_file():
                    print(' ', name, json.dumps(json.loads(path.read_text()), indent=1)[:800])
        return 1
    doc = json.loads(summary.read_text())
    session = doc.get('session') or {}
    hello = session.get('hello') or {}
    recipe = doc.get('recipe') or {}
    print(json.dumps({
        'verdict': doc.get('verdict'),
        'q6': (doc.get('q6') or {}).get('classification'),
        'own1': (doc.get('own1') or {}).get('classification'),
        'boot_status': hello.get('boot_status'),
        'boot_id': hello.get('boot_id'),
        'profile_id': hello.get('profile_id'),
        'agent_version': hello.get('agent_version'),
        'build_id': hello.get('build_id'),
        'recipe': recipe.get('refused') or {k: v.get('status')
                                            for k, v in (recipe.get('cells') or {}).items()},
        'recipe_attach': recipe.get('attach'),
        'ioctl': {k: v for k, v in (doc.get('ioctl') or {}).items()
                  if k in ('device', 'command', 'rc', 'errno', 'output_len', 'output_sha256')},
    }, indent=1, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
