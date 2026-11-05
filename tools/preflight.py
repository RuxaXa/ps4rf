#!/usr/bin/env python3
from pathlib import Path
import sys,json,re,importlib.util
ROOT=Path(__file__).resolve().parents[1];fails=[];checks=0
def check(cond,msg):
    global checks;checks+=1
    if not cond:fails.append(msg)
def main():
    check(sys.version_info>=(3,11),f'Python >=3.11 required for package assembly; Hermes target >=3.12, found {sys.version.split()[0]}')
    for mod in ('pydantic','cryptography','yaml','jsonschema','pytest'):
        check(importlib.util.find_spec(mod) is not None,f'missing dependency {mod}')
    check(importlib.util.find_spec('rfc8785') is not None,'missing rfc8785 (required before freeze tag)')
    for n in ('common','capability','rpc','evidence','experiment','profile','exploit','surface','candidate'):
        p=ROOT/'schemas'/f'{n}.schema.json';check(p.exists(),f'missing {p}')
        if p.exists():
            try:json.loads(p.read_text())
            except Exception as e:fails.append(f'invalid schema {p}: {e}')
    pool=ROOT/'core/rpc/pool.py';src=pool.read_text() if pool.exists() else ''
    check(src.count('def submit(')==1,'pool must contain exactly one submit')
    scan_py=[p for p in ROOT.rglob('*.py') if p.resolve()!=Path(__file__).resolve()]
    all_src='\n'.join(p.read_text(errors='ignore') for p in scan_py)
    check('_tokens._value' not in all_src,'private semaphore internals present')
    hang=[p for p in scan_py if re.search(r'^class\s+MockHangReleased\b',p.read_text(errors='ignore'),re.M)]
    check(hang==[ROOT/'core/rpc/hang.py'],f'MockHangReleased must be unique: {hang}')
    check((ROOT/'profiles/fw900').is_dir() and (ROOT/'profiles/fw1352').is_dir(),'profile dirs missing')
    print(f'PS4RF Pre-Flight: {checks} checks, {len(fails)} failures')
    for f in fails:print(' FAIL:',f)
    print('PRE-FLIGHT: PASS (static)' if not fails else 'PRE-FLIGHT: FAIL')
    return 0 if not fails else 1
if __name__=='__main__':raise SystemExit(main())
