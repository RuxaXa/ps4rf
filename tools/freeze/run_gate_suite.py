#!/usr/bin/env python3
import json,subprocess,sys
from pathlib import Path
from datetime import datetime,timezone
TAG='PS4RF-CORE-1.0-MOCK-READY'
GATES=[('G1',['python','-m','pytest','tests/','-q','--tb=short']),('G2',['python','-m','pytest','tests/test_roundtrip.py','-q']),('G3',['python','-m','pytest','tests/test_mock_recovery.py','-q']),('G4',['python','-m','pytest','tests/test_pool.py','tests/test_concurrency.py','-q']),('G5',['python','-m','pytest','tests/test_gate.py','tests/test_sync.py','-q']),('G6',['python','-m','pytest','tests/test_verification.py','-q']),('G7',['python','-m','pytest','tests/test_framing.py','tests/test_handshake_roles.py','-q']),('G8',['python','-m','pytest','tests/test_rpc_budget.py','-q'])]
def sh(c):
    p=subprocess.run(c,capture_output=True,text=True);return p.returncode,(p.stdout+p.stderr).strip()
def main():
    results={};fails=[]
    for g,c in GATES:
        rc,out=sh(c);results[g]={'cmd':' '.join(c),'rc':rc,'summary':out.splitlines()[-1] if out else ''}
        if rc:fails.append((g,out))
    grc,commit=sh(['git','rev-parse','HEAD']); drc,dirty=sh(['git','status','--porcelain'])
    report={'tag_candidate':TAG,'commit':commit if grc==0 else None,'worktree_dirty':bool(dirty) if drc==0 else None,'python':sys.version,'timestamp_utc':datetime.now(timezone.utc).isoformat(),'gates':results,'all_green':not fails and grc==0 and drc==0 and not dirty}
    Path('FREEZE-REPORT.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))
    for g,out in fails:print(f'\nFAILED gate={g}\n{out[-4000:]}')
    if report['all_green']:
        subprocess.run(['git','tag',TAG],check=True);print('TAG set:',TAG);return 0
    print('NOT TAGGED');return 1
if __name__=='__main__':raise SystemExit(main())
