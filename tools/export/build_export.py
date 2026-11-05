#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,zipfile,tarfile,datetime
ROOT=Path(__file__).resolve().parents[2];DIST=ROOT/'dist';DIST.mkdir(exist_ok=True);PREFIX='PS4RF'
SKIP={'.git','.venv','venv','__pycache__','.pytest_cache','dist'}
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b)
    return h.hexdigest()
def files():
    return [p for p in ROOT.rglob('*') if p.is_file() and not any(x in p.parts for x in SKIP) and p.name not in ('SHA256SUMS','EXPORT-MANIFEST.json')]
def main():
    es=[(p.relative_to(ROOT).as_posix(),p,sha(p),p.stat().st_size) for p in files()]
    sums='\n'.join(f'{h}  {rel}' for rel,p,h,s in es)+'\n';(DIST/'SHA256SUMS').write_text(sums)
    man={'project_name':'PS4RF','project_version':'0.8.1-handoff-candidate','status':'FREEZE_PATCH_APPLIED_NOT_TESTED','created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'file_count':len(es),'files':[{'path':r,'sha256':h,'size':s} for r,p,h,s in es],'freeze_gate_command':'python tools/freeze/run_gate_suite.py','expected_freeze_tag':'PS4RF-CORE-1.0-MOCK-READY'}
    (DIST/'EXPORT-MANIFEST.json').write_text(json.dumps(man,indent=2))
    zp=DIST/'ps4rf-core-1.0-mock-ready-candidate.zip';tp=DIST/'ps4rf-core-1.0-mock-ready-candidate.tar.gz'
    with zipfile.ZipFile(zp,'w',zipfile.ZIP_DEFLATED) as z:
        z.write(DIST/'SHA256SUMS',f'{PREFIX}/SHA256SUMS');z.write(DIST/'EXPORT-MANIFEST.json',f'{PREFIX}/EXPORT-MANIFEST.json')
        for r,p,h,s in es:z.write(p,f'{PREFIX}/{r}')
    with tarfile.open(tp,'w:gz') as t:
        t.add(DIST/'SHA256SUMS',arcname=f'{PREFIX}/SHA256SUMS');t.add(DIST/'EXPORT-MANIFEST.json',arcname=f'{PREFIX}/EXPORT-MANIFEST.json')
        for r,p,h,s in es:t.add(p,arcname=f'{PREFIX}/{r}')
    print(json.dumps({'zip':str(zp),'zip_sha256':sha(zp),'tar':str(tp),'tar_sha256':sha(tp),'file_count':len(es)},indent=2))
if __name__=='__main__':main()
