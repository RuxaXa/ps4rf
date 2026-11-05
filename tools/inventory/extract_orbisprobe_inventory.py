#!/usr/bin/env python3
from __future__ import annotations
import ast,re,sys
from pathlib import Path
HEX=re.compile(r'\b0x[0-9a-fA-F]{6,16}\b');FW=re.compile(r'(?i)\b(fw|firmware)[\s_-]?([0-9]{1,2}\.[0-9]{2})\b');PS4=re.compile(r'(?i)\b(orbis|ps4|libkernel|app0|cdev|sce\w+|sysctl|/dev/)\b');LIVE=re.compile(r'(?i)(subprocess|os\.system|os\.popen|socket\.|ptrace|ctypes|CDLL|mmap)');SAFETY=re.compile(r'(?i)(safety|guard|dry[_-]?run|confirm|abort|risk)');TOOLS=re.compile(r'(?i)(ghidra|rizin|radare2?|angr|unicorn|afl|syzkaller|boofuzz|scapy|tshark|wireshark|mitmproxy)')
TAGS=((HEX,'hexconst'),(FW,'fwversion'),(PS4,'ps4keyword'),(LIVE,'liveexec'),(SAFETY,'safety'),(TOOLS,'tool'))
def main(root='.'):
    root=Path(root);mods=[];classes=[];funcs=[];hits=[];tests=[]
    for p in sorted(root.rglob('*')):
        if not p.is_file() or any(x in p.parts for x in ('.git','venv','.venv','__pycache__')):continue
        if p.name.startswith('test_') or p.name.endswith('_test.py'):tests.append(str(p))
        if p.suffix=='.py':
            src=p.read_text(errors='replace');mods.append(str(p))
            try:tree=ast.parse(src)
            except SyntaxError:tree=None;hits.append(f'{p}:0 [PARSE_ERROR]')
            if tree:
                for n in ast.walk(tree):
                    if isinstance(n,ast.ClassDef):classes.append(f'{p}:{n.lineno} class {n.name}')
                    elif isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):funcs.append(f'{p}:{n.lineno} def {n.name}')
            for i,line in enumerate(src.splitlines(),1):
                for rx,tag in TAGS:
                    if rx.search(line):hits.append(f'{p}:{i} [{tag}] {line.strip()[:160]}')
    out=Path('ORBISPROBE-INVENTORY.draft.md')
    out.write_text('# ORBISPROBE-INVENTORY (static draft)\n\n## Modules\n```\n'+'\n'.join(mods)+'\n```\n\n## Classes\n```\n'+'\n'.join(classes)+'\n```\n\n## Functions\n```\n'+'\n'.join(funcs)+'\n```\n\n## Findings\n```\n'+'\n'.join(hits)+'\n```\n\n## Tests\n```\n'+'\n'.join(tests)+'\n```\n')
    print(out)
if __name__=='__main__':main(sys.argv[1] if len(sys.argv)>1 else '.')
