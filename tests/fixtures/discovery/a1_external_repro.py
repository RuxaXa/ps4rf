"""Read-only, synthetic reproductions of confirmed PS4RF A1 findings.

ORIGIN: written by the independent A1 audit, supplied by the operator on 2026-11-05 and
kept verbatim so the auditor's own counterexamples stay executable. SHA-256
9abe5faad94e7c3773c502a0f328f758727e321acdc2bcab6f0835046b81e017 (85 lines before this
header). Every proof here asserts the behaviour of the audited snapshot 1328aa5, so on the
corrected tree each one must fail; tests/test_discovery_a1_external_repro.py requires
exactly that. Do not 'fix' this file -- it is the counterexample, not a test of the
desired behaviour.

Run: cd <extracted repo> && PYTHONPATH=. python tests/fixtures/discovery/a1_external_repro.py
No firmware / console / network required.
"""
from __future__ import annotations
import sys, types
from types import SimpleNamespace as N

# Minimal Capstone x86 operand-type stubs: testing the analyzer's own logic,
# not x86 decoding correctness. No external packages required.
cap = types.ModuleType('capstone'); x86 = types.ModuleType('capstone.x86')
for k,v in {'X86_OP_IMM':1, 'X86_OP_MEM':2, 'X86_OP_REG':3,
            'X86_REG_RBP':4, 'X86_REG_RSP':5}.items(): setattr(x86,k,v)
cap.x86=x86
sys.modules.setdefault('capstone',cap)
sys.modules.setdefault('capstone.x86',x86)

from tools.discovery import handles
from tools.discovery.semgraph import Graph, chains
from tools.discovery.queue import build
from tools.discovery.chains import compose

def ins(address, mnemonic, op_str='', operands=()):
    return N(address=address,mnemonic=mnemonic,op_str=op_str,
             operands=operands,reg_name=lambda x:{7:'rdi',8:'r15',9:'eax'}.get(x,'?'))
def mem(width=4,base=7,disp=16):
    return N(type=x86.X86_OP_MEM, mem=N(base=base,index=0,disp=disp),size=width)
def reg(n=9):return N(type=x86.X86_OP_REG,reg=n)

def handle_store_proof():
    mov=ins(0x100,'mov','dword ptr [rdi + 0x10], eax',[mem(),reg()])
    got=handles.summarize(N(disasm=lambda *args:([mov],None)),0x100,5)
    print('H1 mov-to-record-field: expected store {16:{4}}; got',got.stores)
    assert got.stores=={},'This reproduction is for the unpatched code.'

def refcount_guard_proof():
    dec=ins(0x100,'dec','dword ptr [rdi + 0x28]',[mem(base=7,disp=0x28)])
    cmp=ins(0x101,'cmp','eax, 0x10')  # compare with sixteen; NOT == 1
    call=ins(0x102,'call','0x500')
    view=N(ins=[dec,cmp,call],calls={0x102:0x500})
    shape=handles.release_shape(view,lambda rva:rva==0x500)
    print('H2 unrelated cmp eax,0x10 marked as refcount ==1 guard:',shape.drops[0].guarded)
    assert shape.drops[0].guarded is True

def shortest_path_proof():
    g=Graph()
    g.node('entry:sysent[11]','entry',subsystem='B')
    g.node('function:0x100','function',subsystem='A')
    g.node('function:0x200','function',subsystem='B')
    g.edge('entry:sysent[11]','function:0x100','reaches',{'site':'0x10','text':'known entry'},status='proved')
    g.edge('function:0x100','function:0x200','calls',{'site':'0x120','text':'proved call'})
    g.edge('entry:sysent[11]','function:0x200','reaches',{'site':'0x10','text':'summary not full path'},status='possible')
    f={'detector':'D3_test','rank':2,'function':{'rva':'0x200'},'bug_class':'RACE_UNLOCKED_SHARED_WRITE'}
    c=chains(g.export(),{'findings':[f]}, {})['chains'][0]
    print('H3 chain chosen:',c['hop_status'],'hops',c['hop_count'],'cross-subsystem',c['cross_subsystem'])
    print('   a fully-proved two-hop cross-subsystem path is present in the graph')
    assert (c['hop_status'],c['hop_count'],c['cross_subsystem'])==('possible',1,0)

def queue_merge_proof():
    a={'detector':'D2_double_release','function':{'rva':'0x100'},
       'bug_class':'OWNERSHIP_DOUBLE_FREE','falsification':'check identity',
       'slot':'A','sites':['0x110'],'rank':3,
       'claims':{'same_object':False,'case':'weak'},'window':['weak']}
    b={**a,'slot':'B','sites':['0x115'],'rank':1,
       'claims':{'same_object':True,'case':'strong'},'window':['strong']}
    entry={'0x100':{'kind':'syscall','syscall':99,'narg':2,'label':'sysent[99]','subsystem':'socket'}}
    c1=build([a,b],entry,{},[],min_rank=2)['queue'][0]
    c2=build([b,a],entry,{},[],min_rank=2)['queue'][0]
    print('H4 both rank',c1['evidence']['rank'],c2['evidence']['rank'],
          'but hypothesis differs by input order:')
    print('   first:',c1['root_cause_hypothesis'])
    print('   reversed:',c2['root_cause_hypothesis'])
    assert c1['root_cause_hypothesis']!=c2['root_cause_hypothesis']

def entry_gate_proof():
    f={'detector':'D7_test','function':{'rva':'0x999'},
       'bug_class':'REFCOUNT_IMBALANCE','claims':{}}
    c=compose(f,'entry:sysent[99]',{},entry_kind='syscall')
    print('H5 REQ_UNPRIV_ENTRY cleared without any credential/access evidence:',
          not any(b.id=='BLOCK_REQ_UNPRIV_ENTRY' for b in c.blockers))
    assert not any(b.id=='BLOCK_REQ_UNPRIV_ENTRY' for b in c.blockers)

if __name__=='__main__':
    handle_store_proof();refcount_guard_proof();shortest_path_proof();queue_merge_proof();entry_gate_proof()
    print('All 5 reproductions matched the audited snapshot (not passes of desired behavior).')
