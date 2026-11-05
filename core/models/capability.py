from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Sequence
from pydantic import model_validator
from .common import *

class Scope(str,Enum): SESSION='SESSION'; BOOT='BOOT'
class VerifiedBy(StrictModel):
    operation: OperationName
    expected: str
    observed: str
    verification_run: RunId
    @model_validator(mode='after')
    def _verifyop(self):
        if not self.operation.startswith('verify.'): raise ValueError('verify.* required')
        return self
class CapabilityRecord(StrictModel):
    name: CapabilityName
    availability: Availability
    assurance: Assurance
    context: TargetExecutionContext
    provider: str
    provider_type: ProviderType
    scope: Scope = Scope.SESSION
    session_id: Optional[str]=None
    boot_id: str = 'BOOT-UNSET'
    expires_on_reboot: bool = True
    evidence: Optional[EvidenceRef]=None
    verified_by: Optional[VerifiedBy]=None
    observed_seq: Optional[int]=None
    observed_at: Optional[datetime]=None
    provider_created_at: Optional[datetime]=None
    notes: Optional[str]=None
    @model_validator(mode='after')
    def _rules(self):
        if self.assurance is Assurance.PROVEN and (self.evidence is None or self.verified_by is None):
            raise ValueError('PROVEN requires evidence + verified_by')
        if self.scope is Scope.SESSION and self.observed_seq is not None and not self.session_id:
            raise ValueError('ingested SESSION record requires session_id')
        if self.scope is Scope.BOOT:
            if self.session_id is not None: raise ValueError('BOOT cannot carry session_id')
            if not self.expires_on_reboot: raise ValueError('BOOT records never survive reboot')
        return self

class CapabilityIntake:
    def __init__(self, session_id: str|None, boot_id: str):
        self.session_id=session_id; self.boot_id=boot_id; self._next_seq=0
    def ingest(self, rec: CapabilityRecord)->CapabilityRecord:
        if rec.observed_seq is not None: raise ValueError('observed_seq is host-only')
        if rec.scope is Scope.SESSION and self.session_id is None: raise ValueError('boot intake cannot ingest session record')
        self._next_seq+=1
        d=rec.model_dump()
        d.update(observed_seq=self._next_seq,observed_at=datetime.now(timezone.utc),boot_id=self.boot_id,session_id=self.session_id if rec.scope is Scope.SESSION else None)
        return CapabilityRecord.model_validate(d)

class ProviderRule(StrictModel):
    provider_type: ProviderType
    max_assurance: Assurance
    availability_write: bool=True
    availability_rank: int=0
    provider_pattern: Optional[str]=None
class AuthorityTable:
    def __init__(self,rules=None,min_grant=None): self.rules=rules or []; self.min_assurance_for_grant=min_grant or {}
    def rule_for(self,name,ptype,provider):
        import re
        candidates=[r for r in self.rules if r.provider_type is ptype and (not r.provider_pattern or re.search(r.provider_pattern,provider))]
        return candidates[0] if candidates else None

def default_authority():
    rules=[]
    for p,a,w,rank in [
        (ProviderType.EXPLOIT,Assurance.PROVEN,True,30),(ProviderType.RUNTIME_PROBE,Assurance.OBSERVED,True,30),(ProviderType.BOOTSTRAP,Assurance.OBSERVED,True,20),(ProviderType.FIRMWARE_PROFILE,Assurance.UNVERIFIED,False,0),(ProviderType.MOCK,Assurance.PROVEN,True,10),(ProviderType.OPERATOR,Assurance.PROVEN,False,100),(ProviderType.NATIVE,Assurance.OBSERVED,True,25)]:  # NATIVE entry = W7/F7 patch: ceiling OBSERVED, PROVEN only via verification evidence
        rules.append(ProviderRule(provider_type=p,max_assurance=a,availability_write=w,availability_rank=rank))
    mins={ns:Assurance.PROVEN for ns in PRIVILEGED_NAMESPACES}
    for ns in ['userland','memory','network','filesystem','ioctl','rpc','syscall','jit','shared_memory']: mins[ns]=Assurance.OBSERVED
    return AuthorityTable(rules,mins)

class AxisFactor(str,Enum): MANUAL_OVERRIDE='MANUAL_OVERRIDE'; PROVIDER_AUTHORITY='PROVIDER_AUTHORITY'; RUNTIME_RECENCY='RUNTIME_RECENCY'; RECENCY='RECENCY'; EVIDENCE_RANK='EVIDENCE_RANK'; AUTHORITY_CEILING='AUTHORITY_CEILING'; NO_RECORD='NO_RECORD'
class AxisResolution(StrictModel): value:str; factor:AxisFactor; record_index:Optional[int]=None; detail:str=''
class ExcludedRecord(StrictModel): record_index:int; reason:str
class Resolution(StrictModel):
    name:CapabilityName; availability:Availability; assurance:Assurance; availability_resolution:AxisResolution; assurance_resolution:AxisResolution; excluded:tuple[ExcludedRecord,...]=()
class ManualOverride(StrictModel):
    availability:Optional[Availability]=None; assurance:Optional[Assurance]=None; detail:str=''

def _clamp(a,c): return a if ASSURANCE_RANK[a] <= ASSURANCE_RANK[c] else c

def resolve(name: str, scope: Scope, context: TargetExecutionContext, records: Sequence[CapabilityRecord], authority: AuthorityTable, manual: Optional[ManualOverride]=None, *, session_id:Optional[str]=None, boot_id:Optional[str]=None)->Resolution:
    if scope is Scope.SESSION and not session_id: raise ValueError('session_id required')
    if not boot_id: raise ValueError('boot_id required')
    participants=[]; excluded=[]
    for i,r in enumerate(records):
        reason=None
        if r.name != name: reason='NAME_MISMATCH'
        elif r.scope is not scope: reason='SCOPE_MISMATCH'
        elif r.context is not context: reason='CONTEXT_MISMATCH'
        elif scope is Scope.SESSION and r.session_id != session_id: reason='SESSION_MISMATCH'
        elif r.boot_id != boot_id: reason='BOOT_MISMATCH'
        if reason: excluded.append(ExcludedRecord(record_index=i,reason=reason)); continue
        rule=authority.rule_for(name,r.provider_type,r.provider)
        if rule is None: excluded.append(ExcludedRecord(record_index=i,reason='AUTHORITY_INVALID')); continue
        if r.observed_seq is None: raise ValueError('record not ingested')
        participants.append((i,r,rule))
    seqs=[r.observed_seq for _,r,_ in participants]
    if len(seqs)!=len(set(seqs)): raise ValueError('duplicate observed_seq')
    if manual and manual.availability is not None:
        av=manual.availability; ar=AxisResolution(value=av.value,factor=AxisFactor.MANUAL_OVERRIDE,detail=manual.detail)
    else:
        elig=[x for x in participants if x[2].availability_write]
        if not elig: av=Availability.UNKNOWN; ar=AxisResolution(value=av.value,factor=AxisFactor.NO_RECORD)
        else:
            top=max(x[2].availability_rank for x in elig); tier=sorted([x for x in elig if x[2].availability_rank==top],key=lambda x:x[1].observed_seq); i,r,_=tier[-1]
            av=r.availability; ar=AxisResolution(value=av.value,factor=AxisFactor.RUNTIME_RECENCY if len(tier)>1 else AxisFactor.PROVIDER_AUTHORITY,record_index=i)
    if manual and manual.assurance is Assurance.PROVEN: raise ValueError('ManualOverride cannot create PROVEN')
    best=[]
    for i,r,ru in participants: best.append((ASSURANCE_RANK[_clamp(r.assurance,ru.max_assurance)],i,r,_clamp(r.assurance,ru.max_assurance)))
    if manual and manual.assurance is not None:
        best.append((ASSURANCE_RANK[manual.assurance],-1,None,manual.assurance))
    if not best: ass=Assurance.UNVERIFIED; sr=AxisResolution(value=ass.value,factor=AxisFactor.NO_RECORD)
    else:
        rank=max(x[0] for x in best); same=sorted([x for x in best if x[0]==rank],key=lambda x:(-1 if x[2] is None else x[2].observed_seq or -1)); _,i,r,ass=same[-1]
        sr=AxisResolution(value=ass.value,factor=AxisFactor.MANUAL_OVERRIDE if i==-1 else (AxisFactor.RECENCY if len(same)>1 else AxisFactor.EVIDENCE_RANK),record_index=None if i==-1 else i)
    return Resolution(name=name,availability=av,assurance=ass,availability_resolution=ar,assurance_resolution=sr,excluded=tuple(excluded))

class Requirement(StrictModel): name:CapabilityName; min_assurance:Assurance=Assurance.UNVERIFIED; allow_degraded:bool=False
class GrantDecision(StrictModel): name:CapabilityName; granted:bool; reason:str; availability:Availability; assurance:Assurance

def effective_grant(req,res,session_context,record_context,authority,recovery_required=False):
    if recovery_required: return GrantDecision(name=req.name,granted=False,reason='RECOVERY_REQUIRED',availability=res.availability,assurance=res.assurance)
    if session_context is not record_context: return GrantDecision(name=req.name,granted=False,reason='CONTEXT_MISMATCH',availability=res.availability,assurance=res.assurance)
    nsmin=authority.min_assurance_for_grant.get(req.name.split('.')[0],Assurance.UNVERIFIED); need=req.min_assurance if ASSURANCE_RANK[req.min_assurance]>=ASSURANCE_RANK[nsmin] else nsmin
    if not (res.availability is Availability.AVAILABLE or (res.availability is Availability.DEGRADED and req.allow_degraded)):
        return GrantDecision(name=req.name,granted=False,reason='DEGRADED_NOT_ALLOWED' if res.availability is Availability.DEGRADED else 'CAPABILITY_MISSING',availability=res.availability,assurance=res.assurance)
    if ASSURANCE_RANK[res.assurance] < ASSURANCE_RANK[need]: return GrantDecision(name=req.name,granted=False,reason='ASSURANCE_INSUFFICIENT',availability=res.availability,assurance=res.assurance)
    return GrantDecision(name=req.name,granted=True,reason='OK',availability=res.availability,assurance=res.assurance)
