from __future__ import annotations
from enum import Enum
from .common import *
from .capability import *
from .exploit import ExploitManifest
class VerificationOutcome(str,Enum): PASS='PASS'; FAIL='FAIL'; ERROR='ERROR'; TIMEOUT='TIMEOUT'
class VerificationEvidence(StrictModel):
    verification_run_id:RunId; operation:OperationName; outcome:VerificationOutcome; capability:CapabilityName; provider:str; provider_type:ProviderType=ProviderType.EXPLOIT; profile_sha256:Sha256; context:TargetExecutionContext; scope:Scope; session_id:str|None=None; boot_id:str; expected:str; observed:str; evidence_sha256:Sha256
class StoredEvidence(StrictModel):
    evidence_ref:EvidenceRef; run_id:RunId; operation:OperationName; outcome:VerificationOutcome; capability:CapabilityName; provider:str; provider_type:ProviderType; profile_sha256:Sha256; context:TargetExecutionContext; scope:Scope; session_id:str|None=None; boot_id:str; expected:str; observed:str; canonical_sha256:Sha256
class VerificationRejection(Exception):
    def __init__(self,reason,detail=''): self.reason=reason; self.detail=detail; super().__init__(f'{reason}: {detail}')
_FIELDS=('run_id','operation','outcome','capability','provider','provider_type','profile_sha256','context','scope','session_id','boot_id','expected','observed')
def grant_from_verification(v, capability, manifest:ExploitManifest, trigger_run_id, authority, registry, evidence_store, intake):
    def rej(r,d=''): raise VerificationRejection(r,d)
    if v.scope is Scope.SESSION and v.session_id != intake.session_id: rej('INTAKE_MISMATCH','session')
    if v.boot_id != intake.boot_id: rej('INTAKE_MISMATCH','boot')
    if v.provider != manifest.name: rej('PROVIDER_MISMATCH')
    grant=next((g for g in manifest.provides if g.capability==capability),None)
    if not grant: rej('CAPABILITY_MISMATCH')
    if not grant.verify_operation or v.operation != grant.verify_operation: rej('OPERATION_MISMATCH')
    try: registry.spec(v.operation)
    except KeyError: rej('REGISTRY_UNKNOWN')
    if v.outcome is not VerificationOutcome.PASS: rej('OUTCOME_NOT_PASS')
    stored=evidence_store.get_verified_evidence(v.evidence_sha256)
    for f in _FIELDS:
        vv=v.verification_run_id if f=='run_id' else getattr(v,f)
        if getattr(stored,f) != vv: rej('EVIDENCE_CONTENT_MISMATCH',f)
    if manifest.profile_bindings and v.profile_sha256 not in manifest.profile_bindings: rej('PROFILE_MISMATCH')
    privileged=capability.split('.')[0] in PRIVILEGED_NAMESPACES
    if privileged and v.verification_run_id==trigger_run_id: rej('RUN_NOT_SEPARATE')
    rule=authority.rule_for(capability,v.provider_type,v.provider)
    if rule is None: rej('AUTHORITY_INVALID')
    proven=ASSURANCE_RANK[rule.max_assurance] >= ASSURANCE_RANK[Assurance.PROVEN]
    assurance=Assurance.PROVEN if proven else Assurance.OBSERVED
    return intake.ingest(CapabilityRecord(name=capability,availability=Availability.AVAILABLE,assurance=assurance,context=v.context,provider=v.provider,provider_type=v.provider_type,scope=v.scope,session_id=v.session_id,boot_id=v.boot_id,evidence=stored.evidence_ref,verified_by=VerifiedBy(operation=v.operation,expected=stored.expected,observed=stored.observed,verification_run=stored.run_id) if proven else None))
