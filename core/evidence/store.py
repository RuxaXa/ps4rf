from core.canonical import canonical_sha256
from core.models.verification import StoredEvidence,VerificationRejection
class InMemoryEvidenceStore:
    def __init__(self):self._items={}
    def put(self,item:StoredEvidence):
        d=item.model_dump(exclude={'canonical_sha256'});h=canonical_sha256(d);item=StoredEvidence.model_validate({**d,'canonical_sha256':h});self._items[h]=item;return item
    def hash_is_valid(self,h):return h in self._items
    def get_verified_evidence(self,h):
        if h not in self._items:raise VerificationRejection('EVIDENCE_HASH_INVALID')
        item=self._items[h];actual=canonical_sha256(item.model_dump(exclude={'canonical_sha256'}))
        if actual!=h or item.evidence_ref.run_id!=item.run_id:raise VerificationRejection('EVIDENCE_HASH_INVALID')
        return item
