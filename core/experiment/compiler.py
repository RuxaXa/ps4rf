from __future__ import annotations
import yaml
from core.canonical import canonical_sha256,canonical_bytes
from .budget import check_budget
def compile_experiment(src):
    ir=yaml.safe_load(src) if isinstance(src,str) else src
    canonical_bytes(ir);check_budget(ir);ir['_canonical_sha256']=canonical_sha256(ir);return ir
