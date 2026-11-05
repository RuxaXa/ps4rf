from __future__ import annotations
import hashlib, json, math, re
from typing import Any
try:
    import rfc8785 as _rfc8785
except Exception:
    _rfc8785 = None

SAFE_MAX = 2**53 - 1
SAFE_MIN = -SAFE_MAX
_HEX16 = re.compile(r"^0x[0-9a-f]{16}$")

class UnsafeNumber(ValueError): pass

def validate_safe_numbers(obj: Any) -> None:
    if obj is None or isinstance(obj,(bool,str)): return
    if isinstance(obj,int):
        if not SAFE_MIN <= obj <= SAFE_MAX: raise UnsafeNumber(obj)
        return
    if isinstance(obj,float):
        if not math.isfinite(obj): raise UnsafeNumber(obj)
        if obj.is_integer() and abs(obj) > SAFE_MAX: raise UnsafeNumber(obj)
        return
    if isinstance(obj,dict):
        for k,v in obj.items():
            if not isinstance(k,str): raise TypeError("JSON object keys must be strings")
            validate_safe_numbers(v)
        return
    if isinstance(obj,(list,tuple)):
        for v in obj: validate_safe_numbers(v)
        return
    raise TypeError(type(obj))

def jcs_bytes(obj: Any) -> bytes:
    if _rfc8785 is not None:
        return _rfc8785.dumps(obj)
    # Handoff fallback only. Hermes must install rfc8785 before freeze tagging.
    return json.dumps(obj, ensure_ascii=False, separators=(",",":"), sort_keys=True).encode()

def canonical_bytes(obj: Any) -> bytes:
    validate_safe_numbers(obj)
    return jcs_bytes(obj)

def canonical_sha256(obj: Any) -> str:
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()

def normalize_u64(value: str|int) -> str:
    if isinstance(value,str):
        if not value.lower().startswith('0x'): raise ValueError('u64 requires 0x prefix')
        v=int(value,16)
    else: v=int(value)
    if not 0 <= v < 2**64: raise ValueError(value)
    return f"0x{v:016x}"

def is_canonical_u64(value: str) -> bool:
    return bool(_HEX16.fullmatch(value))
