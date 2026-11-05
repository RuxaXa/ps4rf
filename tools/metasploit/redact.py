import re
from core.canonical import canonical_sha256
REDACTED='<redacted>';SECRET_KEY_RE=re.compile(r'(?i)(password|pass|token|secret|api[_-]?key|key)$')
def redact_options(options,sensitive_from_module=None,extra_fields=None):
    sensitive=set(sensitive_from_module or ())|set(extra_fields or ());out={};red=[]
    for k,v in options.items():
        if k in sensitive or SECRET_KEY_RE.search(k):out[k]=REDACTED;red.append(k)
        else:out[k]=v
    return out,sorted(red)
def options_sha256(options,**kw):return canonical_sha256(redact_options(options,**kw)[0])
