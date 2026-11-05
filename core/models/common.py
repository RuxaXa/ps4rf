from __future__ import annotations
from enum import Enum
from typing import Annotated, Optional
from pydantic import BaseModel, ConfigDict, StringConstraints

class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')

Sha256 = Annotated[str,StringConstraints(pattern=r'^[a-f0-9]{64}$')]
RunId = Annotated[str,StringConstraints(pattern=r'^RUN-[0-9]{8}T[0-9]{6}Z-[0-9A-Fa-f]{8}$')]
SessionId = Annotated[str,StringConstraints(pattern=r'^SES-[0-9A-Fa-f]{16,64}$')]
RequestId = Annotated[str,StringConstraints(pattern=r'^REQ-[0-9a-f]{32}$')]
CapabilityName = Annotated[str,StringConstraints(pattern=r'^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$')]
OperationName = CapabilityName
U64Hex = Annotated[str,StringConstraints(pattern=r'^0x[0-9a-f]{16}$')]
Address = U64Hex
AddressKernel = U64Hex

class TargetExecutionContext(str,Enum):
    BROWSER='BROWSER'; MEDIA_PLAYER='MEDIA_PLAYER'; SYSTEM_SERVICE='SYSTEM_SERVICE'; HOMEBREW='HOMEBREW'; JAILBROKEN_PROCESS='JAILBROKEN_PROCESS'; UNKNOWN='UNKNOWN'
class ExploitExecutionContext(str,Enum):
    HOST='HOST'; WEB_CONTENT='WEB_CONTENT'; USERLAND_AGENT='USERLAND_AGENT'; SYSTEM_SERVICE='SYSTEM_SERVICE'; KERNEL_CONTEXT='KERNEL_CONTEXT'; BOOTSTRAP_PROVIDER='BOOTSTRAP_PROVIDER'; MULTI_STAGE='MULTI_STAGE'
class Availability(str,Enum): UNKNOWN='UNKNOWN'; AVAILABLE='AVAILABLE'; DEGRADED='DEGRADED'; UNAVAILABLE='UNAVAILABLE'
class Assurance(str,Enum): UNVERIFIED='UNVERIFIED'; OBSERVED='OBSERVED'; PROVEN='PROVEN'
class ProviderType(str,Enum): FIRMWARE_PROFILE='FIRMWARE_PROFILE'; BOOTSTRAP='BOOTSTRAP'; EXPLOIT='EXPLOIT'; RUNTIME_PROBE='RUNTIME_PROBE'; MOCK='MOCK'; OPERATOR='OPERATOR'; NATIVE='NATIVE'  # W7/F7 integration patch
ASSURANCE_RANK={Assurance.UNVERIFIED:0,Assurance.OBSERVED:1,Assurance.PROVEN:2}
PRIVILEGED_NAMESPACES=('kernel','gpuvm','keymgr','ccp','samu','pup','eap','sbram','emc','secure')

class EvidenceRef(StrictModel):
    run_id: RunId
    path: Optional[str]=None
    sha256: Optional[Sha256]=None
