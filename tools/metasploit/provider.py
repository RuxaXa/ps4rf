"""Metasploit provider manifest bridge (spec v0.3 §12.2/§12.3, P2).

Responsibilities:

* Validate ``modules/*.exploit.yaml`` manifests (``status: PROVIDER`` requires
  ``reliability`` + ``reproducers`` + ``profile_bindings``; reliability obeys the
  sum invariant from spec v0.4 §9.6; privileged capabilities in ``provides``
  require a ``verify.*`` operation).
* Enforce the execution-context mapping of §12.3 for msf refs:
  ``exploit/ps4/browser/*`` -> prepare HOST, trigger WEB_CONTENT, verify
  USERLAND_AGENT; ``auxiliary/ps4/*`` -> HOST; ``post/ps4/*`` -> declared
  session context (USERLAND_AGENT or SYSTEM_SERVICE).
* Bridge to the core :class:`~core.models.exploit.ExploitManifest` (name
  ``metasploit:<msf-ref>``), which is what ``grant_from_verification`` consumes.
* Carry the authority rule for the ``^metasploit:`` provider namespace: records
  from MSF module runs are capped at ``OBSERVED`` -- PROVEN can only arise from a
  separate PS4RF verification run whose record is attributed to a PS4RF-native
  provider (not the msf namespace) with ``verified_by.operation in verify.*``.

Deliberately NOT here: any orchestration. The adapter never chains
check->run->verify; the caller decides, the safety gates stay in PS4RF (§12.5).
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Optional

import yaml
from pydantic import Field, StringConstraints, model_validator

from core.models.capability import (AuthorityTable, CapabilityRecord, ProviderRule,
                                    default_authority)
from core.models.common import (Availability, Assurance, CapabilityName,
                                EvidenceRef, ExploitExecutionContext, ProviderType,
                                Sha256, StrictModel, TargetExecutionContext)
from core.models.exploit import CapabilityGrant, ExploitManifest
from core.rpc.registry import OperationRegistry, OperationSpec

MSF_PROVIDER_PATTERN = r"^metasploit:"
MSF_REF = Annotated[str, StringConstraints(
    pattern=r"^(exploit|auxiliary|post)/[a-z0-9_]+(/[a-z0-9_]+)*$")]

MODULES_DIR = Path(__file__).resolve().parent / "modules"


class MsfManifestStatus(str, Enum):
    PLANNED = "PLANNED"
    PROVIDER = "PROVIDER"


class MsfKind(str, Enum):
    EXPLOIT = "exploit"
    AUXILIARY = "auxiliary"
    POST = "post"


class ReliabilityStats(StrictModel):
    """Mirrors spec v0.4 §9.6 (moves to core with delivery 2)."""

    attempts: int = Field(ge=0)
    successes: int = Field(ge=0)
    clean_failures: int = Field(ge=0)
    hangs: int = Field(ge=0)
    panics: int = Field(ge=0)
    reboots: int = Field(ge=0)
    median_trigger_ms: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _sum_invariant(self) -> "ReliabilityStats":
        total = (self.successes + self.clean_failures + self.hangs
                 + self.panics + self.reboots)
        if total != self.attempts:
            raise ValueError("successes+clean_failures+hangs+panics+reboots != attempts")
        return self


class MsfExecutionContexts(StrictModel):
    """Execution contexts of a module per §12.3 (host-side, trigger, verify)."""

    prepare: ExploitExecutionContext
    trigger: Optional[ExploitExecutionContext] = None
    verify: Optional[ExploitExecutionContext] = None


class MsfModuleManifest(StrictModel):
    """Validated ``*.exploit.yaml`` module manifest (mock-scope, §12.3)."""

    status: MsfManifestStatus
    name: str
    msf_ref: MSF_REF
    kind: MsfKind
    execution: MsfExecutionContexts
    requires: list[CapabilityName] = Field(default_factory=list)
    provides: list[CapabilityGrant] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    verification: Optional[str] = None
    cleanup: Optional[str] = None
    reliability: Optional[ReliabilityStats] = None
    reproducers: list[str] = Field(default_factory=list)
    profile_bindings: list[Sha256] = Field(default_factory=list)
    side_effects: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _name_and_kind(self) -> "MsfModuleManifest":
        if self.name != f"metasploit:{self.msf_ref}":
            raise ValueError("name must be 'metasploit:<msf_ref>'")
        if self.kind.value != self.msf_ref.split("/")[0]:
            raise ValueError("kind must match the msf_ref prefix")
        return self

    @model_validator(mode="after")
    def _context_mapping(self) -> "MsfModuleManifest":
        ex = self.execution
        if self.kind is MsfKind.EXPLOIT:
            if ex.prepare is not ExploitExecutionContext.HOST:
                raise ValueError("exploit prepare context must be HOST (§12.3)")
            if self.msf_ref.startswith("exploit/ps4/browser/"):
                if (ex.trigger is not ExploitExecutionContext.WEB_CONTENT
                        or ex.verify is not ExploitExecutionContext.USERLAND_AGENT):
                    raise ValueError(
                        "exploit/ps4/browser/* requires trigger WEB_CONTENT and "
                        "verify USERLAND_AGENT (§12.3)")
        elif self.kind is MsfKind.AUXILIARY:
            if ex.prepare is not ExploitExecutionContext.HOST:
                raise ValueError("auxiliary context must be HOST (§12.3)")
            if ex.trigger is not None or ex.verify is not None:
                raise ValueError("auxiliary modules carry no trigger/verify context")
        else:  # post
            allowed = (ExploitExecutionContext.USERLAND_AGENT,
                       ExploitExecutionContext.SYSTEM_SERVICE)
            if ex.prepare not in allowed:
                raise ValueError(
                    "post context must be USERLAND_AGENT or SYSTEM_SERVICE (§12.3)")
            if ex.trigger is not None:
                raise ValueError("post modules carry no trigger context")
        return self

    @model_validator(mode="after")
    def _provider_completeness(self) -> "MsfModuleManifest":
        if self.status is MsfManifestStatus.PROVIDER:
            missing = []
            if self.reliability is None:
                missing.append("reliability")
            if not self.reproducers:
                missing.append("reproducers")
            if not self.profile_bindings:
                missing.append("profile_bindings")
            if missing:
                raise ValueError(f"status PROVIDER requires {', '.join(missing)}")
        return self


class MsfExploitProvider:
    """Manifest-backed provider entry: ``metasploit:<msf-ref>``."""

    def __init__(self, manifest: MsfModuleManifest) -> None:
        self.manifest = manifest

    @property
    def name(self) -> str:
        return self.manifest.name

    @classmethod
    def from_yaml(cls, path: Path) -> "MsfExploitProvider":
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        return cls(MsfModuleManifest.model_validate(data))

    def to_exploit_manifest(self) -> ExploitManifest:
        """Bridge to the core manifest consumed by ``grant_from_verification``."""
        return ExploitManifest(
            name=self.manifest.name,
            provides=list(self.manifest.provides),
            profile_bindings=list(self.manifest.profile_bindings))


def load_module_manifests(directory: Optional[Path] = None) -> dict[str, MsfExploitProvider]:
    """Load and validate all ``*.exploit.yaml`` manifests in the module dir."""
    directory = directory or MODULES_DIR
    providers: dict[str, MsfExploitProvider] = {}
    for path in sorted(directory.glob("*.exploit.yaml")):
        provider = MsfExploitProvider.from_yaml(path)
        if provider.name in providers:
            raise ValueError(f"duplicate module manifest: {provider.name}")
        providers[provider.name] = provider
    return providers


# ----------------------------------------------------------------------- authority
def msf_provider_rule() -> ProviderRule:
    """Provider namespace rule: ``^metasploit:`` records cap at OBSERVED (§12.3)."""
    return ProviderRule(provider_type=ProviderType.EXPLOIT,
                        max_assurance=Assurance.OBSERVED,
                        availability_write=True, availability_rank=30,
                        provider_pattern=MSF_PROVIDER_PATTERN)


def metasploit_authority_table(base: Optional[AuthorityTable] = None) -> AuthorityTable:
    """Authority table with the msf rule FIRST (``rule_for`` returns first match)."""
    base = base or default_authority()
    return AuthorityTable([msf_provider_rule(), *base.rules],
                          dict(base.min_assurance_for_grant))


def observed_capability_record(provider_name: str, capability: CapabilityName, *,
                               context: TargetExecutionContext,
                               session_id: Optional[str] = None,
                               boot_id: str = "BOOT-UNSET",
                               evidence: Optional[EvidenceRef] = None,
                               availability: Availability = Availability.AVAILABLE,
                               notes: Optional[str] = None) -> CapabilityRecord:
    """Availability/OBSERVED record produced by a metasploit module run (§12.3).

    Never PROVEN: an msf run yields at most an observation. PROVEN requires the
    separate PS4RF verification path (``grant_from_verification``) with a
    non-msf provider record.
    """
    return CapabilityRecord(name=capability, availability=availability,
                            assurance=Assurance.OBSERVED, context=context,
                            provider=provider_name, provider_type=ProviderType.EXPLOIT,
                            session_id=session_id, boot_id=boot_id,
                            evidence=evidence, notes=notes)


# ----------------------------------------------------------- host-core operations
# §12.6: host-core namespace -- never sent to ps4rfd. ``True`` = effect-bearing,
# ``False`` = query. Kept out of ``default_registry()`` on purpose: that registry
# describes what the *target daemon* may receive.
HOST_CORE_OPERATIONS: dict[str, bool] = {
    "msf.health": False,
    "msf.modules.list": False,
    "msf.modules.info": False,
    "msf.job.list": False,
    "msf.job.stop": True,
    "msf.session.list": False,
    "msf.session.info": False,
    "msf.session.command": True,
    "msf.session.close": True,
    "exploit.list": False,
    "exploit.info": False,
    "exploit.check": False,
    "exploit.run": True,
    "exploit.status": False,
    "exploit.verify": False,
    "chain.plan": False,
    "chain.run": True,
    "agent.deploy": True,
}


def register_host_core_operations(
        registry: Optional[OperationRegistry] = None) -> OperationRegistry:
    """Register §12.6 host-core operations (never transmitted to ps4rfd)."""
    registry = registry or OperationRegistry()
    for name, mutating in HOST_CORE_OPERATIONS.items():
        if not registry.has(name):
            registry.register(OperationSpec(name, None, mutating, False))
    return registry


def host_core_registry(base: Optional[OperationRegistry] = None) -> OperationRegistry:
    """Convenience: copy-style registry that starts empty (or from ``base``)."""
    return register_host_core_operations(base or OperationRegistry())


__all__ = ["MSF_PROVIDER_PATTERN", "MsfManifestStatus", "MsfKind", "ReliabilityStats",
           "MsfExecutionContexts", "MsfModuleManifest", "MsfExploitProvider",
           "load_module_manifests", "msf_provider_rule", "metasploit_authority_table",
           "observed_capability_record", "HOST_CORE_OPERATIONS",
           "register_host_core_operations", "host_core_registry"]
