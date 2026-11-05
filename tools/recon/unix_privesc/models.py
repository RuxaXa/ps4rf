"""Data contract for the platform-independent local enumeration layer.

Two directions:

* **Input** -- ``ps4rf.unix_privesc.collect/v1``: a collector document that a
  future target-side collector produces and this layer consumes. Raw strings
  only; the adapter never interprets them.
* **Output** -- the classification report (:class:`UnixPrivescReport`) built
  from a validated collector document. Every report node is an explicit
  ``OBSERVATION`` that ``requires_verification`` -- recon output is never an
  exploit finding.

Platform semantics: every category carries ``posix`` | ``linux_only`` |
``freebsd_only`` and the classifier records the per-platform applicability
(``applicable`` | ``inapplicable`` | ``refused``). Linux- and OrbisOS/FreeBSD
specific checks can be derived from this substrate later.

PS4/OrbisOS-specific checks are intentionally out of scope: they are owned by
PS4RF surface/experiment modules and implemented later natively. Raw hints land
in the separate ``platform_specific`` bucket, pinned to :data:`PS4_SCOPE_NOTE`;
this layer makes no PS4 coverage claim.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated

from pydantic import ConfigDict, Field, StringConstraints, model_validator

from core.models.common import Sha256, StrictModel

SCHEMA_ID = "ps4rf.unix_privesc.collect/v1"

NonEmptyStr = Annotated[str, StringConstraints(min_length=1)]

PS4_OWNERSHIP_OWNER = "ps4rf.surface/experiment"
PS4_SCOPE_NOTE = (
    "PS4/OrbisOS-specific checks are owned by PS4RF surface/experiment modules "
    "and are implemented later natively; this platform-independent enumeration "
    "layer records raw observations only and makes no PS4 coverage claim."
)


# ------------------------------------------------------------------ enumerations
class TargetPlatform(str, Enum):
    """Platform detected from the collector's verbatim platform hint."""

    LINUX = "linux"
    FREEBSD_ORBISOS = "freebsd_orbisos"
    UNKNOWN = "unknown"


class PlatformSemantics(str, Enum):
    """Platform semantics of a category (the layer's key contract)."""

    POSIX = "posix"
    LINUX_ONLY = "linux_only"
    FREEBSD_ONLY = "freebsd_only"


class CategoryStatus(str, Enum):
    """Per-category classification outcome (never a silent drop)."""

    APPLICABLE = "applicable"
    INAPPLICABLE = "inapplicable"
    REFUSED = "refused"


class PlatformInterpretation(str, Enum):
    """Document-level interpretation state (``refused`` for unknown targets)."""

    APPLICABLE = "applicable"
    REFUSED = "refused"


class PlatformSpecificStatus(str, Enum):
    """State of the separate PS4/OrbisOS bucket."""

    DEFERRED = "deferred"
    REFUSED = "refused"


class ObservationClass(str, Enum):
    """Recon output classification -- always exactly ``OBSERVATION``."""

    OBSERVATION = "OBSERVATION"


class Category(str, Enum):
    """The captured enumeration categories of ``ps4rf.unix_privesc.collect/v1``."""

    OS_KERNEL = "os_kernel"
    IDENTITY = "identity"
    MOUNTS = "mounts"
    FILESYSTEM_PERMISSIONS = "filesystem_permissions"
    SUID = "suid"
    SGID = "sgid"
    PATH = "path"
    ENVIRONMENT = "environment"
    PROCESSES = "processes"
    SERVICES = "services"
    SOCKETS = "sockets"
    CRON = "cron"
    WRITABLE_EXECUTABLES = "writable_executables"
    WRITABLE_LIBRARIES = "writable_libraries"
    WRITABLE_CONFIGURATION = "writable_configuration"
    DEVICE_NODES = "device_nodes"
    LOADED_MODULES = "loaded_modules"
    SYSCTLS = "sysctls"
    JAILS = "jails"
    SHELLS = "shells"
    INSTALLED_BINARIES = "installed_binaries"
    PROCFS = "procfs"
    SYSTEMD = "systemd"


# Category -> platform semantics. Jails are FreeBSD/OrbisOS-only; proc-based
# and systemd-based fields are Linux-only; everything else is POSIX.
CATEGORY_SEMANTICS: dict[Category, PlatformSemantics] = {
    Category.OS_KERNEL: PlatformSemantics.POSIX,
    Category.IDENTITY: PlatformSemantics.POSIX,
    Category.MOUNTS: PlatformSemantics.POSIX,
    Category.FILESYSTEM_PERMISSIONS: PlatformSemantics.POSIX,
    Category.SUID: PlatformSemantics.POSIX,
    Category.SGID: PlatformSemantics.POSIX,
    Category.PATH: PlatformSemantics.POSIX,
    Category.ENVIRONMENT: PlatformSemantics.POSIX,
    Category.PROCESSES: PlatformSemantics.POSIX,
    Category.SERVICES: PlatformSemantics.POSIX,
    Category.SOCKETS: PlatformSemantics.POSIX,
    Category.CRON: PlatformSemantics.POSIX,
    Category.WRITABLE_EXECUTABLES: PlatformSemantics.POSIX,
    Category.WRITABLE_LIBRARIES: PlatformSemantics.POSIX,
    Category.WRITABLE_CONFIGURATION: PlatformSemantics.POSIX,
    Category.DEVICE_NODES: PlatformSemantics.POSIX,
    Category.LOADED_MODULES: PlatformSemantics.POSIX,
    Category.SYSCTLS: PlatformSemantics.POSIX,
    Category.JAILS: PlatformSemantics.FREEBSD_ONLY,
    Category.SHELLS: PlatformSemantics.POSIX,
    Category.INSTALLED_BINARIES: PlatformSemantics.POSIX,
    Category.PROCFS: PlatformSemantics.LINUX_ONLY,
    Category.SYSTEMD: PlatformSemantics.LINUX_ONLY,
}


def classification_status(platform: TargetPlatform,
                          semantics: PlatformSemantics) -> CategoryStatus:
    """Platform-independent applicability rule (single source of truth).

    * ``posix`` categories are always ``applicable``.
    * on an ``unknown`` platform, platform-specific categories are ``refused``
      (never guessed);
    * otherwise a category matching the platform is ``applicable`` and a
      category belonging to another platform is ``inapplicable``.
    """
    if semantics is PlatformSemantics.POSIX:
        return CategoryStatus.APPLICABLE
    if platform is TargetPlatform.UNKNOWN:
        return CategoryStatus.REFUSED
    matches = ((semantics is PlatformSemantics.LINUX_ONLY
                and platform is TargetPlatform.LINUX)
               or (semantics is PlatformSemantics.FREEBSD_ONLY
                   and platform is TargetPlatform.FREEBSD_ORBISOS))
    return CategoryStatus.APPLICABLE if matches else CategoryStatus.INAPPLICABLE


# --------------------------------------------------------------- input contract
class RawEntry(StrictModel):
    """One raw, uninterpreted collector entry (key/value strings only)."""

    key: NonEmptyStr
    value: str


class CategoryBlock(StrictModel):
    """Raw entries for one category, exactly as the collector reported them."""

    category: Category
    entries: list[RawEntry] = Field(default_factory=list)


class CollectorInfo(StrictModel):
    tool: NonEmptyStr
    version: NonEmptyStr


class TargetInfo(StrictModel):
    """Target identity. ``platform_hint`` is the collector's verbatim string."""

    hostname: NonEmptyStr
    platform_hint: str
    os: str
    kernel: str


class CollectorDocument(StrictModel):
    """``ps4rf.unix_privesc.collect/v1`` document. Strict: unknown fields refuse."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_id: NonEmptyStr = Field(alias="schema")
    collector: CollectorInfo
    target: TargetInfo
    categories: list[CategoryBlock]
    platform_specific: list[RawEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def _contract(self) -> "CollectorDocument":
        if self.schema_id != SCHEMA_ID:
            raise ValueError(f"unsupported collector schema: {self.schema_id!r}")
        seen = [block.category for block in self.categories]
        if len(seen) != len(set(seen)):
            raise ValueError("duplicate category blocks in collector document")
        return self


# -------------------------------------------------------------- output contract
class Observation(StrictModel):
    """Base for every node of the report tree: observation-only, always verified.

    Recon output is never an exploit finding; the validator refuses any node
    that claims otherwise.
    """

    classification: ObservationClass = ObservationClass.OBSERVATION
    requires_verification: bool = True

    @model_validator(mode="after")
    def _observation_only(self) -> "Observation":
        if self.classification is not ObservationClass.OBSERVATION:
            raise ValueError(
                "recon output is observation-only: classification must be OBSERVATION")
        if self.requires_verification is not True:
            raise ValueError("recon observations always require verification")
        return self


class DocumentBinding(Observation):
    """Hash-bound provenance of the collector document this report derives from."""

    document_sha256: Sha256
    document_bytes: int = Field(ge=0)
    collector_tool: NonEmptyStr
    collector_version: NonEmptyStr
    hostname: NonEmptyStr


class CategoryEntry(Observation):
    """Raw entry carried through into the report, still uninterpreted."""

    key: NonEmptyStr
    value: str


class CategoryReport(Observation):
    """Classification of one category: semantics, platform status, raw entries."""

    category: Category
    platform_semantics: PlatformSemantics
    status: CategoryStatus
    entries: list[CategoryEntry] = Field(default_factory=list)
    note: NonEmptyStr


class PlatformSpecificFindings(Observation):
    """Separate bucket for PS4/OrbisOS-specific raw hints (deferred, no claims).

    The owner and the scope note are pinned: PS4-specific checks are owned by
    PS4RF surface/experiment modules and implemented later natively.
    """

    findings: list[CategoryEntry] = Field(default_factory=list)
    owner: NonEmptyStr = PS4_OWNERSHIP_OWNER
    status: PlatformSpecificStatus = PlatformSpecificStatus.DEFERRED
    note: NonEmptyStr = PS4_SCOPE_NOTE

    @model_validator(mode="after")
    def _scope_pinned(self) -> "PlatformSpecificFindings":
        if self.owner != PS4_OWNERSHIP_OWNER:
            raise ValueError("platform_specific owner is pinned to surface/experiment")
        if self.note != PS4_SCOPE_NOTE:
            raise ValueError("platform_specific scope note is pinned")
        return self


class UnixPrivescReport(Observation):
    """Classified report for one hash-bound collector document.

    Strict and self-consistent: every declared category appears exactly once,
    per-category statuses must agree with the detected platform, and an
    ``unknown`` platform forces ``platform_interpretation='refused'``.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_id: NonEmptyStr = Field(alias="schema")
    source: DocumentBinding
    platform: TargetPlatform
    platform_hint: str
    platform_interpretation: PlatformInterpretation
    platform_note: NonEmptyStr
    categories: list[CategoryReport]
    platform_specific: PlatformSpecificFindings

    @model_validator(mode="after")
    def _contract(self) -> "UnixPrivescReport":
        if self.schema_id != SCHEMA_ID:
            raise ValueError(f"unsupported report schema: {self.schema_id!r}")
        seen = [item.category for item in self.categories]
        if len(seen) != len(set(seen)) or set(seen) != set(Category):
            raise ValueError("report must carry every declared category exactly once")
        for item in self.categories:
            expected = classification_status(self.platform, item.platform_semantics)
            if item.status is not expected:
                raise ValueError(
                    f"category {item.category.value!r}: status {item.status.value!r} "
                    f"contradicts platform {self.platform.value!r} "
                    f"(expected {expected.value!r})")
            if item.status is CategoryStatus.INAPPLICABLE and item.entries:
                raise ValueError(
                    f"inapplicable category {item.category.value!r} must not carry entries")
        refused = self.platform_interpretation is PlatformInterpretation.REFUSED
        if refused != (self.platform is TargetPlatform.UNKNOWN):
            raise ValueError(
                "platform_interpretation must be 'refused' iff the platform is unknown")
        if self.platform is TargetPlatform.LINUX and self.platform_specific.findings:
            raise ValueError(
                "platform_specific findings cannot originate from a linux target")
        expected_bucket = (PlatformSpecificStatus.REFUSED
                           if self.platform is TargetPlatform.UNKNOWN
                           else PlatformSpecificStatus.DEFERRED)
        if self.platform_specific.status is not expected_bucket:
            raise ValueError("platform_specific bucket status contradicts the target platform")
        return self
