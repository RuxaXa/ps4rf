"""PEASS-ng / linPEAS adapter models (P4 recon).

Data-model contract for parsing off-system linPEAS-style scan output. The rules
below are enforced by field types and validators -- and pinned by tests:

* Every finding is an OBSERVATION with ``requires_verification=True``. The
  adapter output can never be classified as a vulnerability: the field types
  (``Literal``) reject any other value at validation time, and the report
  validator re-checks it.
* A report may be marked ``compatible`` ONLY for LINUX targets; the verdict is
  derived from the detected target OS and cross-checked, so it cannot be
  hand-rolled. FREEBSD_ORBISOS (PS4/OrbisOS) and UNKNOWN targets are never
  compatible (fail closed).
* Credential findings carry presence information only; the parser replaces any
  value after a credential keyword with a fixed marker before it can reach the
  model (never copy secrets).

``dump_canonical`` renders the deterministic analysis document: sorted keys, no
timestamps, LF newlines, exactly one trailing newline.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Annotated, Literal, Optional

from pydantic import Field, StringConstraints, model_validator

from core.models.common import Sha256, StrictModel

#: The only classification the adapter may ever emit for a finding.
OBSERVATION = "OBSERVATION"

#: Module path / artifact of the default (and only built-in) scanner: the offline mock.
MOCK_MODULE = "tools.recon.peass.mock.linpeas_mock"
MOCK_ARTIFACT = str(Path(__file__).resolve().parent / "mock" / "linpeas_mock.py")

#: Sentinel recorded when a scan was produced elsewhere and its command is unknown.
SCANNER_CMD_NOT_RECORDED = "<scanner-command-not-recorded>"

#: Canonical compatibility reasons (the report validator enforces these exactly).
LINUX_REASON = (
    "target detected as Linux: linPEAS assumptions apply, but every finding "
    "remains an observation that requires verification.")
UNSUPPORTED_REASON = (
    "linPEAS assumptions do not apply to PS4/OrbisOS (FreeBSD-derived console "
    "target): linPEAS output about it is not evidence about OrbisOS, and "
    "PS4-specific checks must be implemented natively later via PS4RF "
    "surface/experiment modules.")
UNKNOWN_REASON = (
    "target OS could not be identified from the scan content: linPEAS "
    "assumptions cannot be applied; failing closed until the target OS is known.")


class PeassError(Exception):
    """Base class for adapter failures."""


class PeassConfigError(PeassError):
    """Invalid configuration or arguments."""


class PeassRunError(PeassError):
    """Scanner invocation failed (non-zero exit, missing output)."""

    def __init__(self, exit_code: int, detail: str) -> None:
        self.exit_code, self.detail = exit_code, detail
        super().__init__(f"scanner run failed (exit {exit_code}): {detail}")


class PeassTimeout(PeassError):
    """Scanner invocation exceeded the configured timeout (process killed)."""


class PeassHashMismatch(PeassError):
    """Scan output or scanner artifact hash does not match the pinned expectation."""


class PeassEvidenceError(PeassError):
    """A recorded run does not re-verify (hash, model, counts, document bytes)."""


class PeassSchemaError(PeassError):
    """Scan output cannot be parsed into the PEASS report contract."""


class PeassScanTarget(str, Enum):
    """Requested target profile for the offline mock scanner."""

    LINUX = "linux"
    ORBISOS = "orbisos"


class PeassTargetOS(str, Enum):
    """Target OS class detected from scan content (fail closed to UNKNOWN)."""

    LINUX = "LINUX"
    FREEBSD_ORBISOS = "FREEBSD_ORBISOS"
    UNKNOWN = "UNKNOWN"


class FindingCategory(str, Enum):
    """Enumeration areas covered by the parsed report."""

    FILESYSTEM = "filesystem"
    PERMISSIONS = "permissions"
    SUID_SGID = "suid_sgid"
    CAPABILITIES = "capabilities"
    SERVICES = "services"
    CRON = "cron"
    SOCKETS = "sockets"
    CREDENTIALS = "credentials"
    MOUNTS = "mounts"
    KERNEL_OS = "kernel_os"
    INTERESTING_BINARIES = "interesting_binaries"
    ENVIRONMENT = "environment"


class PeassFinding(StrictModel):
    """One observed entry line of a scan section.

    Never a vulnerability claim: ``classification`` is fixed to OBSERVATION and
    ``requires_verification`` is fixed to ``True`` -- any other value is
    rejected at validation time.
    """

    category: FindingCategory
    line: int = Field(ge=1)
    text: Annotated[str, StringConstraints(min_length=1)]
    classification: Literal["OBSERVATION"] = "OBSERVATION"
    requires_verification: Literal[True] = True

    @model_validator(mode="after")
    def _observation_only(self) -> "PeassFinding":
        if self.classification != OBSERVATION or self.requires_verification is not True:
            raise ValueError(
                "adapter findings are OBSERVATION with requires_verification=True; "
                "vulnerability classification is not representable")
        return self


class PeassTargetInfo(StrictModel):
    """Target identity as observed in the scan's System Information section."""

    hostname: Annotated[str, StringConstraints(min_length=1)]
    os: PeassTargetOS
    kernel: Optional[Annotated[str, StringConstraints(min_length=1)]] = None
    release: Optional[Annotated[str, StringConstraints(min_length=1)]] = None


class PeassCompatibility(StrictModel):
    """Compatibility verdict for the detected target OS."""

    compatible: bool
    reason: Annotated[str, StringConstraints(min_length=1)]


class PeassScannerInfo(StrictModel):
    """Scanner provenance declared by the report (tool/version, synthetic flag)."""

    tool: Annotated[str, StringConstraints(min_length=1)]
    version: Annotated[str, StringConstraints(min_length=1)]
    synthetic: bool


def compatibility_for(target_os: PeassTargetOS) -> PeassCompatibility:
    """Canonical verdict per target OS: True only for LINUX, everything else fails closed."""
    return PeassCompatibility(
        compatible=target_os is PeassTargetOS.LINUX,
        reason={
            PeassTargetOS.LINUX: LINUX_REASON,
            PeassTargetOS.FREEBSD_ORBISOS: UNSUPPORTED_REASON,
            PeassTargetOS.UNKNOWN: UNKNOWN_REASON,
        }[target_os])


class PeassReport(StrictModel):
    """Parsed scan report, bound to the sha256 of the exact scan bytes it came from."""

    scan_sha256: Sha256
    scanner: PeassScannerInfo
    target: PeassTargetInfo
    compatibility: PeassCompatibility
    findings: list[PeassFinding] = Field(min_length=1)

    @model_validator(mode="after")
    def _compatibility_is_derived(self) -> "PeassReport":
        expected = compatibility_for(self.target.os)
        if (self.compatibility.compatible, self.compatibility.reason) != (
                expected.compatible, expected.reason):
            raise ValueError(
                f"compatibility must be the canonical verdict for target os "
                f"{self.target.os.value}; it cannot be hand-rolled")
        return self

    @model_validator(mode="after")
    def _findings_are_ordered(self) -> "PeassReport":
        lines = [finding.line for finding in self.findings]
        if lines != sorted(set(lines)):
            raise ValueError("findings must be unique and ordered by line number")
        return self


class PeassRunRecord(StrictModel):
    """Evidence record of one scan analysis (hash-bound, single attempt)."""

    mode: Literal["scan", "ingest"]
    scanner_cmd: list[str] = Field(min_length=1)
    scanner_tool: Annotated[str, StringConstraints(min_length=1)]
    scanner_version: Annotated[str, StringConstraints(min_length=1)]
    scan_path: str
    scan_sha256: Sha256
    report_path: str
    report_sha256: Sha256
    started_at: datetime
    ended_at: datetime
    findings_count: int = Field(ge=1)
    categories_count: int = Field(ge=1)
    category_counts: dict[str, int]

    @model_validator(mode="after")
    def _counts_and_argv(self) -> "PeassRunRecord":
        if any(not part for part in self.scanner_cmd):
            raise ValueError("scanner_cmd entries must be non-empty strings")
        known = {category.value for category in FindingCategory}
        if not set(self.category_counts) <= known:
            raise ValueError("category_counts contains unknown categories")
        if any(count < 1 for count in self.category_counts.values()):
            raise ValueError("category_counts values must be >= 1")
        if list(self.category_counts) != sorted(self.category_counts):
            raise ValueError("category_counts keys are not sorted")
        if sum(self.category_counts.values()) != self.findings_count:
            raise ValueError("category_counts do not sum to findings_count")
        if len(self.category_counts) != self.categories_count:
            raise ValueError("categories_count does not match category_counts")
        if self.ended_at < self.started_at:
            raise ValueError("ended_at precedes started_at")
        return self


class PeassAnalysis(StrictModel):
    """One analysis: the parsed report plus its evidence record."""

    report: PeassReport
    run: PeassRunRecord


class PeassConfig(StrictModel):
    """Scanner configuration. ``scanner_cmd`` is an argv list -- never a shell."""

    scanner_cmd: list[str] = Field(
        default_factory=lambda: [sys.executable, "-m", MOCK_MODULE])
    scanner_artifact: str = MOCK_ARTIFACT
    work_dir: str
    timeout_s: float = Field(default=120.0, gt=0)

    @model_validator(mode="after")
    def _argv_policy(self) -> "PeassConfig":
        if not self.scanner_cmd or not all(
                isinstance(part, str) and part for part in self.scanner_cmd):
            raise ValueError("scanner_cmd must be a non-empty list of argv strings (no shell)")
        if not self.work_dir:
            raise ValueError("work_dir must be set")
        return self


def dump_canonical(report: PeassReport) -> str:
    """Deterministic JSON rendering of a parsed report.

    Sorted keys, no timestamps, no host-local paths; the same scan bytes always
    render the same document (pinned as a fixture).
    """
    return json.dumps(report.model_dump(mode="json"), sort_keys=True, indent=2) + "\n"


__all__ = [
    "OBSERVATION", "MOCK_MODULE", "MOCK_ARTIFACT", "SCANNER_CMD_NOT_RECORDED",
    "LINUX_REASON", "UNSUPPORTED_REASON", "UNKNOWN_REASON",
    "PeassError", "PeassConfigError", "PeassRunError", "PeassTimeout",
    "PeassHashMismatch", "PeassEvidenceError", "PeassSchemaError",
    "PeassScanTarget", "PeassTargetOS", "FindingCategory", "PeassFinding",
    "PeassTargetInfo", "PeassCompatibility", "PeassScannerInfo", "PeassReport",
    "PeassRunRecord", "PeassAnalysis", "PeassConfig", "compatibility_for",
    "dump_canonical",
]
