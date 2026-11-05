"""Offline parser for linPEAS-style scan output (P4 recon).

Pure text processing: the parser never executes, contacts or interprets the
scanned system; it only restructures lines of a scan report that was captured
off-system (or emitted by the offline mock). Boundaries:

* Target OS is detected from report content (provenance header plus the System
  Information section). Ambiguity or absence fails closed to ``UNKNOWN``. Only
  LINUX targets can be compatible; the verdict is derived here via
  :func:`~tools.recon.peass.models.compatibility_for` and re-checked by the
  models.
* Every parsed entry line becomes one :class:`PeassFinding` -- an OBSERVATION
  that requires verification, never a vulnerability.
* Unrecognized sections and stray lines are skipped; a scan without any
  recognized finding is refused (:class:`PeassSchemaError`), so an unsupported
  format fails closed instead of yielding a hollow "clean" report.
* Credential handling: every entry line passes through
  :func:`redact_secret_values`, which replaces the value after credential
  keywords (``password=...``, ``token: ...``, ...) with ``[value withheld]``
  before it can reach any model. Presence is reported; secret values never are.

Format assumption (v0.1, see tools/recon/peass/README.md): linPEAS-style section
headers ``╔══════════╣ <title>`` (optionally followed by ``╚ ... ╝``) and entry
lines ``╚ <text>``. Real linPEAS captures will be reconciled with the first
real sample; unparsed lines are skipped, never guessed at.
"""

from __future__ import annotations

import re
from typing import Optional

from tools.recon.peass.models import (FindingCategory, PeassFinding, PeassReport,
                                      PeassScannerInfo, PeassSchemaError,
                                      PeassTargetInfo, PeassTargetOS,
                                      compatibility_for)

_SECTION_RE = re.compile(r"^╔═+╣\s*(?P<title>[^╚]+?)\s*(?:╚.*╝)?\s*$")
_ENTRY_RE = re.compile(r"^╚\s+(?P<text>.+?)\s*$")
_SCANNER_RE = re.compile(r"^#\s*scanner\s*:\s*(?P<rest>.+?)\s*$", re.IGNORECASE)
_SYNTHETIC_RE = re.compile(r"^#\s*synthetic\s*:\s*(?P<value>\S+)\s*$", re.IGNORECASE)

_SECRET_VALUE_RE = re.compile(
    r"(?i)(\b(?:pass(?:word|wd)?|passphrase|secret|token|api[_-]?key|credential)s?"
    r"\s*[:=]\s*)(\S+)")

#: Marker substituted for any secret value found in an entry line.
VALUE_WITHHELD = "[value withheld]"

#: Section title (normalized) -> finding category. Unknown titles are skipped.
_SECTION_CATEGORIES: dict[str, FindingCategory] = {
    "system information": FindingCategory.KERNEL_OS,
    "filesystem": FindingCategory.FILESYSTEM,
    "mounts": FindingCategory.MOUNTS,
    "permissions": FindingCategory.PERMISSIONS,
    "suid-sgid binaries": FindingCategory.SUID_SGID,
    "linux capabilities": FindingCategory.CAPABILITIES,
    "services": FindingCategory.SERVICES,
    "cron jobs": FindingCategory.CRON,
    "active sockets": FindingCategory.SOCKETS,
    "credentials search": FindingCategory.CREDENTIALS,
    "interesting binaries": FindingCategory.INTERESTING_BINARIES,
    "container-vm indicators": FindingCategory.ENVIRONMENT,
}

_FREEBSD_MARKERS = re.compile(r"(?i)\b(?:freebsd|orbis(?:os)?|playstation|ps4)\b")
_LINUX_MARKERS = re.compile(r"(?i)\blinux\b")


def _normalize(title: str) -> str:
    return " ".join(title.lower().split())


def redact_secret_values(text: str) -> str:
    """Replace values after credential keywords with ``[value withheld]``.

    Best effort by design: the property pinned by tests is that a value passed
    in a ``keyword: value`` / ``keyword=value`` form never appears in adapter
    output.
    """
    return _SECRET_VALUE_RE.sub(r"\1[value withheld]", text)


def _system_window(text: str) -> tuple[list[str], list[str]]:
    """Provenance/header lines plus System Information entries of the scan."""
    header_lines: list[str] = []
    entries: list[str] = []
    in_system = False
    for line in text.splitlines():
        if line.startswith("#"):
            header_lines.append(line)
            continue
        header = _SECTION_RE.match(line)
        if header:
            in_system = _normalize(header.group("title")) == "system information"
            continue
        if in_system:
            entry = _ENTRY_RE.match(line)
            if entry:
                entries.append(entry.group("text"))
    return header_lines, entries


def detect_target_os(text: str) -> PeassTargetOS:
    """Detect the target OS from report content; ambiguous or absent -> UNKNOWN."""
    header_lines, entries = _system_window(text)
    blob = "\n".join([*header_lines, *entries])
    freebsd_hit = bool(_FREEBSD_MARKERS.search(blob))
    linux_hit = bool(_LINUX_MARKERS.search(blob))
    if freebsd_hit and not linux_hit:
        return PeassTargetOS.FREEBSD_ORBISOS
    if linux_hit and not freebsd_hit:
        return PeassTargetOS.LINUX
    return PeassTargetOS.UNKNOWN


def _scanner_info(text: str) -> PeassScannerInfo:
    tool, version, synthetic = "linPEAS", "unknown", False
    for line in text.splitlines():
        if not line.startswith("#"):
            continue
        match = _SCANNER_RE.match(line)
        if match:
            parts = match.group("rest").split()
            tool = parts[0] if parts else tool
            if len(parts) > 1:
                version = " ".join(parts[1:])
        match = _SYNTHETIC_RE.match(line)
        if match and match.group("value").lower() in ("true", "yes", "1"):
            synthetic = True
    return PeassScannerInfo(tool=tool, version=version, synthetic=synthetic)


def _extract(entries: list[str], *patterns: str) -> Optional[str]:
    for entry in entries:
        for pattern in patterns:
            match = re.match(pattern, entry, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                if value:
                    return value
    return None


def _target_info(text: str, target_os: PeassTargetOS) -> PeassTargetInfo:
    _, entries = _system_window(text)
    return PeassTargetInfo(
        hostname=_extract(entries, r"hostname\s*:\s*(.+)") or "unknown",
        os=target_os,
        kernel=_extract(entries, r"uname -a\s*:\s*(.+)", r"kernel\s*:\s*(.+)"),
        release=_extract(entries, r"/etc/os-release\s*:\s*(.+)",
                         r"os-release\s*:\s*(.+)", r"release\s*:\s*(.+)"))


def parse_scan(text: str, scan_sha256: str) -> PeassReport:
    """Parse linPEAS-style scan output into a hash-bound report.

    Raises :class:`PeassSchemaError` when the scan is empty or contains no
    recognized findings (fail closed).
    """
    if not text.strip():
        raise PeassSchemaError("scan output is empty")
    target_os = detect_target_os(text)
    findings: list[PeassFinding] = []
    category: Optional[FindingCategory] = None
    for lineno, line in enumerate(text.splitlines(), start=1):
        header = _SECTION_RE.match(line)
        if header:
            category = _SECTION_CATEGORIES.get(_normalize(header.group("title")))
            continue
        entry = _ENTRY_RE.match(line)
        if entry is None or category is None:
            continue
        findings.append(PeassFinding(
            category=category, line=lineno,
            text=redact_secret_values(entry.group("text"))))
    if not findings:
        raise PeassSchemaError(
            "no recognized linPEAS-style sections with findings in scan output")
    return PeassReport(
        scan_sha256=scan_sha256,
        scanner=_scanner_info(text),
        target=_target_info(text, target_os),
        compatibility=compatibility_for(target_os),
        findings=findings)


__all__ = ["VALUE_WITHHELD", "detect_target_os", "parse_scan", "redact_secret_values"]
