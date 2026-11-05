"""PEASS-ng / linPEAS adapter (P4 recon): offline ingestion of scan results.

Boundaries (consistent with the adapter rules of the handoff; same pattern as
``tools/ghidra/adapter.py`` and ``tools/aflplusplus/adapter.py``):

* No target contact, ever: the adapter never executes or connects to a scanned
  system. Real scans are produced by the operator on the target; this module
  ingests their output. The only scanner it drives is the offline mock
  (``tools/recon/peass/mock/linpeas_mock.py``), which emits synthetic reports.
* Offline-first: the default ``scanner_cmd`` is the loopback mock; no network,
  no PEASS-ng installation is required for any test. A real installation only
  changes ``scanner_cmd`` (and ``scanner_artifact`` for the hash pre-check).
* Hash-bound: the scan output is the pinned input. An expected scanner-artifact
  hash mismatch refuses *before* any run; an expected scan hash mismatch on
  ingest refuses *before* any parsing; after a run the produced scan is
  cross-checked against the expected hash, and the canonical analysis document
  is recorded by hash. :func:`verify_run_record` re-reads, re-parses, recounts
  and re-renders everything.
* PS4/OrbisOS: linPEAS is not a generic PS4 scanner. The report carries a
  compatibility verdict that is True only for LINUX targets; FREEBSD_ORBISOS
  (PS4/OrbisOS) and UNKNOWN targets are never compatible (fail closed).
* Output classification: every finding is an OBSERVATION with
  ``requires_verification=True``; adapter output can never be classified as a
  vulnerability (enforced by the models, pinned by tests).
* Single attempt per invocation, no retries; a timeout kills the process;
  everything is an argv list -- a shell is never used.
"""

from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Never, Optional

from pydantic import ValidationError

from tools.recon.peass.models import (SCANNER_CMD_NOT_RECORDED, PeassAnalysis,
                                      PeassConfig, PeassConfigError,
                                      PeassEvidenceError, PeassHashMismatch,
                                      PeassReport, PeassRunError, PeassRunRecord,
                                      PeassScanTarget, PeassSchemaError,
                                      PeassTimeout, dump_canonical)
from tools.recon.peass.parser import parse_scan


class PeassAdapter:
    """Fail-closed driver for the PEASS/linPEAS surface. Single attempt, no retries."""

    def __init__(self, config: PeassConfig) -> None:
        self.config = config
        self._version: Optional[str] = None
        self.runs: list[PeassRunRecord] = []

    # ------------------------------------------------------------------ plumbing
    def hash_file(self, path: str | Path) -> str:
        """SHA-256 of a file's bytes (scan hashing, no interpretation)."""
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(argv, capture_output=True, text=True,
                                  timeout=self.config.timeout_s, check=False)
        except subprocess.TimeoutExpired as exc:
            raise PeassTimeout(
                f"scanner run exceeded {self.config.timeout_s}s (process killed)") from exc

    @staticmethod
    def _read_scan(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise PeassSchemaError(f"scan output is not valid UTF-8: {exc}") from exc

    @staticmethod
    def _assert_expected_scan_hash(digest: str, expected: Optional[str],
                                   *, phase: str) -> None:
        if expected is not None and digest != expected:
            raise PeassHashMismatch(
                f"scan output {digest} != expected {expected} (refused {phase})")

    # ------------------------------------------------------------------- methods
    def health(self) -> dict[str, object]:
        """Detect the scanner CLI; returns tool version."""
        result = self._run([*self.config.scanner_cmd, "--version"])
        if result.returncode != 0:
            raise PeassRunError(result.returncode, result.stderr.strip()[:500])
        line = (result.stdout.strip().splitlines() or [""])[0]
        parts = line.split()
        version = parts[1] if len(parts) > 1 else line
        self._version = version
        return {"reachable": True, "version": version,
                "cmd": list(self.config.scanner_cmd)}

    def scan(self, target: PeassScanTarget | str, *, scan_path: Optional[str | Path] = None,
             analysis_path: Optional[str | Path] = None,
             expected_scanner_sha256: Optional[str] = None,
             expected_scan_sha256: Optional[str] = None) -> PeassAnalysis:
        """Run one scan against the offline mock profile and parse its output.

        The scanner is invoked exactly once. ``expected_scanner_sha256`` pins
        the local scanner artifact and refuses *before* any run; the produced
        scan must match ``expected_scan_sha256`` when given (drift refusal,
        single attempt already spent).
        """
        try:
            profile = PeassScanTarget(target)
        except ValueError as exc:
            raise PeassConfigError(f"unknown scan target: {target!r}") from exc
        if expected_scanner_sha256 is not None:
            artifact = Path(self.config.scanner_artifact)
            if not artifact.is_file():
                raise PeassConfigError(f"scanner artifact not found: {artifact}")
            digest = self.hash_file(artifact)
            if digest != expected_scanner_sha256:
                raise PeassHashMismatch(
                    f"scanner artifact {digest} != expected {expected_scanner_sha256} "
                    "(refused before any run)")
        if self._version is None:
            self.health()
        out = Path(scan_path) if scan_path is not None else (
            Path(self.config.work_dir) / "scans" / f"{profile.value}-scan.txt")
        out.parent.mkdir(parents=True, exist_ok=True)
        argv = [*self.config.scanner_cmd, "--target", profile.value, "--output", str(out)]
        started = datetime.now(timezone.utc)
        result = self._run(argv)
        if result.returncode != 0:
            raise PeassRunError(result.returncode, result.stderr.strip()[:500])
        if not out.is_file():
            raise PeassRunError(0, f"scanner exited 0 but wrote no scan at {out}")
        digest = self.hash_file(out)
        self._assert_expected_scan_hash(digest, expected_scan_sha256, phase="after run")
        return self._assemble(mode="scan", scan=out, scan_sha256=digest,
                              text=self._read_scan(out), scanner_cmd=argv,
                              started=started, scanner_version=self._version,
                              analysis_path=analysis_path)

    def ingest(self, scan_path: str | Path, *, analysis_path: Optional[str | Path] = None,
               expected_scan_sha256: Optional[str] = None,
               scanner_cmd: Optional[list[str]] = None) -> PeassAnalysis:
        """Parse an existing scan output file (the real-world entry point).

        The scan is sha256-pinned: an expected-hash mismatch refuses *before any
        parsing* (fail closed). ``scanner_cmd`` records how the scan was
        produced when known; otherwise the sentinel
        ``<scanner-command-not-recorded>`` is recorded instead of inventing one.
        """
        scan = Path(scan_path)
        if not scan.is_file():
            raise PeassConfigError(f"scan output not found: {scan}")
        started = datetime.now(timezone.utc)
        digest = self.hash_file(scan)
        self._assert_expected_scan_hash(digest, expected_scan_sha256,
                                        phase="before any parse")
        if scanner_cmd is not None and (not scanner_cmd or not all(
                isinstance(part, str) and part for part in scanner_cmd)):
            raise PeassConfigError("scanner_cmd must be a non-empty list of argv strings")
        command = list(scanner_cmd) if scanner_cmd is not None else [SCANNER_CMD_NOT_RECORDED]
        return self._assemble(mode="ingest", scan=scan, scan_sha256=digest,
                              text=self._read_scan(scan), scanner_cmd=command,
                              started=started, scanner_version=None,
                              analysis_path=analysis_path)

    def _assemble(self, *, mode: Literal["scan", "ingest"], scan: Path, scan_sha256: str,
                  text: str, scanner_cmd: list[str], started: datetime,
                  scanner_version: Optional[str],
                  analysis_path: Optional[str | Path]) -> PeassAnalysis:
        report = parse_scan(text, scan_sha256)
        document = Path(analysis_path) if analysis_path is not None else (
            Path(self.config.work_dir) / "analyses" / f"{scan_sha256[:8]}-analysis.json")
        document.parent.mkdir(parents=True, exist_ok=True)
        document.write_text(dump_canonical(report), encoding="utf-8")
        ended = datetime.now(timezone.utc)
        counts: dict[str, int] = {}
        for finding in report.findings:
            counts[finding.category.value] = counts.get(finding.category.value, 0) + 1
        counts = dict(sorted(counts.items()))
        run = PeassRunRecord(
            mode=mode, scanner_cmd=list(scanner_cmd), scanner_tool=report.scanner.tool,
            scanner_version=scanner_version or report.scanner.version,
            scan_path=str(scan), scan_sha256=scan_sha256,
            report_path=str(document), report_sha256=self.hash_file(document),
            started_at=started, ended_at=ended, findings_count=len(report.findings),
            categories_count=len(counts), category_counts=counts)
        analysis = PeassAnalysis(report=report, run=run)
        self.runs.append(run)
        return analysis


def verify_run_record(record: PeassRunRecord) -> bool:
    """Re-verify a recorded run: scan hash, re-parse, counts and document.

    Raises :class:`PeassEvidenceError` on any mismatch, returns ``True``
    otherwise.
    """

    def fail(message: str) -> Never:
        raise PeassEvidenceError(message)

    scan = Path(record.scan_path)
    if not scan.is_file():
        fail(f"scan output missing: {scan}")
    digest = hashlib.sha256(scan.read_bytes()).hexdigest()
    if digest != record.scan_sha256:
        fail(f"scan hash mismatch: {digest} != {record.scan_sha256}")
    try:
        text = scan.read_text(encoding="utf-8")
        report = parse_scan(text, digest)
    except (PeassSchemaError, UnicodeDecodeError) as exc:
        fail(f"scan failed re-parsing: {exc}")
    counts: dict[str, int] = {}
    for finding in report.findings:
        counts[finding.category.value] = counts.get(finding.category.value, 0) + 1
    counts = dict(sorted(counts.items()))
    if (len(report.findings) != record.findings_count
            or counts != record.category_counts
            or len(counts) != record.categories_count):
        fail("re-parsed scan counts do not match the record")
    if report.scan_sha256 != record.scan_sha256:
        fail("re-parsed report is not bound to the recorded scan hash")
    document = Path(record.report_path)
    if not document.is_file():
        fail(f"analysis document missing: {document}")
    raw = document.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != record.report_sha256:
        fail(f"analysis document hash mismatch: {actual} != {record.report_sha256}")
    try:
        rendered = raw.decode("utf-8")
        parsed = PeassReport.model_validate_json(raw)
    except (UnicodeDecodeError, ValidationError) as exc:
        fail(f"analysis document failed re-validation: {exc}")
    if rendered != dump_canonical(report):
        fail("analysis document is not the canonical rendering of the scan")
    if parsed.scan_sha256 != record.scan_sha256:
        fail("analysis document is not bound to the recorded scan hash")
    if len(parsed.findings) != record.findings_count:
        fail("analysis document counts do not match the record")
    return True


__all__ = ["PeassAdapter", "verify_run_record"]
