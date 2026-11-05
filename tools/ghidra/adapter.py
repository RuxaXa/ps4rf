"""Ghidra headless adapter (P3): function list, decompile, xrefs, hashing.

Boundaries (consistent with the adapter rules of the handoff):

* Static analysis only. The adapter drives a headless CLI, reads its JSON export
  and never executes, loads or patches the analyzed artifact.
* Offline-first: the default ``headless_cmd`` is the loopback mock
  (``tools/ghidra/mock/headless_mock.py``); no network, no Java, no real Ghidra
  is required for any test. A real Ghidra installation only changes the command.
* Every run is hash-bound: artifact SHA-256, postscript SHA-256 and export
  SHA-256 are recorded and re-checkable (:func:`verify_run_record`). Hash
  mismatches refuse *before* a run starts (expected hashes) and after it
  completes (export cross-checks).
* No shell: ``headless_cmd`` must be an argv list; no firmware addresses/RVAs
  ever live in this module -- address handling stays opaque and profile-bound
  work remains in PS4RF's profile domain.
* Single attempt per invocation, no retries; a timeout kills the process.

Export contract: ``ps4rf.ghidra.export/v1`` (see tools/ghidra/README.md).
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated, Never, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, model_validator

from core.models.common import Sha256, StrictModel

SCHEMA_ID = "ps4rf.ghidra.export/v1"
EXPORT_SCRIPT = "ps4rf_ghidra_export.py"
_HEX = re.compile(r"^0x[0-9a-f]{1,16}$")
HexStr = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{1,16}$")]


class GhidraError(Exception):
    """Base class for adapter failures."""


class GhidraConfigError(GhidraError):
    """Invalid configuration or arguments."""


class GhidraRunError(GhidraError):
    """Headless run failed (non-zero exit, missing export)."""

    def __init__(self, exit_code: int, detail: str) -> None:
        self.exit_code, self.detail = exit_code, detail
        super().__init__(f"headless run failed (exit {exit_code}): {detail}")


class GhidraTimeout(GhidraError):
    """Headless run exceeded the configured timeout (process killed)."""


class GhidraHashMismatch(GhidraError):
    """Artifact/script/export hash does not match the expected or recorded value."""


class GhidraEvidenceError(GhidraError):
    """A recorded run does not re-verify (hash, counts, content)."""


class GhidraSchemaError(GhidraError):
    """Export document violates the ``ps4rf.ghidra.export/v1`` contract."""


class GhidraStateError(GhidraError):
    """Result accessors used before :meth:`GhidraAdapter.analyze` ran."""


class GhidraNotFound(GhidraError):
    """Requested function/address is not part of the current analysis."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class XrefType(str, Enum):
    CALL = "CALL"
    JUMP = "JUMP"
    DATA = "DATA"
    OTHER = "OTHER"


class GhidraFunction(_Model):
    name: Annotated[str, StringConstraints(min_length=1)]
    entry: HexStr
    size: int = Field(ge=0)
    body_sha256: Sha256


class GhidraXref(_Model):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    from_addr: HexStr = Field(alias="from")
    to_addr: HexStr = Field(alias="to")
    type: XrefType


class GhidraDecompilation(_Model):
    function: Annotated[str, StringConstraints(min_length=1)]
    entry: HexStr
    text: Annotated[str, StringConstraints(min_length=1)]
    text_sha256: Sha256

    @model_validator(mode="after")
    def _text_binding(self) -> "GhidraDecompilation":
        digest = hashlib.sha256(self.text.encode("utf-8")).hexdigest()
        if digest != self.text_sha256:
            raise ValueError("decompilation text_sha256 does not match text")
        return self


class GhidraProgram(_Model):
    name: Annotated[str, StringConstraints(min_length=1)]
    language: Annotated[str, StringConstraints(min_length=1)]
    image_base: HexStr


class GhidraArtifact(_Model):
    sha256: Sha256


class GhidraGenerator(_Model):
    tool: Annotated[str, StringConstraints(min_length=1)]
    version: Annotated[str, StringConstraints(min_length=1)]
    script: Annotated[str, StringConstraints(min_length=1)]
    script_sha256: Sha256


class GhidraExport(_Model):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_id: str = Field(alias="schema")
    artifact: GhidraArtifact
    program: GhidraProgram
    functions: list[GhidraFunction]
    xrefs: list[GhidraXref]
    decompilations: list[GhidraDecompilation]
    generator: GhidraGenerator

    @model_validator(mode="after")
    def _contract(self) -> "GhidraExport":
        if self.schema_id != SCHEMA_ID:
            raise ValueError(f"unsupported export schema: {self.schema_id!r}")
        names = [f.name for f in self.functions]
        if len(names) != len(set(names)):
            raise ValueError("duplicate function names in export")
        entries = [f.entry for f in self.functions]
        if len(entries) != len(set(entries)):
            raise ValueError("duplicate function entries in export")
        return self


class GhidraRunRecord(StrictModel):
    """Evidence record of one headless analysis run (hash-bound)."""

    artifact_path: str
    artifact_sha256: Sha256
    headless_version: str
    script_name: str
    script_sha256: Sha256
    cmd: list[str]
    started_at: datetime
    ended_at: datetime
    export_path: str
    export_sha256: Sha256
    functions_count: int
    xrefs_count: int
    decompilations_count: int


class GhidraAnalysis(StrictModel):
    export: GhidraExport
    run: GhidraRunRecord


class GhidraConfig(StrictModel):
    """Headless configuration. ``headless_cmd`` is an argv list -- never a shell."""

    headless_cmd: list[str] = Field(
        default_factory=lambda: [sys.executable, "-m", "tools.ghidra.mock.headless_mock"])
    project_dir: str
    project_name: str = "ps4rf"
    script_dir: str = Field(default_factory=lambda: str(Path(__file__).resolve().parent / "scripts"))
    timeout_s: float = Field(default=120.0, gt=0)

    @model_validator(mode="after")
    def _argv_policy(self) -> "GhidraConfig":
        if not self.headless_cmd or not all(
                isinstance(part, str) and part for part in self.headless_cmd):
            raise ValueError("headless_cmd must be a non-empty list of argv strings (no shell)")
        if not self.project_dir or not self.script_dir:
            raise ValueError("project_dir and script_dir must be set")
        return self


class GhidraAdapter:
    """Fail-closed driver for a Ghidra headless CLI. Single attempt, no retries."""

    def __init__(self, config: GhidraConfig) -> None:
        self.config = config
        self._version: Optional[str] = None
        self._last: Optional[GhidraAnalysis] = None
        self.run_log: list[dict[str, object]] = []

    # ------------------------------------------------------------------ plumbing
    def hash_artifact(self, path: str | Path) -> str:
        """SHA-256 of a file's bytes (artifact hashing, no interpretation)."""
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def _script_path(self) -> Path:
        script = Path(self.config.script_dir) / EXPORT_SCRIPT
        if not script.is_file():
            raise GhidraConfigError(f"postscript not found: {script}")
        return script

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(argv, capture_output=True, text=True,
                                  timeout=self.config.timeout_s, check=False)
        except subprocess.TimeoutExpired as exc:
            self.run_log.append({"phase": "timeout", "argv0": argv[0]})
            raise GhidraTimeout(
                f"headless run exceeded {self.config.timeout_s}s (process killed)") from exc

    # ------------------------------------------------------------------- methods
    def health(self) -> dict[str, object]:
        """Detect the headless CLI; returns tool version."""
        result = self._run([*self.config.headless_cmd, "--version"])
        if result.returncode != 0:
            raise GhidraRunError(result.returncode, result.stderr.strip()[:500])
        line = (result.stdout.strip().splitlines() or [""])[0]
        parts = line.split()
        version = parts[1] if len(parts) > 1 else line
        self._version = version
        return {"reachable": True, "version": version,
                "cmd": list(self.config.headless_cmd)}

    def analyze(self, artifact_path: str | Path, *, output_path: str | Path | None = None,
                expected_artifact_sha256: Optional[str] = None,
                expected_script_sha256: Optional[str] = None) -> GhidraAnalysis:
        """Run one headless analysis and return the parsed, hash-bound export.

        Expected hashes refuse *before* any process starts (fail closed).
        """
        artifact = Path(artifact_path)
        if not artifact.is_file():
            raise GhidraConfigError(f"artifact not found: {artifact}")
        digest = self.hash_artifact(artifact)
        if expected_artifact_sha256 is not None and digest != expected_artifact_sha256:
            raise GhidraHashMismatch(
                f"artifact {digest} != expected {expected_artifact_sha256} (refused before run)")
        script = self._script_path()
        script_digest = self.hash_artifact(script)
        if expected_script_sha256 is not None and script_digest != expected_script_sha256:
            raise GhidraHashMismatch(
                f"postscript {script_digest} != expected {expected_script_sha256} (refused before run)")
        if self._version is None:
            self.health()
        export_path = (Path(output_path) if output_path is not None
                       else Path(self.config.project_dir) / "exports" / f"{digest[:8]}-export.json")
        argv = [*self.config.headless_cmd, self.config.project_dir, self.config.project_name,
                "-import", str(artifact), "-scriptPath", str(script.parent),
                "-postScript", script.name, str(export_path), "-deleteProject"]
        started = datetime.now(timezone.utc)
        result = self._run(argv)
        ended = datetime.now(timezone.utc)
        if result.returncode != 0:
            raise GhidraRunError(result.returncode, result.stderr.strip()[:500])
        if not export_path.is_file():
            raise GhidraRunError(0, f"headless exited 0 but wrote no export at {export_path}")
        raw = export_path.read_bytes()
        export_digest = hashlib.sha256(raw).hexdigest()
        try:
            export = GhidraExport.model_validate(json.loads(raw.decode("utf-8")))
        except (json.JSONDecodeError, ValidationError) as exc:
            raise GhidraSchemaError(f"export does not satisfy {SCHEMA_ID}: {exc}") from exc
        if export.artifact.sha256 != digest:
            raise GhidraHashMismatch(
                "export artifact hash does not match the analyzed artifact")
        if export.generator.script_sha256 != script_digest:
            raise GhidraHashMismatch(
                "export postscript hash does not match the local postscript (drift)")
        run = GhidraRunRecord(
            artifact_path=str(artifact), artifact_sha256=digest,
            headless_version=self._version or "unknown", script_name=script.name,
            script_sha256=script_digest, cmd=argv, started_at=started, ended_at=ended,
            export_path=str(export_path), export_sha256=export_digest,
            functions_count=len(export.functions), xrefs_count=len(export.xrefs),
            decompilations_count=len(export.decompilations))
        analysis = GhidraAnalysis(export=export, run=run)
        self._last = analysis
        self.run_log.append({"artifact_sha256": digest, "export_sha256": export_digest,
                             "exit": result.returncode})
        return analysis

    def list_functions(self) -> list[GhidraFunction]:
        """Functions of the current analysis (headless order)."""
        analysis = self._require_analysis()
        return list(analysis.export.functions)

    def decompile(self, function: str) -> GhidraDecompilation:
        """Decompilation of ``function`` (name or ``0x...`` entry)."""
        analysis = self._require_analysis()
        for item in analysis.export.decompilations:
            if function in (item.function, item.entry):
                digest = hashlib.sha256(item.text.encode("utf-8")).hexdigest()
                if digest != item.text_sha256:
                    raise GhidraEvidenceError(
                        f"decompilation for {function!r} failed its content hash")
                return item
        raise GhidraNotFound(f"no decompilation for {function!r} in the current analysis")

    def xrefs(self, target: str, direction: str = "to") -> list[GhidraXref]:
        """Cross references touching ``target``; ``direction`` in {to, from}."""
        analysis = self._require_analysis()
        if not _HEX.match(target):
            raise GhidraConfigError(f"target must be a 0x-prefixed hex address: {target!r}")
        if direction not in ("to", "from"):
            raise GhidraConfigError("direction must be 'to' or 'from'")
        attribute = "to_addr" if direction == "to" else "from_addr"
        return [x for x in analysis.export.xrefs if getattr(x, attribute) == target]

    def _require_analysis(self) -> GhidraAnalysis:
        if self._last is None:
            raise GhidraStateError("no analysis yet -- call analyze() first")
        return self._last


def verify_run_record(record: GhidraRunRecord) -> bool:
    """Re-verify artifact hash, export hash, schema, counts and cross-links.

    Raises :class:`GhidraEvidenceError` on any mismatch, returns True otherwise.
    """
    def fail(message: str) -> Never:
        raise GhidraEvidenceError(message)

    artifact = Path(record.artifact_path)
    if not artifact.is_file():
        fail(f"artifact missing: {artifact}")
    actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if actual != record.artifact_sha256:
        fail(f"artifact hash mismatch: {actual} != {record.artifact_sha256}")
    export_path = Path(record.export_path)
    if not export_path.is_file():
        fail(f"export missing: {export_path}")
    raw = export_path.read_bytes()
    actual_export = hashlib.sha256(raw).hexdigest()
    if actual_export != record.export_sha256:
        fail(f"export hash mismatch: {actual_export} != {record.export_sha256}")
    try:
        export = GhidraExport.model_validate(json.loads(raw.decode("utf-8")))
    except (json.JSONDecodeError, ValidationError) as exc:
        fail(f"export failed re-validation: {exc}")
    if export.artifact.sha256 != record.artifact_sha256:
        fail("export artifact hash does not match the record")
    if export.generator.script_sha256 != record.script_sha256:
        fail("export postscript hash does not match the record")
    if not (len(export.functions) == record.functions_count
            and len(export.xrefs) == record.xrefs_count
            and len(export.decompilations) == record.decompilations_count):
        fail("export counts do not match the record")
    return True
