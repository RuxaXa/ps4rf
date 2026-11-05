"""AFL++ adapter (P3): corpus / crash / reproducer workflow — via evidence.

Boundaries (consistent with the adapter rules of the handoff):

* No fuzzing, no target execution: the adapter drives the *management* surface
  (``afl-showmap`` coverage, ``afl-cmin`` corpus minimization, ``afl-tmin``
  reproducer minimization, ``afl-collect`` crash triage) plus a version probe.
  ``afl-fuzz`` is never launched as a fuzzer here.
* Offline-first: every tool command defaults to the mock
  (``tools/aflplusplus/mock/afl_mock.py``); a real installation only swaps the
  per-tool argv.
* Management happens through evidence: each invocation writes one result
  document (hash-bound) plus, for ``afl-tmin``, the minimized reproducer file;
  input hashes (target, seeds, crash inputs) are recorded per label.
  ``verify_run_record`` re-reads, re-validates, re-hashes every input and the
  minimized file, and recounts.
* Normalization is tolerant on unknown keys but strict on the model: empty
  corpora, kept/dropped sets that do not partition the corpus, duplicate or
  unsorted coverage ids, crashes without a signature, minimized reproducers that
  lost their signature or grew, and crash groups whose counts disagree are
  refusals.
* Single attempt per invocation, no retries; a timeout kills the process.
  No firmware addresses/RVAs live here -- address handling stays opaque.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal, Never, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, TypeAdapter, ValidationError, model_validator

from core.models.common import Sha256, StrictModel

MOCK_MODULE = "tools.aflplusplus.mock.afl_mock"
CRASH_MAGIC = b"PS4RF-AFL-CRASH-v1\n"
COVERAGE_ID = r"^0x[0-9a-f]{4}$"
Hex4 = Annotated[str, StringConstraints(pattern=COVERAGE_ID)]
HexStr = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{1,16}$")]
_NAME = Annotated[str, StringConstraints(min_length=1)]


class AflError(Exception):
    """Base class for adapter failures."""


class AflConfigError(AflError):
    """Invalid configuration or arguments."""


class AflRunError(AflError):
    """Tool invocation failed (non-zero exit)."""

    def __init__(self, exit_code: int, detail: str) -> None:
        self.exit_code, self.detail = exit_code, detail
        super().__init__(f"afl tool failed (exit {exit_code}): {detail}")


class AflTimeout(AflError):
    """Tool invocation exceeded the configured timeout (process killed)."""


class AflHashMismatch(AflError):
    """An input does not match the expected or recorded hash."""


class AflEvidenceError(AflError):
    """A recorded run does not re-verify (hash, model, inputs, counts)."""


class AflSchemaError(AflError):
    """A result document violates the tool contract."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AflTargetRef(_Model):
    sha256: Sha256


class AflInputRef(_Model):
    sha256: Sha256
    size: int = Field(ge=0)


class AflCorpusEntry(AflInputRef):
    name: _NAME


class AflCorpus(_Model):
    entries: list[AflCorpusEntry] = Field(min_length=1)
    total: int = Field(ge=1)

    @model_validator(mode="after")
    def _total_matches_entries(self) -> "AflCorpus":
        if self.total != len(self.entries):
            raise ValueError("corpus total does not match entries")
        names = [entry.name for entry in self.entries]
        if len(set(names)) != len(names):
            raise ValueError("duplicate names in corpus")
        if names != sorted(names):
            raise ValueError("corpus entries are not sorted")
        return self


class AflDroppedEntry(_Model):
    name: _NAME
    reason: _NAME


class AflShowmapResult(_Model):
    tool: Literal["afl-showmap"]
    target: AflTargetRef
    input: AflInputRef
    tuples: list[Hex4] = Field(min_length=1)
    crashes: bool
    signature: Optional[HexStr] = None

    @model_validator(mode="after")
    def _coverage_and_signature_consistency(self) -> "AflShowmapResult":
        if len(set(self.tuples)) != len(self.tuples):
            raise ValueError("duplicate coverage ids")
        if self.tuples != sorted(self.tuples):
            raise ValueError("coverage ids are not sorted")
        if self.crashes != (self.signature is not None):
            raise ValueError("crash flag and signature contradict each other")
        return self


class AflCminResult(_Model):
    tool: Literal["afl-cmin"]
    corpus: AflCorpus
    kept: list[_NAME] = Field(min_length=1)
    dropped: list[AflDroppedEntry]
    coverage_total: int = Field(ge=0)

    @model_validator(mode="after")
    def _partition_is_exact(self) -> "AflCminResult":
        names = {entry.name for entry in self.corpus.entries}
        kept, dropped = set(self.kept), {entry.name for entry in self.dropped}
        if kept & dropped:
            raise ValueError("a file is both kept and dropped")
        if kept | dropped != names:
            raise ValueError("kept + dropped do not partition the corpus")
        if self.kept != sorted(self.kept):
            raise ValueError("kept list is not sorted")
        if self.coverage_total > 4 * len(self.corpus.entries):
            raise ValueError("coverage_total exceeds the achievable id count")
        return self


class AflTminResult(_Model):
    tool: Literal["afl-tmin"]
    input: AflInputRef
    minimized: AflInputRef
    signature: HexStr
    preserved_signature: bool

    @model_validator(mode="after")
    def _reproducer_must_shrink_and_preserve(self) -> "AflTminResult":
        if not self.preserved_signature:
            raise ValueError("minimized reproducer lost the crash signature")
        if self.minimized.size > self.input.size:
            raise ValueError("minimized reproducer is larger than the input")
        return self


class AflGroup(_Model):
    signature: HexStr
    members: list[_NAME] = Field(min_length=1)

    @model_validator(mode="after")
    def _members_sorted_and_unique(self) -> "AflGroup":
        if len(set(self.members)) != len(self.members):
            raise ValueError("duplicate members in group")
        if self.members != sorted(self.members):
            raise ValueError("group members are not sorted")
        return self


class AflCollectResult(_Model):
    tool: Literal["afl-collect"]
    groups: list[AflGroup] = Field(min_length=1)
    total: int = Field(ge=1)

    @model_validator(mode="after")
    def _groups_partition_crashes(self) -> "AflCollectResult":
        signatures = [group.signature for group in self.groups]
        if len(set(signatures)) != len(signatures):
            raise ValueError("duplicate crash signatures")
        if signatures != sorted(signatures):
            raise ValueError("crash groups are not sorted")
        members = [member for group in self.groups for member in group.members]
        if len(set(members)) != len(members):
            raise ValueError("a crash input appears in two groups")
        if self.total != len(members):
            raise ValueError("total does not match group members")
        return self


AflResult = Annotated[
    Union[AflShowmapResult, AflCminResult, AflTminResult, AflCollectResult],
    Field(discriminator="tool")]
_RESULT_ADAPTER: TypeAdapter = TypeAdapter(AflResult)

_RESULT_MODEL = {"afl-showmap": AflShowmapResult, "afl-cmin": AflCminResult,
                 "afl-tmin": AflTminResult, "afl-collect": AflCollectResult}


class AflRunRecord(StrictModel):
    """Evidence record of one AFL++ tool invocation (result + inputs hash-bound)."""

    tool: str
    cmd: list[str]
    started_at: datetime
    ended_at: datetime
    result_path: str
    result_sha256: Sha256
    input_paths: dict[str, str]
    input_hashes: dict[str, Sha256]
    minimized_path: Optional[str] = None
    minimized_sha256: Optional[Sha256] = None
    coverage_count: int
    kept_count: int
    dropped_count: int
    groups_count: int
    crashes_count: int


class AflCoverageOutcome(StrictModel):
    target: AflTargetRef
    input: AflInputRef
    tuples: list[Hex4]
    crashes: bool
    signature: Optional[HexStr] = None
    run: AflRunRecord


class AflCorpusOutcome(StrictModel):
    corpus: AflCorpus
    kept: list[str]
    dropped: list[AflDroppedEntry]
    coverage_total: int
    run: AflRunRecord


class AflReproducerOutcome(StrictModel):
    input: AflInputRef
    minimized: AflInputRef
    signature: HexStr
    preserved_signature: bool
    minimized_path: str
    run: AflRunRecord


class AflTriageOutcome(StrictModel):
    groups: list[AflGroup]
    total: int
    run: AflRunRecord


class AflConfig(StrictModel):
    """AFL++ tool configuration. Every ``*_cmd`` is an argv list -- never a shell."""

    fuzz_cmd: list[str] = Field(
        default_factory=lambda: [sys.executable, "-m", MOCK_MODULE, "afl-fuzz"])
    showmap_cmd: list[str] = Field(
        default_factory=lambda: [sys.executable, "-m", MOCK_MODULE, "afl-showmap"])
    cmin_cmd: list[str] = Field(
        default_factory=lambda: [sys.executable, "-m", MOCK_MODULE, "afl-cmin"])
    tmin_cmd: list[str] = Field(
        default_factory=lambda: [sys.executable, "-m", MOCK_MODULE, "afl-tmin"])
    collect_cmd: list[str] = Field(
        default_factory=lambda: [sys.executable, "-m", MOCK_MODULE, "afl-collect"])
    work_dir: str
    timeout_s: float = Field(default=120.0, gt=0)

    @model_validator(mode="after")
    def _argv_policy(self) -> "AflConfig":
        for name in ("fuzz_cmd", "showmap_cmd", "cmin_cmd", "tmin_cmd", "collect_cmd"):
            argv = getattr(self, name)
            if not argv or not all(isinstance(part, str) and part for part in argv):
                raise ValueError(f"{name} must be a non-empty list of argv strings (no shell)")
        if not self.work_dir:
            raise ValueError("work_dir must be set")
        return self


def _validate_result(document: Any, tool: str) -> Any:
    try:
        result = _RESULT_ADAPTER.validate_python(document)
    except ValidationError as exc:
        raise AflSchemaError(f"result invalid for {tool}: {exc}") from exc
    if result.tool != tool:
        raise AflSchemaError(f"result tool {result.tool!r} != requested {tool!r}")
    return result


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AflAdapter:
    """Fail-closed AFL++ management driver. Single attempt per invocation."""

    def __init__(self, config: AflConfig) -> None:
        self.config = config
        self._version: Optional[str] = None
        self.runs: list[AflRunRecord] = []

    # ------------------------------------------------------------------ plumbing
    def hash_file(self, path: str | Path) -> str:
        return _sha256_file(Path(path))

    def health(self) -> dict[str, object]:
        result = subprocess.run([*self.config.fuzz_cmd, "--version"],
                                capture_output=True, text=True,
                                timeout=self.config.timeout_s, check=False)
        if result.returncode != 0:
            raise AflRunError(result.returncode, result.stderr.strip()[:500])
        line = (result.stdout.strip().splitlines() or [""])[0]
        match = re.search(r"(\d+\.\d+[a-z]?(?:-\w+)?)", line)
        if match is None:
            raise AflSchemaError(f"cannot parse version from {line!r}")
        self._version = match.group(1)
        return {"reachable": True, "version": self._version,
                "cmd": list(self.config.fuzz_cmd)}

    def _invoke(self, argv: list[str]) -> None:
        try:
            result = subprocess.run(argv, capture_output=True, text=True,
                                    timeout=self.config.timeout_s, check=False)
        except subprocess.TimeoutExpired as exc:
            raise AflTimeout(
                f"afl tool exceeded {self.config.timeout_s}s (process killed)") from exc
        if result.returncode != 0:
            raise AflRunError(result.returncode, result.stderr.strip()[:500])

    def _corpus_files(self, directory: Path) -> list[Path]:
        if not directory.is_dir():
            raise AflConfigError(f"directory not found: {directory}")
        files = sorted(path for path in directory.iterdir() if path.is_file())
        if not files:
            raise AflConfigError(f"directory is empty: {directory}")
        return files

    def _run(self, *, tool: str, argv: list[str], result_path: Path,
             input_paths: dict[str, Path],
             minimized_path: Optional[Path] = None) -> tuple[Any, AflRunRecord]:
        started = datetime.now(timezone.utc)
        self._invoke(argv)
        ended = datetime.now(timezone.utc)
        if not result_path.is_file():
            raise AflSchemaError(f"result missing after run: {result_path}")
        try:
            document = json.loads(result_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise AflSchemaError(f"result is not valid JSON: {exc}") from exc
        parsed = _validate_result(document, tool)
        if minimized_path is not None:
            if not minimized_path.is_file():
                raise AflSchemaError(f"minimized file missing after run: {minimized_path}")
            actual = _sha256_file(minimized_path)
            if actual != parsed.minimized.sha256:
                raise AflHashMismatch(
                    f"minimized file {actual} != recorded {parsed.minimized.sha256}")
        coverage_count = kept_count = dropped_count = groups_count = crashes_count = 0
        if isinstance(parsed, AflShowmapResult):
            coverage_count = len(parsed.tuples)
            crashes_count = 1 if parsed.crashes else 0
        elif isinstance(parsed, AflCminResult):
            kept_count, dropped_count = len(parsed.kept), len(parsed.dropped)
        elif isinstance(parsed, AflCollectResult):
            groups_count = len(parsed.groups)
            crashes_count = parsed.total
        record = AflRunRecord(
            tool=tool, cmd=argv, started_at=started, ended_at=ended,
            result_path=str(result_path), result_sha256=_sha256_file(result_path),
            input_paths={label: str(path) for label, path in input_paths.items()},
            input_hashes={label: _sha256_file(path)
                          for label, path in input_paths.items()},
            minimized_path=str(minimized_path) if minimized_path else None,
            minimized_sha256=_sha256_file(minimized_path) if minimized_path else None,
            coverage_count=coverage_count, kept_count=kept_count,
            dropped_count=dropped_count, groups_count=groups_count,
            crashes_count=crashes_count)
        self.runs.append(record)
        return parsed, record

    def _result_path(self, tool: str, key: str,
                     result_path: Optional[str | Path]) -> Path:
        if result_path is not None:
            return Path(result_path)
        return Path(self.config.work_dir) / f"{tool}-{key[:8]}.result.json"

    @staticmethod
    def _digest_of(items: list[tuple[str, str]]) -> str:
        blob = "|".join(f"{name}:{sha}" for name, sha in items)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------- methods
    def showmap(self, target_path: str | Path, input_path: str | Path, *,
                expected_target_sha256: Optional[str] = None,
                expected_input_sha256: Optional[str] = None,
                result_path: Optional[str | Path] = None) -> AflCoverageOutcome:
        target, input_file = Path(target_path), Path(input_path)
        if not target.is_file():
            raise AflConfigError(f"target not found: {target}")
        if not input_file.is_file():
            raise AflConfigError(f"input not found: {input_file}")
        target_sha, input_sha = _sha256_file(target), _sha256_file(input_file)
        if expected_target_sha256 is not None and target_sha != expected_target_sha256:
            raise AflHashMismatch(
                f"target {target_sha} != expected {expected_target_sha256} "
                "(refused before invocation)")
        if expected_input_sha256 is not None and input_sha != expected_input_sha256:
            raise AflHashMismatch(
                f"input {input_sha} != expected {expected_input_sha256} "
                "(refused before invocation)")
        if self._version is None:
            self.health()
        out = self._result_path("afl-showmap", input_sha, result_path)
        argv = [*self.config.showmap_cmd, "--target", str(target), "--input",
                str(input_file), "--out", str(out)]
        parsed, record = self._run(tool="afl-showmap", argv=argv, result_path=out,
                                   input_paths={"target": target, "input": input_file})
        assert isinstance(parsed, AflShowmapResult)
        return AflCoverageOutcome(target=parsed.target, input=parsed.input,
                                  tuples=parsed.tuples, crashes=parsed.crashes,
                                  signature=parsed.signature, run=record)

    def cmin(self, corpus_dir: str | Path, *,
             result_path: Optional[str | Path] = None) -> AflCorpusOutcome:
        corpus = Path(corpus_dir)
        files = self._corpus_files(corpus)
        if self._version is None:
            self.health()
        key = self._digest_of([(f.name, _sha256_file(f)) for f in files])
        out = self._result_path("afl-cmin", key, result_path)
        argv = [*self.config.cmin_cmd, "--corpus", str(corpus), "--out", str(out)]
        parsed, record = self._run(tool="afl-cmin", argv=argv, result_path=out,
                                   input_paths={f"corpus/{f.name}": f for f in files})
        assert isinstance(parsed, AflCminResult)
        return AflCorpusOutcome(corpus=parsed.corpus, kept=parsed.kept,
                                dropped=parsed.dropped,
                                coverage_total=parsed.coverage_total, run=record)

    def tmin(self, crash_path: str | Path, *,
             minimized_path: Optional[str | Path] = None,
             expected_input_sha256: Optional[str] = None,
             result_path: Optional[str | Path] = None) -> AflReproducerOutcome:
        crash = Path(crash_path)
        if not crash.is_file():
            raise AflConfigError(f"crash input not found: {crash}")
        crash_sha = _sha256_file(crash)
        if expected_input_sha256 is not None and crash_sha != expected_input_sha256:
            raise AflHashMismatch(
                f"input {crash_sha} != expected {expected_input_sha256} "
                "(refused before invocation)")
        if self._version is None:
            self.health()
        out = self._result_path("afl-tmin", crash_sha, result_path)
        minimized = Path(minimized_path) if minimized_path is not None \
            else Path(self.config.work_dir) / f"afl-tmin-{crash_sha[:8]}.min.bin"
        argv = [*self.config.tmin_cmd, "--input", str(crash), "--out-min",
                str(minimized), "--out", str(out)]
        parsed, record = self._run(tool="afl-tmin", argv=argv, result_path=out,
                                   input_paths={"input": crash},
                                   minimized_path=minimized)
        assert isinstance(parsed, AflTminResult)
        return AflReproducerOutcome(input=parsed.input, minimized=parsed.minimized,
                                    signature=parsed.signature,
                                    preserved_signature=parsed.preserved_signature,
                                    minimized_path=str(minimized), run=record)

    def triage(self, crashes_dir: str | Path, *,
               result_path: Optional[str | Path] = None) -> AflTriageOutcome:
        crashes = Path(crashes_dir)
        files = self._corpus_files(crashes)
        if self._version is None:
            self.health()
        key = self._digest_of([(f.name, _sha256_file(f)) for f in files])
        out = self._result_path("afl-collect", key, result_path)
        argv = [*self.config.collect_cmd, "--crashes", str(crashes), "--out", str(out)]
        parsed, record = self._run(tool="afl-collect", argv=argv, result_path=out,
                                   input_paths={f"crash/{f.name}": f for f in files})
        assert isinstance(parsed, AflCollectResult)
        return AflTriageOutcome(groups=parsed.groups, total=parsed.total, run=record)


def verify_run_record(record: AflRunRecord) -> bool:
    """Re-read, re-validate, re-hash inputs and recount a recorded invocation."""
    def fail(message: str) -> Never:
        raise AflEvidenceError(message)

    result_path = Path(record.result_path)
    if not result_path.is_file():
        fail(f"result missing: {result_path}")
    if _sha256_file(result_path) != record.result_sha256:
        fail("result hash mismatch")
    if set(record.input_paths) != set(record.input_hashes):
        fail("input labels of paths and hashes differ")
    for label, path_text in record.input_paths.items():
        path = Path(path_text)
        if not path.is_file():
            fail(f"input missing for {label}: {path}")
        if _sha256_file(path) != record.input_hashes[label]:
            fail(f"input hash mismatch for {label}")
    if record.minimized_path is not None:
        minimized = Path(record.minimized_path)
        if not minimized.is_file():
            fail(f"minimized file missing: {minimized}")
        if _sha256_file(minimized) != record.minimized_sha256:
            fail("minimized file hash mismatch")
    try:
        document = json.loads(result_path.read_text(encoding="utf-8"))
        parsed = _validate_result(document, record.tool)
    except (json.JSONDecodeError, AflSchemaError) as exc:
        fail(f"result failed re-validation: {exc}")
    coverage_count = kept_count = dropped_count = groups_count = crashes_count = 0
    if isinstance(parsed, AflShowmapResult):
        coverage_count = len(parsed.tuples)
        crashes_count = 1 if parsed.crashes else 0
        # a recorded crash input must still be a crash input on re-read
        input_path_text = record.input_paths.get("input")
        if input_path_text is not None and parsed.crashes:
            if not Path(input_path_text).read_bytes().startswith(CRASH_MAGIC):
                fail("recorded crash input is not a crash input")
    elif isinstance(parsed, AflCminResult):
        kept_count, dropped_count = len(parsed.kept), len(parsed.dropped)
    elif isinstance(parsed, AflTminResult):
        minimized_text = record.minimized_path
        if minimized_text is not None:
            if not Path(minimized_text).read_bytes().startswith(CRASH_MAGIC):
                fail("minimized reproducer lost the crash magic")
    else:
        groups_count = len(parsed.groups)
        crashes_count = parsed.total
    if (coverage_count, kept_count, dropped_count, groups_count, crashes_count) != \
            (record.coverage_count, record.kept_count, record.dropped_count,
             record.groups_count, record.crashes_count):
        fail("recomputed counts do not match the record")
    return True
