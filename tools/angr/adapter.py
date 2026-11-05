"""angr adapter (P3): CFG, dataflow, symbolic constraints — plus hashing.

Boundaries (consistent with the adapter rules of the handoff):

* Static analysis only; the adapter never executes, loads or patches the
  analyzed artifact. The runner is a separate process answering a request
  document with an export document.
* Offline-first: the default ``runner_cmd`` is the runner mock
  (``tools/angr/mock/angr_mock.py``). A real angr installation only swaps the
  command; the request/export contract stays.
* Both sides of the contract are hash-bound: the request (written by the
  adapter), the export (written by the runner) and the committed runner
  placeholder (``tools/angr/scripts/ps4rf_angr_run.py``) all carry recorded
  sha256 values; ``verify_run_record`` re-reads, re-validates and recounts.
* Normalization is tolerant on unknown angr keys but strict on the model:
  missing/ill-typed fields, duplicate or out-of-range blocks, CFG nodes that do
  not match the function blocks, dataflow addresses outside the queried
  function, paths that did not reach the queried target, and constraints whose
  satisfiability contradicts their solution are refusals.
* Single attempt per invocation, no retries; a timeout kills the process.
  No firmware addresses/RVAs live here -- address handling stays opaque.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Literal, Never, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, TypeAdapter, ValidationError, model_validator

from core.models.common import Sha256, StrictModel

SCHEMA_ID = "ps4rf.angr.export/v1"
REQUEST_SCHEMA_ID = "ps4rf.angr.request/v1"
RUNNER_ID = "ps4rf_angr_run"
RUNNER_PATH = Path(__file__).resolve().parent / "scripts" / "ps4rf_angr_run.py"

HexStr = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{1,16}$")]
_NAME = Annotated[str, StringConstraints(min_length=1)]


class AngrError(Exception):
    """Base class for adapter failures."""


class AngrConfigError(AngrError):
    """Invalid configuration or arguments."""


class AngrRunError(AngrError):
    """Runner invocation failed (non-zero exit)."""

    def __init__(self, exit_code: int, detail: str) -> None:
        self.exit_code, self.detail = exit_code, detail
        super().__init__(f"angr runner failed (exit {exit_code}): {detail}")


class AngrTimeout(AngrError):
    """Runner invocation exceeded the configured timeout (process killed)."""


class AngrHashMismatch(AngrError):
    """Artifact or runner hash does not match the expected or recorded value."""


class AngrEvidenceError(AngrError):
    """A recorded run does not re-verify (hash, mode, content, counts)."""


class AngrSchemaError(AngrError):
    """A document violates the request/export contract."""


class AngrNotFound(AngrError):
    """Function or target could not be resolved (runner refused the query)."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CfgEdgeType(str, Enum):
    CALL = "call"
    JUMP = "jump"
    FALLTHROUGH = "fallthrough"
    RET = "ret"
    OTHER = "other"


class DataflowKind(str, Enum):
    REG = "reg"
    MEM = "mem"
    STACK = "stack"


class AngrInfo(_Model):
    arch: _NAME
    bits: int = Field(gt=0)
    endian: _NAME
    os: _NAME


class AngrFunction(_Model):
    name: _NAME
    offset: HexStr
    size: int = Field(gt=0)
    blocks: list[HexStr] = Field(min_length=1)

    @model_validator(mode="after")
    def _blocks_within_range(self) -> "AngrFunction":
        start = int(self.offset, 16)
        end = start + self.size
        for block in self.blocks:
            if not start <= int(block, 16) < end:
                raise ValueError(f"block {block} lies outside {self.name}")
        if len(set(self.blocks)) != len(self.blocks):
            raise ValueError("duplicate blocks in function")
        return self


class AngrFunctionRef(_Model):
    name: _NAME
    offset: HexStr
    size: int = Field(gt=0)


class AngrCfgNode(_Model):
    offset: HexStr
    size: int = Field(gt=0)


class AngrCfgEdge(_Model):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    from_addr: HexStr = Field(alias="src")
    to_addr: HexStr = Field(alias="dst")
    type: CfgEdgeType


class AngrCfg(_Model):
    nodes: list[AngrCfgNode] = Field(min_length=1)
    edges: list[AngrCfgEdge]

    @model_validator(mode="after")
    def _edges_reference_nodes(self) -> "AngrCfg":
        known = {node.offset for node in self.nodes}
        if len(known) != len(self.nodes):
            raise ValueError("duplicate CFG node offsets")
        for edge in self.edges:
            if edge.from_addr not in known or edge.to_addr not in known:
                raise ValueError(
                    f"CFG edge {edge.from_addr}->{edge.to_addr} leaves the node set")
        return self


class AngrDataflowEdge(_Model):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    from_addr: HexStr = Field(alias="from")
    to_addr: HexStr = Field(alias="to")
    kind: DataflowKind
    value: _NAME


class AngrConstraint(_Model):
    expr: _NAME
    satisfiable: bool
    solution: Optional[_NAME] = None

    @model_validator(mode="after")
    def _solution_matches_satisfiability(self) -> "AngrConstraint":
        if self.satisfiable == (self.solution is None):
            raise ValueError(
                "satisfiable constraints need a solution, unsatisfiable must not have one")
        return self


class AngrPath(_Model):
    path_id: _NAME
    reached: HexStr
    steps: list[HexStr] = Field(min_length=1)
    constraints: list[AngrConstraint]


class SimStamp(_Model):
    schema_id: str = Field(alias="schema")
    artifact: dict[str, Sha256]
    generator: dict[str, str]

    @model_validator(mode="after")
    def _stamp_policy(self) -> "SimStamp":
        if self.schema_id != SCHEMA_ID:
            raise ValueError(f"schema must be {SCHEMA_ID!r}")
        if set(self.artifact) != {"sha256"}:
            raise ValueError("artifact block must contain exactly sha256")
        if set(self.generator) != {"tool", "version", "runner", "runner_sha256"}:
            raise ValueError("generator block must be tool/version/runner/runner_sha256")
        if self.generator["runner"] != RUNNER_ID:
            raise ValueError(f"runner must be {RUNNER_ID!r}")
        return self


class AngrAnalyzeExport(SimStamp):
    mode: Literal["analyze"]
    info: AngrInfo
    entry: HexStr
    functions: list[AngrFunction] = Field(min_length=1)
    cfg: AngrCfg

    @model_validator(mode="after")
    def _entry_is_a_function(self) -> "AngrAnalyzeExport":
        offsets = [fn.offset for fn in self.functions]
        if len(set(offsets)) != len(offsets):
            raise ValueError("duplicate function offsets")
        if self.entry not in offsets:
            raise ValueError("entry is not a function start")
        blocks = [block for fn in self.functions for block in fn.blocks]
        if len(set(blocks)) != len(blocks):
            raise ValueError("blocks claimed by more than one function")
        if set(blocks) != {node.offset for node in self.cfg.nodes}:
            raise ValueError("CFG nodes do not match the union of function blocks")
        return self


class AngrDataflowExport(SimStamp):
    mode: Literal["dataflow"]
    function: AngrFunctionRef
    edges: list[AngrDataflowEdge]

    @model_validator(mode="after")
    def _sources_inside_function(self) -> "AngrDataflowExport":
        start = int(self.function.offset, 16)
        end = start + self.function.size
        for edge in self.edges:
            if not start <= int(edge.from_addr, 16) < end:
                raise ValueError(
                    f"dataflow source {edge.from_addr} outside {self.function.name}")
        return self


class AngrSymbolicExport(SimStamp):
    mode: Literal["symbolic"]
    target: HexStr
    paths: list[AngrPath] = Field(min_length=1)

    @model_validator(mode="after")
    def _paths_reach_target(self) -> "AngrSymbolicExport":
        for path in self.paths:
            if path.reached != self.target:
                raise ValueError(f"path {path.path_id} did not reach {self.target}")
        if len({path.path_id for path in self.paths}) != len(self.paths):
            raise ValueError("duplicate path ids")
        return self


AngrExport = Annotated[
    Union[AngrAnalyzeExport, AngrDataflowExport, AngrSymbolicExport],
    Field(discriminator="mode")]
_EXPORT_ADAPTER: TypeAdapter = TypeAdapter(AngrExport)


class AngrRunRecord(StrictModel):
    """Evidence record of one runner invocation (request and export hash-bound)."""

    artifact_path: str
    artifact_sha256: Sha256
    runner_path: str
    runner_sha256: Sha256
    runner_version: str
    mode: str
    target: Optional[str] = None
    request_path: str
    request_sha256: Sha256
    export_path: str
    export_sha256: Sha256
    started_at: datetime
    ended_at: datetime
    functions_count: int
    nodes_count: int
    edges_count: int
    dataflow_count: int
    paths_count: int
    constraints_count: int


class AngrAnalysis(StrictModel):
    info: AngrInfo
    entry: HexStr
    functions: list[AngrFunction]
    cfg: AngrCfg
    run: AngrRunRecord


class AngrDataflowResult(StrictModel):
    function: AngrFunctionRef
    edges: list[AngrDataflowEdge]
    run: AngrRunRecord


class AngrSymbolicResult(StrictModel):
    target: HexStr
    paths: list[AngrPath]
    run: AngrRunRecord


class AngrConfig(StrictModel):
    """angr runner configuration. ``runner_cmd`` is an argv list -- never a shell."""

    runner_cmd: list[str] = Field(
        default_factory=lambda: [sys.executable, "-m", "tools.angr.mock.angr_mock"])
    work_dir: str
    timeout_s: float = Field(default=120.0, gt=0)
    runner_path: str = str(RUNNER_PATH)

    @model_validator(mode="after")
    def _argv_policy(self) -> "AngrConfig":
        if not self.runner_cmd or not all(
                isinstance(part, str) and part for part in self.runner_cmd):
            raise ValueError("runner_cmd must be a non-empty list of argv strings (no shell)")
        if not self.work_dir:
            raise ValueError("work_dir must be set")
        if not self.runner_path:
            raise ValueError("runner_path must be set")
        return self


def _address(value: Any) -> str:
    """Normalize a caller-supplied address; bad input is a config error."""
    if isinstance(value, int) and not isinstance(value, bool):
        return hex(value)
    if isinstance(value, str):
        candidate = value.lower()
        if candidate.startswith("0x") and all(c in "0123456789abcdef" for c in candidate[2:]) \
                and 1 <= len(candidate) - 2 <= 16:
            return candidate
    raise AngrConfigError(f"cannot normalize address {value!r} (expected 0x-hex)")


def _validate_export(document: Any, mode: str) -> Any:
    try:
        export = _EXPORT_ADAPTER.validate_python(document)
    except ValidationError as exc:
        raise AngrSchemaError(f"export invalid for mode {mode}: {exc}") from exc
    if export.mode != mode:
        raise AngrSchemaError(f"export mode {export.mode!r} != requested {mode!r}")
    return export


class AngrAdapter:
    """Fail-closed angr runner driver. Single attempt per invocation; no retries."""

    def __init__(self, config: AngrConfig) -> None:
        self.config = config
        self._version: Optional[str] = None
        self.runs: list[AngrRunRecord] = []
        self._last_functions: dict[str, AngrFunction] = {}

    # ------------------------------------------------------------------ plumbing
    def hash_artifact(self, path: str | Path) -> str:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def hash_runner(self) -> str:
        runner = Path(self.config.runner_path)
        if not runner.is_file():
            raise AngrConfigError(f"runner not found: {runner}")
        return hashlib.sha256(runner.read_bytes()).hexdigest()

    def health(self) -> dict[str, object]:
        result = subprocess.run([*self.config.runner_cmd, "--version"], capture_output=True,
                                text=True, timeout=self.config.timeout_s, check=False)
        if result.returncode != 0:
            raise AngrRunError(result.returncode, result.stderr.strip()[:500])
        line = (result.stdout.strip().splitlines() or [""])[0]
        parts = line.split()
        version = parts[1] if len(parts) > 1 else line
        self._version = version
        return {"reachable": True, "version": version, "cmd": list(self.config.runner_cmd)}

    def _prepare(self, artifact_path: str | Path, expected_artifact_sha256: Optional[str],
                 expected_runner_sha256: Optional[str]) -> tuple[Path, str]:
        artifact = Path(artifact_path)
        if not artifact.is_file():
            raise AngrConfigError(f"artifact not found: {artifact}")
        digest = self.hash_artifact(artifact)
        if expected_artifact_sha256 is not None and digest != expected_artifact_sha256:
            raise AngrHashMismatch(
                f"artifact {digest} != expected {expected_artifact_sha256} "
                "(refused before invocation)")
        runner_digest = self.hash_runner()
        if expected_runner_sha256 is not None and runner_digest != expected_runner_sha256:
            raise AngrHashMismatch(
                f"runner {runner_digest} != expected {expected_runner_sha256} "
                "(refused before invocation)")
        if self._version is None:
            self.health()
        return artifact, digest

    def _invoke(self, request: dict, request_path: Path, export_path: Path) -> str:
        argv = [*self.config.runner_cmd, "run", "--request", str(request_path),
                "--out", str(export_path)]
        try:
            result = subprocess.run(argv, capture_output=True, text=True,
                                    timeout=self.config.timeout_s, check=False)
        except subprocess.TimeoutExpired as exc:
            raise AngrTimeout(
                f"angr runner exceeded {self.config.timeout_s}s (process killed)") from exc
        if result.returncode != 0:
            detail = result.stderr.strip()[:500]
            if result.returncode == 7:
                raise AngrNotFound(f"function/target not resolved: {detail}")
            raise AngrRunError(result.returncode, detail)
        for path, label in ((request_path, "request"), (export_path, "export")):
            if not path.is_file():
                raise AngrSchemaError(f"{label} missing after run: {path}")
        return export_path.read_text(encoding="utf-8")

    def _paths(self, digest: str, mode: str, target: Optional[str],
               request_path: Optional[str | Path],
               export_path: Optional[str | Path]) -> tuple[Path, Path]:
        stem = f"{digest[:8]}-{mode}" + (f"-{target}" if target else "")
        work = Path(self.config.work_dir)
        request = Path(request_path) if request_path is not None \
            else work / f"{stem}.request.json"
        export = Path(export_path) if export_path is not None \
            else work / f"{stem}.export.json"
        return request, export

    def _run(self, *, mode: str, target: Optional[str], artifact: Path, digest: str,
             runner_digest: str, request_path: Optional[str | Path],
             export_path: Optional[str | Path]) -> tuple[Any, AngrRunRecord]:
        request, export = self._paths(digest, mode, target, request_path, export_path)
        document: dict[str, Any] = {"schema": REQUEST_SCHEMA_ID, "mode": mode,
                                    "artifact": str(artifact.resolve()),
                                    "artifact_sha256": digest}
        if mode == "analyze":
            document["entry"] = target
        elif mode == "dataflow":
            document["function"] = target
        else:
            document["target"] = target
        request.parent.mkdir(parents=True, exist_ok=True)
        request.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
        started = datetime.now(timezone.utc)
        raw = self._invoke(document, request, export)
        ended = datetime.now(timezone.utc)
        try:
            loaded = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AngrSchemaError(f"export is not valid JSON: {exc}") from exc
        parsed = _validate_export(loaded, mode)
        if parsed.artifact["sha256"] != digest:
            raise AngrHashMismatch(
                f"export artifact {parsed.artifact['sha256']} != {digest}")
        if parsed.generator["runner_sha256"] != runner_digest:
            raise AngrHashMismatch(
                f"export runner hash {parsed.generator['runner_sha256']} != "
                f"local runner {runner_digest}")
        counts = {"functions_count": 0, "nodes_count": 0, "edges_count": 0,
                  "dataflow_count": 0, "paths_count": 0, "constraints_count": 0}
        if isinstance(parsed, AngrAnalyzeExport):
            counts["functions_count"] = len(parsed.functions)
            counts["nodes_count"] = len(parsed.cfg.nodes)
            counts["edges_count"] = len(parsed.cfg.edges)
        elif isinstance(parsed, AngrDataflowExport):
            counts["dataflow_count"] = len(parsed.edges)
        else:
            counts["paths_count"] = len(parsed.paths)
            counts["constraints_count"] = sum(len(p.constraints) for p in parsed.paths)
        record = AngrRunRecord(
            artifact_path=str(artifact), artifact_sha256=digest,
            runner_path=str(self.config.runner_path), runner_sha256=runner_digest,
            runner_version=self._version or "unknown", mode=mode, target=target,
            request_path=str(request),
            request_sha256=hashlib.sha256(request.read_bytes()).hexdigest(),
            export_path=str(export),
            export_sha256=hashlib.sha256(export.read_bytes()).hexdigest(),
            started_at=started, ended_at=ended, **counts)
        self.runs.append(record)
        return parsed, record

    # ------------------------------------------------------------------- methods
    def analyze(self, artifact_path: str | Path, entry: Optional[str | int] = None, *,
                expected_artifact_sha256: Optional[str] = None,
                expected_runner_sha256: Optional[str] = None,
                request_path: Optional[str | Path] = None,
                export_path: Optional[str | Path] = None) -> AngrAnalysis:
        artifact, digest = self._prepare(artifact_path, expected_artifact_sha256,
                                        expected_runner_sha256)
        target = _address(entry) if entry is not None else None
        parsed, record = self._run(mode="analyze", target=target, artifact=artifact,
                                   digest=digest, runner_digest=self.hash_runner(),
                                   request_path=request_path, export_path=export_path)
        assert isinstance(parsed, AngrAnalyzeExport)
        if target is not None and parsed.entry != target:
            raise AngrSchemaError(f"export entry {parsed.entry} != requested {target}")
        self._last_functions = {fn.offset: fn for fn in parsed.functions}
        return AngrAnalysis(info=parsed.info, entry=parsed.entry,
                            functions=parsed.functions, cfg=parsed.cfg, run=record)

    def dataflow(self, artifact_path: str | Path, function: str | int, *,
                 expected_artifact_sha256: Optional[str] = None,
                 expected_runner_sha256: Optional[str] = None,
                 request_path: Optional[str | Path] = None,
                 export_path: Optional[str | Path] = None) -> AngrDataflowResult:
        artifact, digest = self._prepare(artifact_path, expected_artifact_sha256,
                                        expected_runner_sha256)
        target = _address(function)
        parsed, record = self._run(mode="dataflow", target=target, artifact=artifact,
                                   digest=digest, runner_digest=self.hash_runner(),
                                   request_path=request_path, export_path=export_path)
        assert isinstance(parsed, AngrDataflowExport)
        if parsed.function.offset != target:
            raise AngrSchemaError(
                f"export function {parsed.function.offset} != requested {target}")
        known = self._last_functions.get(target)
        if known is not None and (known.name != parsed.function.name
                                  or known.size != parsed.function.size):
            raise AngrSchemaError("export function disagrees with the analyzed function")
        return AngrDataflowResult(function=parsed.function, edges=parsed.edges, run=record)

    def symbolic(self, artifact_path: str | Path, target: str | int, *,
                 expected_artifact_sha256: Optional[str] = None,
                 expected_runner_sha256: Optional[str] = None,
                 request_path: Optional[str | Path] = None,
                 export_path: Optional[str | Path] = None) -> AngrSymbolicResult:
        artifact, digest = self._prepare(artifact_path, expected_artifact_sha256,
                                        expected_runner_sha256)
        address = _address(target)
        parsed, record = self._run(mode="symbolic", target=address, artifact=artifact,
                                   digest=digest, runner_digest=self.hash_runner(),
                                   request_path=request_path, export_path=export_path)
        assert isinstance(parsed, AngrSymbolicExport)
        if parsed.target != address:
            raise AngrSchemaError(f"export target {parsed.target} != requested {address}")
        return AngrSymbolicResult(target=parsed.target, paths=parsed.paths, run=record)


def verify_run_record(record: AngrRunRecord) -> bool:
    """Re-read, re-validate and recount a recorded runner invocation."""
    def fail(message: str) -> Never:
        raise AngrEvidenceError(message)

    artifact = Path(record.artifact_path)
    if not artifact.is_file():
        fail(f"artifact missing: {artifact}")
    if hashlib.sha256(artifact.read_bytes()).hexdigest() != record.artifact_sha256:
        fail("artifact hash mismatch")
    runner = Path(record.runner_path)
    if not runner.is_file():
        fail(f"runner missing: {runner}")
    if hashlib.sha256(runner.read_bytes()).hexdigest() != record.runner_sha256:
        fail("runner hash mismatch")
    for path_text, expected, label in (
            (record.request_path, record.request_sha256, "request"),
            (record.export_path, record.export_sha256, "export")):
        path = Path(path_text)
        if not path.is_file():
            fail(f"{label} missing: {path}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            fail(f"{label} hash mismatch")
    try:
        request = json.loads(Path(record.request_path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"request is not valid JSON: {exc}")
    if request.get("schema") != REQUEST_SCHEMA_ID or request.get("mode") != record.mode:
        fail("request does not match the record")
    if request.get("artifact_sha256") != record.artifact_sha256:
        fail("request artifact hash does not match the record")
    try:
        document = json.loads(Path(record.export_path).read_text(encoding="utf-8"))
        parsed = _validate_export(document, record.mode)
    except (json.JSONDecodeError, AngrSchemaError) as exc:
        fail(f"export failed re-validation: {exc}")
    if parsed.artifact["sha256"] != record.artifact_sha256:
        fail("export artifact hash does not match the record")
    if parsed.generator["runner_sha256"] != record.runner_sha256:
        fail("export runner hash does not match the record")
    functions_count = nodes_count = edges_count = 0
    dataflow_count = paths_count = constraints_count = 0
    if isinstance(parsed, AngrAnalyzeExport):
        functions_count = len(parsed.functions)
        nodes_count = len(parsed.cfg.nodes)
        edges_count = len(parsed.cfg.edges)
        if record.target is not None and parsed.entry != record.target:
            fail("export entry does not match the recorded target")
    elif isinstance(parsed, AngrDataflowExport):
        dataflow_count = len(parsed.edges)
        if record.target is not None and parsed.function.offset != record.target:
            fail("export function does not match the recorded target")
    else:
        paths_count = len(parsed.paths)
        constraints_count = sum(len(p.constraints) for p in parsed.paths)
        if record.target is not None and parsed.target != record.target:
            fail("export target does not match the recorded target")
    if (functions_count, nodes_count, edges_count, dataflow_count, paths_count,
            constraints_count) != (record.functions_count, record.nodes_count,
                                   record.edges_count, record.dataflow_count,
                                   record.paths_count, record.constraints_count):
        fail("recomputed counts do not match the record")
    return True
