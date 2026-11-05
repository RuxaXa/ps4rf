"""Rizin adapter (P3): xrefs, CFG, basic-block boundaries — plus hashing.

Boundaries (consistent with the adapter rules of the handoff):

* Static analysis only; the adapter never executes, loads or patches the
  analyzed artifact.
* Offline-first: the default ``rizin_cmd`` is the command-surface mock
  (``tools/rizin/mock/rizin_mock.py``). A real rizin installation only changes
  the command; the invocation style (``-q``, ``-e``, repeated ``-c``, ``?e``
  echo markers) follows the real CLI.
* stdout is the evidence: every invocation is captured byte-exactly to a file,
  hashed and recorded. ``verify_run_record`` re-reads, re-parses, re-validates
  and recounts; tampering is detected.
* Normalization is tolerant on unknown rizin keys (explicit field picks) but
  strict on the normalized model: missing/ill-typed fields, stray output
  outside the marker sections, xrefs that contradict the queried
  address/direction, and CFG edges that contradict their blocks are refusals.
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
from typing import Annotated, Any, Never, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, model_validator

from core.models.common import Sha256, StrictModel

MARKER_TEMPLATE = "__PS4RF_:{}__"
SECTIONS = ("info", "functions", "xr", "cfg", "bb")
_QUERY_SECTIONS: dict[str, tuple[str, ...]] = {
    "analyze": ("info", "functions"),
    "xrefs": ("xr",),
    "cfg": ("cfg",),
    "boundaries": ("bb",),
}
HexStr = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{1,16}$")]
_NAME = Annotated[str, StringConstraints(min_length=1)]


class RizinError(Exception):
    """Base class for adapter failures."""


class RizinConfigError(RizinError):
    """Invalid configuration or arguments."""


class RizinRunError(RizinError):
    """rizin invocation failed (non-zero exit)."""

    def __init__(self, exit_code: int, detail: str) -> None:
        self.exit_code, self.detail = exit_code, detail
        super().__init__(f"rizin invocation failed (exit {exit_code}): {detail}")


class RizinTimeout(RizinError):
    """rizin invocation exceeded the configured timeout (process killed)."""


class RizinHashMismatch(RizinError):
    """Artifact hash does not match the expected or recorded value."""


class RizinEvidenceError(RizinError):
    """A recorded run does not re-verify (hash, sections, counts, content)."""


class RizinSchemaError(RizinError):
    """stdout violates the adapter's marker/normalization contract."""


class RizinNotFound(RizinError):
    """Address is not a known function (mock/rizin refused the query)."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class XrefType(str, Enum):
    CALL = "CALL"
    JUMP = "JUMP"
    DATA = "DATA"
    OTHER = "OTHER"


class EdgeType(str, Enum):
    JUMP = "jump"
    FAIL = "fail"
    OTHER = "other"


class RizinInfo(_Model):
    arch: _NAME
    bits: int = Field(gt=0)
    endian: _NAME
    os: _NAME


class RizinFunction(_Model):
    name: _NAME
    offset: HexStr
    size: int = Field(ge=0)
    type: _NAME


class RizinXref(_Model):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    from_addr: HexStr = Field(alias="from")
    to_addr: HexStr = Field(alias="to")
    type: XrefType


class RizinBasicBlock(_Model):
    offset: HexStr
    size: int = Field(gt=0)
    jump: Optional[HexStr] = None
    fail: Optional[HexStr] = None
    ninstr: int = Field(ge=0)


class RizinEdge(_Model):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    from_addr: HexStr = Field(alias="src")
    to_addr: HexStr = Field(alias="dst")
    type: EdgeType


class RizinCfg(_Model):
    function: _NAME
    offset: HexStr
    blocks: list[RizinBasicBlock] = Field(min_length=1)
    edges: list[RizinEdge]

    @model_validator(mode="after")
    def _edge_block_consistency(self) -> "RizinCfg":
        by_offset = {b.offset: b for b in self.blocks}
        if len(by_offset) != len(self.blocks):
            raise ValueError("duplicate block offsets in CFG")
        for edge in self.edges:
            block = by_offset.get(edge.from_addr)
            if block is None:
                raise ValueError(f"edge source {edge.from_addr} is not a block")
            if edge.type is EdgeType.JUMP and block.jump != edge.to_addr:
                raise ValueError("jump edge contradicts block.jump")
            if edge.type is EdgeType.FAIL and block.fail != edge.to_addr:
                raise ValueError("fail edge contradicts block.fail")
        declared = {(b.offset, b.jump) for b in self.blocks if b.jump}
        declared |= {(b.offset, b.fail) for b in self.blocks if b.fail}
        actual = {(e.from_addr, e.to_addr) for e in self.edges
                  if e.type in (EdgeType.JUMP, EdgeType.FAIL)}
        if declared != actual:
            raise ValueError("CFG edges do not match block jump/fail fields")
        return self


class RizinRunRecord(StrictModel):
    """Evidence record of one rizin invocation (stdout hash-bound)."""

    artifact_path: str
    artifact_sha256: Sha256
    rizin_version: str
    query_kind: str
    query_target: Optional[str] = None
    query_direction: Optional[str] = None
    cmd: list[str]
    started_at: datetime
    ended_at: datetime
    stdout_path: str
    stdout_sha256: Sha256
    sections: list[str]
    functions_count: int
    xrefs_count: int
    blocks_count: int
    edges_count: int


class RizinAnalysis(StrictModel):
    info: RizinInfo
    functions: list[RizinFunction]
    run: RizinRunRecord


class RizinXrefResult(StrictModel):
    xrefs: list[RizinXref]
    run: RizinRunRecord


class RizinCfgResult(StrictModel):
    cfg: RizinCfg
    run: RizinRunRecord


class RizinBoundariesResult(StrictModel):
    function: str
    offset: HexStr
    blocks: list[RizinBasicBlock]
    run: RizinRunRecord


class RizinConfig(StrictModel):
    """rizin configuration. ``rizin_cmd`` is an argv list -- never a shell."""

    rizin_cmd: list[str] = Field(
        default_factory=lambda: [sys.executable, "-m", "tools.rizin.mock.rizin_mock"])
    work_dir: str
    timeout_s: float = Field(default=120.0, gt=0)

    @model_validator(mode="after")
    def _argv_policy(self) -> "RizinConfig":
        if not self.rizin_cmd or not all(
                isinstance(part, str) and part for part in self.rizin_cmd):
            raise ValueError("rizin_cmd must be a non-empty list of argv strings (no shell)")
        if not self.work_dir:
            raise ValueError("work_dir must be set")
        return self


# --------------------------------------------------------------------- parsing
def split_sections(stdout: str, expected: tuple[str, ...]) -> dict[str, str]:
    """Split stdout into marker-delimited sections; strict about stray output."""
    markers = {MARKER_TEMPLATE.format(name): name for name in expected}
    payloads: dict[str, list[str]] = {name: [] for name in expected}
    current: Optional[str] = None
    seen: list[str] = []
    for line in stdout.splitlines():
        if line in markers:
            current = markers[line]
            if current in seen:
                raise RizinSchemaError(f"duplicate marker for section {current!r}")
            seen.append(current)
            continue
        if current is None:
            if line.strip():
                raise RizinSchemaError("output outside marker sections")
            continue
        payloads[current].append(line)
    if seen != list(expected):
        raise RizinSchemaError(f"marker sections {seen} != expected {list(expected)}")
    result = {}
    for name in expected:
        text = "\n".join(payloads[name]).strip()
        if not text:
            raise RizinSchemaError(f"empty section {name!r}")
        result[name] = text
    return result


def _normalize_offset(value: Any, field: str) -> str:
    if isinstance(value, bool) or value is None:
        raise RizinSchemaError(f"{field}: missing or invalid offset")
    if isinstance(value, int):
        return hex(value)
    if isinstance(value, str):
        candidate = value.lower()
        if candidate.startswith("0x") and all(c in "0123456789abcdef" for c in candidate[2:]) \
                and 1 <= len(candidate) - 2 <= 16:
            return candidate
    raise RizinSchemaError(f"{field}: cannot normalize offset {value!r}")


def _address(address: str) -> str:
    """Normalize a caller-supplied address; bad input is a config error."""
    try:
        return _normalize_offset(address, "address")
    except RizinSchemaError as exc:
        raise RizinConfigError(str(exc)) from exc


def _json_of(text: str, section: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise RizinSchemaError(f"section {section!r} is not valid JSON: {exc}") from exc


def normalize_info(raw: Any) -> RizinInfo:
    if not isinstance(raw, dict):
        raise RizinSchemaError("info section is not an object")
    try:
        return RizinInfo(arch=raw["arch"], bits=raw["bits"], endian=raw["endian"],
                         os=raw["os"])
    except (KeyError, ValidationError) as exc:
        raise RizinSchemaError(f"info section invalid: {exc}") from exc


def normalize_functions(raw: Any) -> list[RizinFunction]:
    if not isinstance(raw, list):
        raise RizinSchemaError("functions section is not a list")
    functions = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise RizinSchemaError(f"function {index} is not an object")
        try:
            functions.append(RizinFunction(
                name=entry["name"], offset=_normalize_offset(entry["offset"], "offset"),
                size=entry["size"], type=entry["type"]))
        except (KeyError, ValidationError) as exc:
            raise RizinSchemaError(f"function {index} invalid: {exc}") from exc
    if len({f.offset for f in functions}) != len(functions):
        raise RizinSchemaError("duplicate function offsets")
    return functions


def normalize_xrefs(raw: Any, target: str, direction: str) -> list[RizinXref]:
    if not isinstance(raw, list):
        raise RizinSchemaError("xref section is not a list")
    xrefs = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise RizinSchemaError(f"xref {index} is not an object")
        try:
            xref = RizinXref.model_validate({
                "from": _normalize_offset(entry["from"], "from"),
                "to": _normalize_offset(entry["to"], "to"),
                "type": entry["type"]})
        except (KeyError, ValidationError) as exc:
            raise RizinSchemaError(f"xref {index} invalid: {exc}") from exc
        expected_side = xref.to_addr if direction == "to" else xref.from_addr
        if expected_side != target:
            raise RizinSchemaError(
                f"xref {index} contradicts {direction}-query for {target}")
        xrefs.append(xref)
    return xrefs


def normalize_blocks(raw: Any) -> list[RizinBasicBlock]:
    if not isinstance(raw, list) or not raw:
        raise RizinSchemaError("basic block section is empty or not a list")
    blocks = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise RizinSchemaError(f"block {index} is not an object")
        try:
            blocks.append(RizinBasicBlock(
                offset=_normalize_offset(entry["offset"], "offset"),
                size=entry["size"],
                jump=None if entry.get("jump") in (None, "") else
                _normalize_offset(entry["jump"], "jump"),
                fail=None if entry.get("fail") in (None, "") else
                _normalize_offset(entry["fail"], "fail"),
                ninstr=entry["ninstr"]))
        except (KeyError, ValidationError) as exc:
            raise RizinSchemaError(f"block {index} invalid: {exc}") from exc
    if len({b.offset for b in blocks}) != len(blocks):
        raise RizinSchemaError("duplicate block offsets")
    offsets = [int(b.offset, 16) for b in blocks]
    if offsets != sorted(offsets):
        raise RizinSchemaError("block offsets are not ascending")
    for previous, following in zip(blocks, blocks[1:]):
        if int(previous.offset, 16) + previous.size > int(following.offset, 16):
            raise RizinSchemaError("overlapping basic blocks")
    return blocks


def normalize_cfg(raw: Any, target: str) -> RizinCfg:
    if not isinstance(raw, dict):
        raise RizinSchemaError("cfg section is not an object")
    try:
        blocks = normalize_blocks(raw["blocks"])
        offset = _normalize_offset(raw["offset"], "offset")
        if offset != target:
            raise RizinSchemaError(f"cfg offset {offset} != queried {target}")
        edges = []
        for index, entry in enumerate(raw["edges"]):
            if not isinstance(entry, dict):
                raise RizinSchemaError(f"edge {index} is not an object")
            edges.append(RizinEdge.model_validate({
                "src": _normalize_offset(entry["src"], "src"),
                "dst": _normalize_offset(entry["dst"], "dst"),
                "type": entry["type"]}))
        return RizinCfg(function=raw["name"], offset=offset, blocks=blocks, edges=edges)
    except (KeyError, ValidationError) as exc:
        raise RizinSchemaError(f"cfg section invalid: {exc}") from exc


def check_boundaries(blocks: list[RizinBasicBlock], function: Optional[RizinFunction]) -> None:
    """Cross-check block boundaries against the function range when known."""
    if function is None:
        return
    start = int(function.offset, 16)
    end = start + function.size
    for block in blocks:
        begin = int(block.offset, 16)
        if begin < start or begin + block.size > end:
            raise RizinSchemaError(
                f"block {block.offset} lies outside function {function.name} "
                f"({function.offset}+{function.size})")


class RizinAdapter:
    """Fail-closed rizin driver. Single attempt per invocation; no retries."""

    def __init__(self, config: RizinConfig) -> None:
        self.config = config
        self._version: Optional[str] = None
        self.runs: list[RizinRunRecord] = []
        self._last_functions: dict[str, RizinFunction] = {}

    # ------------------------------------------------------------------ plumbing
    def hash_artifact(self, path: str | Path) -> str:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()

    def health(self) -> dict[str, object]:
        result = subprocess.run([*self.config.rizin_cmd, "-v"], capture_output=True,
                                text=True, timeout=self.config.timeout_s, check=False)
        if result.returncode != 0:
            raise RizinRunError(result.returncode, result.stderr.strip()[:500])
        line = (result.stdout.strip().splitlines() or [""])[0]
        parts = line.split()
        version = parts[1] if len(parts) > 1 else line
        self._version = version
        return {"reachable": True, "version": version,
                "cmd": list(self.config.rizin_cmd)}

    def _invoke(self, commands: list[str], artifact: Path,
                stdout_path: Path) -> str:
        argv = [*self.config.rizin_cmd, "-q", "-e", "scr.color=0"]
        for command in commands:
            argv += ["-c", command]
        argv.append(str(artifact))
        try:
            result = subprocess.run(argv, capture_output=True, text=True,
                                    timeout=self.config.timeout_s, check=False)
        except subprocess.TimeoutExpired as exc:
            raise RizinTimeout(
                f"rizin invocation exceeded {self.config.timeout_s}s (process killed)") from exc
        if result.returncode != 0:
            if result.returncode == 7:
                raise RizinNotFound(
                    f"not a known function: {result.stderr.strip()[:200]}")
            raise RizinRunError(result.returncode, result.stderr.strip()[:500])
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text(result.stdout, encoding="utf-8")
        return result.stdout

    def _prepare(self, artifact_path: str | Path,
                 expected_artifact_sha256: Optional[str]) -> tuple[Path, str]:
        artifact = Path(artifact_path)
        if not artifact.is_file():
            raise RizinConfigError(f"artifact not found: {artifact}")
        digest = self.hash_artifact(artifact)
        if expected_artifact_sha256 is not None and digest != expected_artifact_sha256:
            raise RizinHashMismatch(
                f"artifact {digest} != expected {expected_artifact_sha256} "
                "(refused before invocation)")
        if self._version is None:
            self.health()
        return artifact, digest

    def _record(self, *, artifact: Path, digest: str, kind: str, sections: list[str],
                cmd: list[str], stdout_path: Path, started: datetime,
                ended: datetime, target: Optional[str] = None,
                direction: Optional[str] = None, functions_count: int = 0,
                xrefs_count: int = 0, blocks_count: int = 0,
                edges_count: int = 0) -> RizinRunRecord:
        digest_stdout = hashlib.sha256(stdout_path.read_bytes()).hexdigest()
        record = RizinRunRecord(
            artifact_path=str(artifact), artifact_sha256=digest,
            rizin_version=self._version or "unknown", query_kind=kind,
            query_target=target, query_direction=direction, cmd=cmd,
            started_at=started, ended_at=ended, stdout_path=str(stdout_path),
            stdout_sha256=digest_stdout, sections=sections,
            functions_count=functions_count, xrefs_count=xrefs_count,
            blocks_count=blocks_count, edges_count=edges_count)
        self.runs.append(record)
        return record

    def _stdout_path(self, digest: str, stem: str,
                     stdout_path: Optional[str | Path],
                     target: Optional[str] = None) -> Path:
        """Unique per (kind, target): two queries must never share an evidence file."""
        if stdout_path is not None:
            return Path(stdout_path)
        name = f"{digest[:8]}-{stem}" + (f"-{target}" if target else "")
        return Path(self.config.work_dir) / f"{name}.stdout.txt"

    def _commands(self, section: str, payload_command: str) -> list[str]:
        return ["aaa", f"?e {MARKER_TEMPLATE.format(section)}", payload_command]

    # ------------------------------------------------------------------- methods
    def analyze(self, artifact_path: str | Path, *,
                expected_artifact_sha256: Optional[str] = None,
                stdout_path: Optional[str | Path] = None) -> RizinAnalysis:
        artifact, digest = self._prepare(artifact_path, expected_artifact_sha256)
        out = self._stdout_path(digest, "analyze", stdout_path)
        commands = self._commands("info", "ij") + \
            self._commands("functions", "aflj")[1:]
        started = datetime.now(timezone.utc)
        stdout = self._invoke(commands, artifact, out)
        ended = datetime.now(timezone.utc)
        sections = split_sections(stdout, _QUERY_SECTIONS["analyze"])
        info = normalize_info(_json_of(sections["info"], "info"))
        functions = normalize_functions(_json_of(sections["functions"], "functions"))
        self._last_functions = {f.offset: f for f in functions}
        run = self._record(artifact=artifact, digest=digest, kind="analyze",
                           sections=list(_QUERY_SECTIONS["analyze"]), cmd=commands,
                           stdout_path=out, started=started, ended=ended,
                           functions_count=len(functions))
        return RizinAnalysis(info=info, functions=functions, run=run)

    def xrefs(self, address: str, direction: str = "to", *,
              expected_artifact_sha256: Optional[str] = None,
              artifact_path: str | Path | None = None,
              stdout_path: Optional[str | Path] = None) -> RizinXrefResult:
        """Xrefs to/from ``address``. ``artifact_path`` defaults to the last analysis."""
        if direction not in ("to", "from"):
            raise RizinConfigError("direction must be 'to' or 'from'")
        target = _address(address)
        artifact, digest = self._prepare(self._artifact_or_last(artifact_path),
                                         expected_artifact_sha256)
        out = self._stdout_path(digest, "xrefs-" + direction, stdout_path, target)
        command = f"{'axtj' if direction == 'to' else 'axfj'} @ {target}"
        commands = self._commands("xr", command)
        started = datetime.now(timezone.utc)
        stdout = self._invoke(commands, artifact, out)
        ended = datetime.now(timezone.utc)
        sections = split_sections(stdout, _QUERY_SECTIONS["xrefs"])
        xrefs = normalize_xrefs(_json_of(sections["xr"], "xr"), target, direction)
        run = self._record(artifact=artifact, digest=digest, kind="xrefs",
                           sections=list(_QUERY_SECTIONS["xrefs"]), cmd=commands,
                           stdout_path=out, started=started, ended=ended,
                           target=target, direction=direction, xrefs_count=len(xrefs))
        return RizinXrefResult(xrefs=xrefs, run=run)

    def cfg(self, address: str, *,
            expected_artifact_sha256: Optional[str] = None,
            artifact_path: str | Path | None = None,
            stdout_path: Optional[str | Path] = None) -> RizinCfgResult:
        target = _address(address)
        artifact, digest = self._prepare(self._artifact_or_last(artifact_path),
                                         expected_artifact_sha256)
        out = self._stdout_path(digest, "cfg", stdout_path, target)
        commands = self._commands("cfg", f"agfj @ {target}")
        started = datetime.now(timezone.utc)
        stdout = self._invoke(commands, artifact, out)
        ended = datetime.now(timezone.utc)
        sections = split_sections(stdout, _QUERY_SECTIONS["cfg"])
        cfg = normalize_cfg(_json_of(sections["cfg"], "cfg"), target)
        run = self._record(artifact=artifact, digest=digest, kind="cfg",
                           sections=list(_QUERY_SECTIONS["cfg"]), cmd=commands,
                           stdout_path=out, started=started, ended=ended,
                           target=target, blocks_count=len(cfg.blocks),
                           edges_count=len(cfg.edges))
        return RizinCfgResult(cfg=cfg, run=run)

    def boundaries(self, address: str, *,
                   expected_artifact_sha256: Optional[str] = None,
                   artifact_path: str | Path | None = None,
                   stdout_path: Optional[str | Path] = None) -> RizinBoundariesResult:
        target = _address(address)
        artifact, digest = self._prepare(self._artifact_or_last(artifact_path),
                                         expected_artifact_sha256)
        out = self._stdout_path(digest, "boundaries", stdout_path, target)
        commands = self._commands("bb", f"afbj @ {target}")
        started = datetime.now(timezone.utc)
        stdout = self._invoke(commands, artifact, out)
        ended = datetime.now(timezone.utc)
        sections = split_sections(stdout, _QUERY_SECTIONS["boundaries"])
        blocks = normalize_blocks(_json_of(sections["bb"], "bb"))
        function = self._last_functions.get(target)
        check_boundaries(blocks, function)
        name = function.name if function is not None else "unknown"
        run = self._record(artifact=artifact, digest=digest, kind="boundaries",
                           sections=list(_QUERY_SECTIONS["boundaries"]), cmd=commands,
                           stdout_path=out, started=started, ended=ended,
                           target=target, blocks_count=len(blocks))
        return RizinBoundariesResult(function=name, offset=target, blocks=blocks,
                                     run=run)

    # ------------------------------------------------------------------- helpers
    def _last_artifact(self) -> Optional[str]:
        return self.runs[-1].artifact_path if self.runs else None

    def _artifact_or_last(self, artifact_path: str | Path | None) -> str | Path:
        resolution = artifact_path or self._last_artifact()
        if resolution is None:
            raise RizinConfigError(
                "no artifact given and no previous run to fall back to")
        return resolution


def verify_run_record(record: RizinRunRecord) -> bool:
    """Re-read, re-parse, re-validate and recount a recorded invocation."""
    def fail(message: str) -> Never:
        raise RizinEvidenceError(message)

    artifact = Path(record.artifact_path)
    if not artifact.is_file():
        fail(f"artifact missing: {artifact}")
    actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if actual != record.artifact_sha256:
        fail(f"artifact hash mismatch: {actual} != {record.artifact_sha256}")
    stdout_path = Path(record.stdout_path)
    if not stdout_path.is_file():
        fail(f"stdout file missing: {stdout_path}")
    raw = stdout_path.read_text(encoding="utf-8")
    actual_stdout = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    if actual_stdout != record.stdout_sha256:
        fail(f"stdout hash mismatch: {actual_stdout} != {record.stdout_sha256}")
    expected = _QUERY_SECTIONS.get(record.query_kind)
    if expected is None:
        fail(f"unknown query kind {record.query_kind!r}")
    if list(record.sections) != list(expected):
        fail("recorded sections do not match the query kind")
    try:
        sections = split_sections(raw, expected)
        functions_count = xrefs_count = blocks_count = edges_count = 0
        if record.query_kind == "analyze":
            normalize_info(_json_of(sections["info"], "info"))
            functions_count = len(normalize_functions(
                _json_of(sections["functions"], "functions")))
        elif record.query_kind == "xrefs":
            assert record.query_target is not None
            xrefs_count = len(normalize_xrefs(
                _json_of(sections["xr"], "xr"), record.query_target,
                record.query_direction or "to"))
        elif record.query_kind == "cfg":
            assert record.query_target is not None
            cfg = normalize_cfg(_json_of(sections["cfg"], "cfg"), record.query_target)
            blocks_count, edges_count = len(cfg.blocks), len(cfg.edges)
        elif record.query_kind == "boundaries":
            blocks = normalize_blocks(_json_of(sections["bb"], "bb"))
            blocks_count = len(blocks)
    except (RizinSchemaError,) as exc:
        fail(f"stdout failed re-validation: {exc}")
    if (functions_count, xrefs_count, blocks_count, edges_count) != \
            (record.functions_count, record.xrefs_count, record.blocks_count,
             record.edges_count):
        fail("recomputed counts do not match the record")
    return True
