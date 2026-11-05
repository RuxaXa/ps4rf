"""MSF adapter: msfrpcd/MessagePack-RPC transport for PS4RF (spec v0.3 §12, P2).

Role and boundaries (§12.1/§12.3):

* Metasploit is an *external* exploit/auxiliary/session backend. It is never the
  source of truth for profiles, capabilities, experiments, evidence, resources or
  candidate states. This adapter only translates; PS4RF remains authoritative.
* Transport is msfrpcd/MessagePack-RPC only -- no ``msfconsole`` parsing. The
  endpoint must be loopback or TLS (§12.1).
* The auth token comes from an environment variable, is read per call, and is
  never stored, logged, returned or embedded in evidence. Module options are
  redacted via :mod:`tools.metasploit.redact` (N4: ``<redacted>``, no
  secret-derived hash or fingerprint).
* No automatic retries anywhere (§12.5/§49): every call is a single attempt;
  errors surface as typed exceptions. Nothing is chained implicitly
  (no check->run, no run->verify).

Evidence: every module run yields a :class:`MetasploitRunRecord` (§12.4 + N4)
bound to its raw output via SHA-256.
"""

from __future__ import annotations

import hashlib
import http.client
import os
import ssl
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import msgpack
from pydantic import Field, model_validator

from core.canonical import canonical_bytes
from core.models.common import EvidenceRef, RunId, Sha256, StrictModel
from tools.metasploit.redact import options_sha256, redact_options

RPC_PATH = "/api/"
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")


class MsfError(Exception):
    """Base class for adapter failures."""


class MsfConfigError(MsfError):
    """Invalid endpoint configuration (e.g. non-local without TLS)."""


class MsfTokenMissing(MsfError):
    """No token in the configured environment variable."""


class MsfTransportError(MsfError):
    """Endpoint unreachable / HTTP-level failure (single attempt, no retry)."""


class MsfRpcError(MsfError):
    """msfrpcd returned a JSON-RPC error object."""

    def __init__(self, code: int, message: str) -> None:
        self.code, self.message = code, message
        super().__init__(f"msfrpcd error {code}: {message}")


class MsfSessionNotOwned(MsfError):
    """session_command/session_close called for a session this adapter did not open."""


class MsfEvidenceError(MsfError):
    """Run record failed its hash / redaction re-check."""


class ExploitResult(str, Enum):
    NOT_RUN = "NOT_RUN"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    DEAD_TARGET = "DEAD_TARGET"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


class CheckResult(str, Enum):
    NOT_RUN = "NOT_RUN"
    VULNERABLE = "VULNERABLE"
    PATCHED = "PATCHED"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


# msfrpcd check codes -> PS4RF check result (v0.1 mapping)
_CHECK_MAP = {
    "vulnerable": CheckResult.VULNERABLE,
    "safe": CheckResult.PATCHED,
    "detected": CheckResult.UNKNOWN,   # service present, vulnerability not confirmed
    "unknown": CheckResult.UNKNOWN,
    "error": CheckResult.ERROR,
}

# module.execute result field -> exploit result (v0.1 mapping)
_RESULT_MAP = {
    "success": ExploitResult.SUCCESS,
    "failure": ExploitResult.FAILED,
    "failed": ExploitResult.FAILED,
    "dead": ExploitResult.DEAD_TARGET,
    "timeout": ExploitResult.TIMEOUT,
    "error": ExploitResult.ERROR,
}

REDACTED = "<redacted>"


# msfrpcd module listing methods by kind (real daemon naming)
MODULE_LIST_METHOD = {
    "exploit": "module.exploits",
    "auxiliary": "module.auxiliary",
    "post": "module.post",
}


class MsfConfig(StrictModel):
    """msfrpcd endpoint configuration. Loopback unless TLS is enabled (§12.1)."""

    host: str = "127.0.0.1"
    port: int = Field(default=55553, ge=1, le=65535)
    tls: bool = False
    path: str = RPC_PATH
    token_env: str = "PS4RF_MSF_TOKEN"
    timeout_s: float = Field(default=10.0, gt=0)

    @model_validator(mode="after")
    def _endpoint_policy(self) -> "MsfConfig":
        if not self.tls and self.host not in LOCAL_HOSTS:
            raise ValueError("non-local msfrpcd endpoint requires TLS (spec §12.1)")
        if not self.path.startswith("/"):
            raise ValueError("path must be absolute")
        return self

    @property
    def endpoint(self) -> str:
        scheme = "https" if self.tls else "http"
        return f"{scheme}://{self.host}:{self.port}{self.path}"


class MetasploitRunRecord(StrictModel):
    """Evidence record of one msf module run (§12.4, options redacted per N4)."""

    module: str
    framework_revision: str
    started_at: datetime
    ended_at: datetime
    exploit_result: ExploitResult = ExploitResult.NOT_RUN
    check_result: CheckResult = CheckResult.NOT_RUN
    options: dict[str, Any] = Field(default_factory=dict)
    redacted_fields: list[str] = Field(default_factory=list)
    options_sha256: Sha256
    job_id: Optional[int] = None
    session_id: Optional[str] = None
    output_sha256: Optional[Sha256] = None
    output_path: Optional[str] = None
    ps4rf_verification: Optional[EvidenceRef] = None
    candidate_id: Optional[str] = None
    related_run_id: Optional[RunId] = None


class MetasploitAdapter:
    """Thin, fail-closed msfrpcd client. Single attempt per call; no retries."""

    def __init__(self, config: Optional[MsfConfig] = None) -> None:
        self.config = config or MsfConfig()
        self._request_id = 0
        self._revision: Optional[str] = None
        self.owned_sessions: set[str] = set()
        self.call_log: list[str] = []            # method names only, never params
        self.session_log: list[dict[str, Any]] = []

    # ------------------------------------------------------------------ plumbing
    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _call(self, method: str, params: Optional[list[Any]] = None) -> Any:
        token = os.environ.get(self.config.token_env)
        if not token:
            raise MsfTokenMissing(
                f"no token in environment variable {self.config.token_env!r} "
                "(values never live in files or logs; spec §12.1)")
        body = msgpack.packb(
            {"jsonrpc": "2.0", "method": method, "params": [token, *(params or [])],
             "id": self._next_id()},
            use_bin_type=True)
        assert body is not None
        conn = self._connect()
        try:
            conn.request("POST", self.config.path, body=body,
                         headers={"Content-Type": "binary/message-pack",
                                  "Accept": "binary/message-pack"})
            response = conn.getresponse()
            raw = response.read()
            status = response.status
        except (OSError, http.client.HTTPException) as exc:
            raise MsfTransportError(f"{method}: {exc}") from exc
        finally:
            conn.close()
        if status != 200:
            raise MsfTransportError(f"{method}: HTTP {status}")
        try:
            document = msgpack.unpackb(raw, raw=False, strict_map_key=False)
        except Exception as exc:  # noqa: BLE001 - malformed payload from endpoint
            raise MsfTransportError(f"{method}: invalid message pack response") from exc
        self.call_log.append(method)
        error = document.get("error") if isinstance(document, dict) else None
        if error:
            raise MsfRpcError(int(error.get("code", -1)), str(error.get("message", "?")))
        return document.get("result")

    def _connect(self) -> http.client.HTTPConnection:
        if self.config.tls:
            return http.client.HTTPSConnection(
                self.config.host, self.config.port, timeout=self.config.timeout_s,
                context=ssl.create_default_context())
        return http.client.HTTPConnection(self.config.host, self.config.port,
                                          timeout=self.config.timeout_s)

    def _framework_revision(self) -> str:
        if self._revision is None:
            self.health()
        assert self._revision is not None
        return self._revision

    # ------------------------------------------------------------------- methods
    def health(self) -> dict[str, Any]:
        """Reachability + core.version. Revision is bound per run in evidence."""
        version = self._call("core.version") or {}
        self._revision = str(version.get("version", "unknown"))
        return {"reachable": True, "endpoint": self.config.endpoint,
                "version": self._revision, "ruby": version.get("ruby"),
                "api": version.get("api")}

    def list_modules(self, kind: Optional[str] = None) -> list[str]:
        """List module refs. ``kind`` in {exploit, auxiliary, post} or None."""
        kinds = [kind] if kind else list(MODULE_LIST_METHOD)
        refs: list[str] = []
        for k in kinds:
            try:
                method = MODULE_LIST_METHOD[k]
            except KeyError:
                raise MsfConfigError(f"unknown module kind: {k!r}") from None
            refs.extend(self._call(method) or [])
        return sorted(refs)

    def module_info(self, kind: str, ref: str) -> dict[str, Any]:
        return self._call("module.info", [kind, ref]) or {}

    def module_check(self, kind: str, ref: str,
                     options: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Non-exploiting check. Returns ``{check_result, code, message}``."""
        raw = self._call("module.check", [kind, ref, options or {}]) or {}
        code = str(raw.get("code", "unknown"))
        return {"check_result": _CHECK_MAP.get(code, CheckResult.UNKNOWN),
                "code": code, "message": str(raw.get("message", ""))}

    def module_run(self, kind: str, ref: str,
                   options: Optional[dict[str, Any]] = None, *,
                   dry_run: bool = True,
                   output_path: Optional[str] = None,
                   ps4rf_verification: Optional[EvidenceRef] = None,
                   candidate_id: Optional[str] = None,
                   related_run_id: Optional[RunId] = None) -> MetasploitRunRecord:
        """Run a module (``dry_run=True`` performs only ``module.check``).

        Never chains checks or verification; never retries. Sessions opened by
        this run are adopted so that ``session_command``/``session_close`` stay
        restricted to PS4RF-initiated sessions (§12.5).
        """
        options = dict(options or {})
        revision = self._framework_revision()
        started = datetime.now(timezone.utc)
        clean, redacted = redact_options(options)
        record = MetasploitRunRecord(
            module=ref, framework_revision=revision, started_at=started,
            ended_at=started, options=clean, redacted_fields=redacted,
            options_sha256=options_sha256(options), ps4rf_verification=ps4rf_verification,
            candidate_id=candidate_id, related_run_id=related_run_id)
        if dry_run:
            check = self.module_check(kind, ref, options)
            record = record.model_copy(update={
                "ended_at": datetime.now(timezone.utc),
                "check_result": check["check_result"]})
            payload = {"mode": "dry_run", "check_code": check["code"],
                       "check_result": check["check_result"].value,
                       "message": check["message"]}
            return self._maybe_write_output(record, output_path, payload)
        before = set(self.list_sessions())
        result = self._call("module.execute", [kind, ref, options]) or {}
        after = set(self.list_sessions())
        new_sessions = sorted(after - before)
        self.owned_sessions.update(new_sessions)
        exploit_result = _RESULT_MAP.get(str(result.get("result", "error")),
                                         ExploitResult.ERROR)
        record = record.model_copy(update={
            "ended_at": datetime.now(timezone.utc),
            "exploit_result": exploit_result,
            "job_id": int(result["job_id"]) if result.get("job_id") is not None else None,
            "session_id": new_sessions[0] if len(new_sessions) == 1 else None})
        payload = {"mode": "execute",
                   "job_id": result.get("job_id"),
                   "result": str(result.get("result", "error")),
                   "new_sessions": new_sessions}
        return self._maybe_write_output(record, output_path, payload)

    def list_jobs(self) -> list[dict[str, Any]]:
        jobs = self._call("job.list") or {}
        out = [{"job_id": int(job_id), "module": str(module)}
               for job_id, module in jobs.items()]
        return sorted(out, key=lambda job: job["job_id"])

    def stop_job(self, job_id: int) -> dict[str, Any]:
        return self._call("job.stop", [job_id]) or {}

    def list_sessions(self) -> dict[str, dict[str, Any]]:
        return self._call("session.list") or {}

    def session_info(self, session_id: str) -> dict[str, Any]:
        return self._call("session.info", [session_id]) or {}

    def session_command(self, session_id: str, command: str) -> str:
        """Run a command on a PS4RF-owned session; fully logged, single attempt."""
        self._require_owned(session_id)
        self._call("session.shell_write", [session_id, command])
        response = self._call("session.shell_read", [session_id]) or {}
        data = str(response.get("data", ""))
        self.session_log.append({
            "session_id": session_id, "command": command,
            "response_sha256": hashlib.sha256(data.encode("utf-8")).hexdigest(),
            "at": datetime.now(timezone.utc).isoformat()})
        return data

    def session_close(self, session_id: str) -> dict[str, Any]:
        self._require_owned(session_id)
        result = self._call("session.stop", [session_id]) or {}
        self.owned_sessions.discard(session_id)
        return result

    # ------------------------------------------------------------------- helpers
    def _require_owned(self, session_id: str) -> None:
        if session_id not in self.owned_sessions:
            raise MsfSessionNotOwned(
                f"session {session_id!r} was not opened by this adapter run (§12.5)")

    def _maybe_write_output(self, record: MetasploitRunRecord,
                            output_path: Optional[str],
                            payload: dict[str, Any]) -> MetasploitRunRecord:
        if output_path is None:
            return record
        blob = canonical_bytes(payload)
        with open(output_path, "wb") as handle:
            handle.write(blob)
        return record.model_copy(update={
            "output_path": str(output_path),
            "output_sha256": hashlib.sha256(blob).hexdigest()})


def verify_run_record(record: MetasploitRunRecord) -> bool:
    """Re-check a run record: output hash binding + N4 redaction invariants.

    Raises :class:`MsfEvidenceError` on mismatch, returns True otherwise.
    """
    if record.output_path is not None:
        if record.output_sha256 is None:
            raise MsfEvidenceError("output_path without output_sha256")
        with open(record.output_path, "rb") as handle:
            actual = hashlib.sha256(handle.read()).hexdigest()
        if actual != record.output_sha256:
            raise MsfEvidenceError(
                f"output hash mismatch: {actual} != {record.output_sha256}")
    for field in record.redacted_fields:
        if field not in record.options or record.options[field] != REDACTED:
            raise MsfEvidenceError(f"redaction missing for {field!r}")
    if options_sha256(record.options) != record.options_sha256:
        raise MsfEvidenceError(
            "options_sha256 does not match the redacted options object (N4)")
    return True
