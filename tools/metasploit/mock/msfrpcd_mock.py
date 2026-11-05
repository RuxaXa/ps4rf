"""Offline mock of an msfrpcd-compatible MessagePack-RPC endpoint (P2, spec v0.3 §12).

Scope: exactly the msfrpcd surface that :mod:`tools.metasploit.adapter` drives.
No real Metasploit, no external network -- loopback only (spec §12.1: "TLS oder
localhost"). TLS is intentionally not implemented in the mock; the adapter still
refuses non-local endpoints unless TLS is configured.

Wire format (v0.1, documented assumption -- matches the de-facto msfrpcd client
behaviour of JSON-RPC-2.0-over-MessagePack):

* HTTP ``POST /api/`` with ``Content-Type: binary/message-pack``
* Request body: MessagePack map ``{"jsonrpc": "2.0", "method": <str>,
  "params": [<token>, ...], "id": <int>}`` -- the auth token is ``params[0]``
  on every call.
* Response body: MessagePack map ``{"jsonrpc": "2.0", "id": <int>,
  "result": ...}`` or ``{"jsonrpc": "2.0", "id": <int>, "error":
  {"code": <int>, "message": <str>}}``.

Secret handling (N4 / §12.1): the token is read from the environment at request
time and compared in memory. It is never echoed in a response, never written to
the call log (method names only) and never persisted anywhere.

Deterministic behaviour for offline tests: no randomness beyond UUIDs, job and
session ids; ``fail_next()`` injects a one-shot RPC error; ``set_check_result()``
overrides a catalog check code.
"""

from __future__ import annotations

import collections
import http.server
import os
import threading
import time
import uuid
from typing import Any, Optional

import msgpack

RPC_PATH = "/api/"

# JSON-RPC style error codes used by the mock (stable contract for tests).
ERR_AUTH_FAILED = -32001
ERR_MODULE_NOT_FOUND = -32002
ERR_SESSION_NOT_FOUND = -32003
ERR_TOKEN_UNCONFIGURED = -32004
ERR_INJECTED = -32099
ERR_METHOD_NOT_FOUND = -32601

DEFAULT_CATALOG: dict[str, dict[str, Any]] = {
    "exploit/ps4/browser/example": {
        "type": "exploit",
        "name": "PS4 Browser Example (mock)",
        "rank": "normal",
        "description": "Synthetic mock module; no real exploit content.",
        "check": "vulnerable",
        "creates_session": True,
    },
    "auxiliary/ps4/example_probe": {
        "type": "auxiliary",
        "name": "PS4 Example Probe (mock)",
        "rank": "normal",
        "description": "Synthetic mock auxiliary module; availability signal only.",
        "check": "detected",
        "creates_session": False,
    },
    "post/ps4/example_status": {
        "type": "post",
        "name": "PS4 Example Status (mock)",
        "rank": "normal",
        "description": "Synthetic mock post module running inside a session.",
        "check": "safe",
        "creates_session": False,
    },
}

_PUBLIC_SESSION_FIELDS = (
    "type", "tunnel_local", "tunnel_peer", "via_exploit", "via_payload",
    "desc", "info", "workspace", "session_host", "session_port", "opened_at",
)


def _pack(obj: Any) -> bytes:
    packed = msgpack.packb(obj, use_bin_type=True)
    assert packed is not None
    return packed


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ps4rf-msfrpcd-mock/0.1"

    # The owning MockMsfRpc instance is injected by the server factory.
    mock: "MockMsfRpc"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - base signature
        return

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        if self.path != RPC_PATH:
            self._respond(404, _pack(
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": ERR_METHOD_NOT_FOUND, "message": "path.not_found"}}))
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length else b""
        try:
            request = msgpack.unpackb(body, raw=False, strict_map_key=False)
            response = self.mock.handle_request(request)
        except Exception:  # noqa: BLE001 - mock must never crash the test run
            response = {"jsonrpc": "2.0", "id": None,
                        "error": {"code": ERR_METHOD_NOT_FOUND, "message": "request.invalid"}}
        self._respond(200, _pack(response))

    def _respond(self, status: int, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "binary/message-pack")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class MockMsfRpc:
    """Offline msfrpcd mock. Loopback only; token comes from the environment."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 token_env: str = "PS4RF_MSF_TOKEN",
                 catalog: Optional[dict[str, dict[str, Any]]] = None) -> None:
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("mock is loopback-only (spec §12.1)")
        self.host, self.token_env = host, token_env
        self.catalog = {k: dict(v) for k, v in (catalog or DEFAULT_CATALOG).items()}
        self._lock = threading.Lock()
        self._httpd: Optional[_Server] = None
        self._thread: Optional[threading.Thread] = None
        self._requested_port = port
        # observable state for tests / evidence
        self.call_counts: collections.Counter = collections.Counter()
        self.call_log: list[str] = []          # method names only, never params
        self._fail_next: collections.Counter = collections.Counter()
        self._jobs: dict[int, dict[str, Any]] = {}
        self._sessions: dict[str, dict[str, Any]] = {}
        self._job_seq = 0
        self._session_seq = 0

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> str:
        """Start the loopback server; returns the base URL."""
        handler = type("_BoundHandler", (_Handler,), {"mock": self})
        self._httpd = _Server((self.host, self._requested_port), handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        name="msfrpcd-mock", daemon=True)
        self._thread.start()
        return self.url

    def stop(self) -> None:
        httpd, thread = self._httpd, self._thread
        self._httpd = self._thread = None
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        if thread is not None:
            thread.join(timeout=5)

    def __enter__(self) -> "MockMsfRpc":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    @property
    def url(self) -> str:
        if self._httpd is None:
            raise RuntimeError("mock not started")
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def port(self) -> int:
        if self._httpd is None:
            raise RuntimeError("mock not started")
        return int(self._httpd.server_address[1])

    # ------------------------------------------------------------- test controls
    def fail_next(self, method: str, times: int = 1) -> None:
        """Inject ``times`` one-shot errors for ``method`` (no retry target)."""
        with self._lock:
            self._fail_next[method] += times

    def set_check_result(self, ref: str, code: str) -> None:
        with self._lock:
            self.catalog[ref]["check"] = code

    def override_result(self, ref: str, result: str) -> None:
        """Force the ``result`` field of ``module.execute`` for ``ref``."""
        with self._lock:
            self.catalog[ref]["result"] = result

    @property
    def sessions(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {sid: dict(s) for sid, s in self._sessions.items()}

    # ------------------------------------------------------------------ dispatch
    def handle_request(self, request: Any) -> dict[str, Any]:
        rid = request.get("id") if isinstance(request, dict) else None
        if not isinstance(request, dict) or request.get("method") is None:
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": ERR_METHOD_NOT_FOUND, "message": "request.invalid"}}
        method = request["method"]
        params = list(request.get("params") or [])
        with self._lock:
            self.call_counts[method] += 1
            self.call_log.append(method)
            injected = self._fail_next.get(method, 0)
            if injected:
                self._fail_next[method] = injected - 1
        if injected:
            return self._error(rid, ERR_INJECTED, "mock.injected_failure")
        token = params[0] if params else None
        expected = os.environ.get(self.token_env)
        if expected is None:
            return self._error(rid, ERR_TOKEN_UNCONFIGURED, "auth.token_unavailable")
        if token != expected:
            return self._error(rid, ERR_AUTH_FAILED, "auth.invalid")
        args = params[1:]
        try:
            handler = self._METHODS[method]
        except KeyError:
            return self._error(rid, ERR_METHOD_NOT_FOUND, "method.not_found")
        try:
            result = handler(self, *args)
        except _RpcError as exc:
            return self._error(rid, exc.code, exc.message)
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    @staticmethod
    def _error(rid: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}

    # ------------------------------------------------------------------- methods
    def _auth_login(self, *_args: Any) -> dict[str, Any]:
        # Token already validated by the dispatcher; never echo it.
        return {"result": "success"}

    def _core_version(self, *_args: Any) -> dict[str, Any]:
        return {"version": "6.4.0-mock", "ruby": "3.2.0-mock", "api": "1.0"}

    def _module_list(self, kind: str, *_args: Any) -> list[str]:
        with self._lock:
            return sorted(ref for ref, spec in self.catalog.items() if spec["type"] == kind)

    def _module_info(self, kind: str, ref: str, *_args: Any) -> dict[str, Any]:
        spec = self._lookup(kind, ref)
        return {"name": ref, "type": spec["type"], "rank": spec["rank"],
                "description": spec["description"], "default_options": {}}

    def _module_check(self, kind: str, ref: str, _options: Any = None,
                      *_args: Any) -> dict[str, Any]:
        spec = self._lookup(kind, ref)
        return {"code": spec["check"], "message": f"mock check for {ref}"}

    def _module_execute(self, kind: str, ref: str, _options: Any = None,
                        *_args: Any) -> dict[str, Any]:
        spec = self._lookup(kind, ref)
        with self._lock:
            self._job_seq += 1
            job_id = self._job_seq
            self._jobs[job_id] = {"module": ref, "status": "completed",
                                  "result": spec.get("result", "success")}
            session_id = None
            if spec["creates_session"]:
                self._session_seq += 1
                session_id = str(self._session_seq)
                self._sessions[session_id] = {
                    "type": "shell", "tunnel_local": "127.0.0.1:4444",
                    "tunnel_peer": "127.0.0.1:55555", "via_exploit": ref,
                    "via_payload": "generic/mock", "desc": "mock session",
                    "info": "mock session", "workspace": "default",
                    "session_host": "192.0.2.10", "session_port": 22,
                    "opened_at": int(time.time()), "last_command": None,
                }
        out: dict[str, Any] = {"job_id": job_id, "uuid": uuid.uuid4().hex[:32],
                               "result": self._jobs[job_id]["result"]}
        if session_id is not None:
            out["session_id"] = session_id
        return out

    def _job_list(self, *_args: Any) -> dict[str, str]:
        with self._lock:
            return {str(jid): job["module"] for jid, job in self._jobs.items()}

    def _job_stop(self, job_id: Any, *_args: Any) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(int(job_id))
            if job is None:
                raise _RpcError(ERR_MODULE_NOT_FOUND, "job.not_found")
            job["status"] = "stopped"
        return {"result": "success"}

    def _session_list(self, *_args: Any) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {sid: self._public_session(s) for sid, s in self._sessions.items()}

    def _session_info(self, session_id: Any, *_args: Any) -> dict[str, Any]:
        with self._lock:
            session = self._sessions.get(str(session_id))
            if session is None:
                raise _RpcError(ERR_SESSION_NOT_FOUND, "session.not_found")
            return self._public_session(session)

    def _session_shell_write(self, session_id: Any, data: Any,
                             *_args: Any) -> dict[str, Any]:
        payload = "" if data is None else str(data)
        with self._lock:
            session = self._sessions.get(str(session_id))
            if session is None:
                raise _RpcError(ERR_SESSION_NOT_FOUND, "session.not_found")
            session["last_command"] = payload
            return {"write_count": len(payload)}

    def _session_shell_read(self, session_id: Any, *_args: Any) -> dict[str, Any]:
        with self._lock:
            session = self._sessions.get(str(session_id))
            if session is None:
                raise _RpcError(ERR_SESSION_NOT_FOUND, "session.not_found")
            command = session.get("last_command")
            data = "" if command is None else f"mock-session-{session_id}$ {command}\n"
            return {"data": data}

    def _session_stop(self, session_id: Any, *_args: Any) -> dict[str, Any]:
        with self._lock:
            if str(session_id) not in self._sessions:
                raise _RpcError(ERR_SESSION_NOT_FOUND, "session.not_found")
            del self._sessions[str(session_id)]
        return {"result": "success"}

    # ------------------------------------------------------------------- helpers
    def _lookup(self, kind: str, ref: str) -> dict[str, Any]:
        with self._lock:
            spec = self.catalog.get(ref)
        if spec is None or spec["type"] != kind:
            raise _RpcError(ERR_MODULE_NOT_FOUND, "module.not_found")
        return spec

    @staticmethod
    def _public_session(session: dict[str, Any]) -> dict[str, Any]:
        return {k: session[k] for k in _PUBLIC_SESSION_FIELDS if k in session}

    _METHODS = {
        "auth.login": _auth_login,
        "core.version": _core_version,
        "module.exploits": lambda self, *a: self._module_list("exploit", *a),
        "module.auxiliary": lambda self, *a: self._module_list("auxiliary", *a),
        "module.post": lambda self, *a: self._module_list("post", *a),
        "module.info": _module_info,
        "module.check": _module_check,
        "module.execute": _module_execute,
        "job.list": _job_list,
        "job.stop": _job_stop,
        "session.list": _session_list,
        "session.info": _session_info,
        "session.shell_write": _session_shell_write,
        "session.shell_read": _session_shell_read,
        "session.stop": _session_stop,
    }


class _RpcError(Exception):
    def __init__(self, code: int, message: str) -> None:
        self.code, self.message = code, message
        super().__init__(f"{message} ({code})")
