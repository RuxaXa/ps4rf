"""Host side of the W14 resident daemon: the offline controller.

The resident agent dials out (``platform_connect``), so the controller's job is to **listen per
session**: open a listener, accept the agent's connection, run the frozen session (handshake,
READY, REQUEST/RESPONSE, BYE) and close again. There is no agent-side listener and no agent-side
port, so nothing here may assume an inbound connection to the console.

Two connections are meaningful per session:

* the **session connection** -- the accept that becomes a session, and
* a **further connection** while a session is active -- §13 caps the agent at *one* active
  research session, so this connection carries the ``SESSION_BUSY`` notice instead of a session.

The notice is written *before* any handshake, so it cannot be authenticated; it carries no
authority at all. This module parses it strictly and only reports it -- it never lets a notice
influence session state, evidence or an operation decision. A notice is information about why a
connection was closed, nothing more.
"""

from __future__ import annotations

import json
import pathlib
import socket
import struct
import subprocess
import time

from tools.hostctl import session as S

BUSY_MSG = 'SESSION_BUSY'
BUSY_NOTICE_VERSION = 'ps4rfd-daemon-w14'
#: the complete field set of the notice (a notice with any other shape is not one)
BUSY_NOTICE_KEYS = ('active_sessions', 'agent_version', 'build_id', 'msg', 'sessions_served',
                    'state')
BUSY_NOTICE_MAX = 512
#: the notice exists only while a session is active: a refusal names that, never a session id
BUSY_NOTICE_ACTIVE_SESSIONS = 1
#: states a *refusal* may name: the agent refuses because it is not idle
BUSY_REFUSAL_STATES = ('BOOTSTRAP', 'SESSION_ACTIVE', 'SESSION_CLEANUP', 'RESIDENT_IDLE')

#: the daemon report vocabulary (native/target/ps4rf_daemon.h)
DAEMON_STATES = ('BOOTSTRAP', 'RESIDENT_IDLE', 'SESSION_ACTIVE', 'SESSION_CLEANUP', 'EXITED')
DAEMON_EXIT_REASONS = ('NONE', 'ADMIN_SHUTDOWN', 'PROTOCOL_CORRUPTION',
                       'RECOVERY_REQUIRED_UNSAFE', 'INTERNAL_INTEGRITY_FAILURE')
DAEMON_STOP_REASONS = ('NONE', 'DRIVER_BUDGET', 'EXIT_CONDITION', 'BOOTSTRAP_FAILED',
                       'NO_CONTROLLER')


def rst(sock) -> None:
    """Drop a connection the way a vanished controller does: RST, not a half close.

    A half close (SHUT_WR) is a *controlled* end -- the agent answers it with a BYE. An RST is the
    uncontrolled case: the agent learns about it while reading, with whatever it was doing in
    flight. Tests of §5 need both."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    except OSError:
        pass
    sock.close()


#: W14 §18 -- the lifetime half of the report that every session record belongs to.
LIFETIME_KEYS = ('lifetime_id', 'lifetime_start_sec', 'recovery_source', 'recovery_transitions',
                 'exit_reason', 'boot_inputs')

#: The bounded session-record list the daemon keeps (it mirrors PS4RF_DAEMON_SESSION_RECORDS).
SESSION_RECORD_CAPACITY = 8

#: The bounded session-id ring the daemon keeps for replay detection (PS4RF_DAEMON_SESSION_IDS).
SESSION_ID_CAPACITY = 64

#: One record's fields: what the session was, did, held and how it ended.
SESSION_RECORD_KEYS = ('session_id', 'bye', 'cleanup_state', 'held_after_cleanup', 'reaped',
                       'requests', 'provider_entries', 'deferred', 'invalid', 'violations',
                       'recovery_at_start', 'boot_recheck_ok')


def lifetime_evidence(report: dict, observed_session_ids: list[str]) -> list[str]:
    """W14 §18 -- the two evidence levels, checked against what the host actually saw.

    The daemon-lifetime record carries the boot facts, the recovery history and the final exit
    reason; the session records carry what each session was, did, held and how it ended. Every
    session record belongs to the lifetime in the same report, and every session the host drove must
    appear in it -- evidence that cannot be tied to a lifetime is not evidence. The list is bounded,
    so the check also refuses a report whose records exceed the documented capacity.

    Returns the list of problems (empty = the evidence holds).
    """
    problems: list[str] = []
    missing = [key for key in LIFETIME_KEYS if key not in report]
    if missing:
        problems.append(f'the lifetime record is incomplete: {",".join(missing)}')
        return problems
    if not report.get('lifetime_id'):
        problems.append('the lifetime record carries no lifetime_id')
    records = report.get('session_records')
    if not isinstance(records, list):
        problems.append('session_records is not a list')
        return problems
    total = report.get('session_records_total', 0)
    if not isinstance(total, int) or total < len(records):
        problems.append(f'session_records_total {total!r} is smaller than the list ({len(records)})')
    if len(records) > SESSION_RECORD_CAPACITY:
        problems.append(f'the evidence grew past its capacity: {len(records)} records')
    if total != len(observed_session_ids):
        problems.append(f'the lifetime records {total} sessions, the host drove '
                        f'{len(observed_session_ids)}')
    recorded = [rec.get('session_id') for rec in records]
    # The list is bounded, so the demand is: the records are exactly the most recent sessions the
    # host drove -- every one of them while the run is shorter than the capacity, the newest
    # `capacity` afterwards. The total above is what says nothing was lost.
    expected = observed_session_ids[-SESSION_RECORD_CAPACITY:]
    if recorded != expected:
        missing = [sid for sid in expected if sid not in recorded]
        problems.append(f'the lifetime evidence does not match the sessions the host drove '
                        f'({len(missing)} missing, e.g. {missing[:1]})')
    for rec in records:
        absent = [key for key in SESSION_RECORD_KEYS if key not in rec]
        if absent:
            problems.append(f'session {rec.get("session_id")}: record lacks {",".join(absent)}')
            continue
        if rec['held_after_cleanup'] != 0 or rec['cleanup_state'] != 'COMPLETE':
            problems.append(f'session {rec["session_id"]}: ended with '
                            f'{rec["held_after_cleanup"]} objects in {rec["cleanup_state"]}')
        if not rec['boot_recheck_ok']:
            problems.append(f'session {rec["session_id"]}: the per-session boot re-check failed')
        if not rec['bye']:
            problems.append(f'session {rec["session_id"]}: no BYE reason recorded')
    return problems


def freshness_report(observations: list[dict]) -> list[str]:
    """W14 §14/§4 -- the freshness demands of a resident agent, as explicit checks.

    Each observation is one session of the same agent, with the keys
    ``hello``, ``session_id``, ``transcript`` and (optionally) ``keys``. What must hold:

    * every session announces the *same* agent/boot identity (build id, platform, profile, boot
      facts, label, context, provider, transport) -- an agent that changes identity mid-run is not
      the same agent,
    * every session uses its **own** nonce, session id, transcript and directional key material,
    * the boot-wide recovery state may be *raised* between sessions and never lowered.

    Returns the list of violations (empty = the demands hold).
    """
    problems: list[str] = []
    if not observations:
        return ['no sessions observed']
    for index, obs in enumerate(observations):
        hello = obs.get('hello') or {}
        missing = [field for field in S.IDENTITY_FIELDS if field not in hello]
        if missing:
            problems.append(f'session {index}: HELLO carries no W14 identity block (missing '
                            f'{",".join(missing)})')
    identity = [{field: (obs.get('hello') or {}).get(field) for field in S.IDENTITY_FIELDS}
                for obs in observations]
    first = identity[0]
    for index, entry in enumerate(identity[1:], start=1):
        for field in S.IDENTITY_FIELDS:
            if entry[field] != first[field]:
                problems.append(f'session {index}: identity field {field} changed '
                                f'{first[field]!r} -> {entry[field]!r}')
    for key in ('nonce',):
        values = [(obs.get('hello') or {}).get(key) for obs in observations]
        if len(set(values)) != len(values):
            problems.append(f'a session reused its {key}')
    for key in ('session_id', 'transcript'):
        values = [obs.get(key) for obs in observations]
        if len(set(values)) != len(values):
            problems.append(f'a session reused its {key}')
    keys = [obs.get('keys') for obs in observations if obs.get('keys') is not None]
    if keys and len(set(keys)) != len(keys):
        problems.append('a session reused its directional key material')
    raised = False
    for index, obs in enumerate(observations):
        state = (obs.get('hello') or {}).get('recovery_required')
        if state is True:
            raised = True
        elif state is False and raised:
            problems.append(f'session {index}: the boot-wide recovery flag was lowered by a '
                            f'session (allowed only by a real boot/agent lifecycle reset)')
    return problems


class BusyNoticeError(Exception):
    """The bytes on a refused connection are not the documented SESSION_BUSY notice."""


def parse_busy_notice(raw: bytes) -> dict:
    """Parse and validate the §13 refusal notice. Fail-closed: an unexpected shape is an error,
    never a session and never a silently ignored connection."""
    if isinstance(raw, str):
        raw = raw.encode()
    text = raw.split(b'\n', 1)[0].decode('utf-8', errors='strict')
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BusyNoticeError(f'not JSON: {text[:80]!r}') from exc
    if not isinstance(doc, dict):
        raise BusyNoticeError(f'not a JSON object: {text[:80]!r}')
    if doc.get('msg') != BUSY_MSG:
        raise BusyNoticeError(f'msg is {doc.get("msg")!r}, expected {BUSY_MSG!r}')
    if tuple(sorted(doc)) != tuple(sorted(BUSY_NOTICE_KEYS)):
        raise BusyNoticeError(f'unexpected field set: {sorted(doc)}')
    if doc.get('agent_version') != BUSY_NOTICE_VERSION:
        raise BusyNoticeError(f'agent_version is {doc.get("agent_version")!r}')
    if not isinstance(doc.get('sessions_served'), int):
        raise BusyNoticeError('sessions_served is not an integer')
    if doc.get('active_sessions') != BUSY_NOTICE_ACTIVE_SESSIONS:
        raise BusyNoticeError(f'active_sessions is {doc.get("active_sessions")!r}, expected '
                              f'{BUSY_NOTICE_ACTIVE_SESSIONS} (a refusal exists only while a '
                              f'session is active)')
    if doc.get('state') not in BUSY_REFUSAL_STATES:
        raise BusyNoticeError(f'state {doc.get("state")!r} is not a lifecycle state')
    # A notice must never leak session-bound material: it is unauthenticated.
    for banned in ('session_id', 'nonce', 'key', 'psk', 'boot_id', 'region', 'address'):
        if banned in text:
            raise BusyNoticeError(f'the notice carries {banned!r} (unauthenticated leak)')
    return doc


class ResidentController:
    """Listens per session for the resident daemon and records what arrived.

    Usage:
        ctl = ResidentController(binary, psk, sessions=2)
        ctl.start()
        session = ctl.accept_session()        # connection -> HostSession
        notice = ctl.accept_busy_notice()     # a further connection while active
        ctl.finish()                          # the daemon's own report + exit code
    """

    def __init__(self, binary: pathlib.Path | str, psk: bytes, *, host: str = '127.0.0.1',
                 port: int = 0, sessions: int = 1, lifetime: int = 60, idle: int = 30,
                 extra_args: list[str] | None = None, env: dict | None = None,
                 label: str = 'w14-resident', context: str = 'offline-resident',
                 accept_timeout: float = 30.0, listen: bool = True,
                 tmpdir: pathlib.Path | str | None = None) -> None:
        if len(psk) != 32:
            raise ValueError('the pre-shared key must be 32 bytes')
        if not listen and port == 0:
            raise ValueError('a controller without a listener needs an explicit endpoint port')
        self.binary = pathlib.Path(binary)
        self.psk = psk
        self.host = host
        self.sessions = sessions
        self.lifetime = lifetime
        self.idle = idle
        self.extra_args = list(extra_args or [])
        self.env = env
        self.label = label
        self.context = context
        self.accept_timeout = accept_timeout
        self.listen = listen
        self.srv: socket.socket | None = None
        self.port = port
        self.proc: subprocess.Popen | None = None
        self.accepted: list[dict] = []
        self._tmp: pathlib.Path | None = pathlib.Path(tmpdir) if tmpdir else None

    # ------------------------------------------------------------------ lifecycle
    def start(self, tmpdir: pathlib.Path | None = None) -> 'ResidentController':
        if tmpdir is not None:
            self._tmp = pathlib.Path(tmpdir)
        if self._tmp is None:
            self._tmp = pathlib.Path(f'/tmp/ps4rf-resident-{int(time.time() * 1000)}')
        self._tmp.mkdir(parents=True, exist_ok=True)
        psk_path = self._tmp / 'psk.bin'
        psk_path.write_bytes(self.psk)
        # W14: the host listens per session; the daemon dials in on the same endpoint for every
        # session (and for the §13 refusal), so the backlog must hold more than one connection.
        # `listen=False` models the other case: no controller offering a session at all.
        if self.listen:
            self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.srv.bind((self.host, self.port))
            self.srv.listen(8)
            self.srv.settimeout(self.accept_timeout)
            self.port = self.srv.getsockname()[1]
        cmd = [str(self.binary), '--resident', '--connect', self.host, str(self.port),
               '--psk-file', str(psk_path), '--label', self.label, '--context', self.context,
               '--lifetime', str(self.lifetime), '--idle', str(self.idle),
               '--sessions', str(self.sessions)] + self.extra_args
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, env=self.env)
        return self

    def accept_session(self, timeout: float | None = None):
        """The connection that becomes a session (the caller drives the frozen handshake)."""
        if self.srv is None:
            raise RuntimeError('not started')
        if timeout is not None:
            self.srv.settimeout(timeout)
        conn, peer = self.srv.accept()
        conn.settimeout(timeout if timeout is not None else 30.0)
        self.accepted.append({'kind': 'session_connection', 'peer': list(peer)})
        return conn

    def accept_busy_notice(self, timeout: float | None = None) -> dict:
        """A further connection while a session is active: read and validate the §13 notice."""
        if self.srv is None:
            raise RuntimeError('not started')
        if timeout is not None:
            self.srv.settimeout(timeout)
        conn, peer = self.srv.accept()
        conn.settimeout(timeout if timeout is not None else 30.0)
        chunks = bytearray()
        deadline = time.time() + (timeout if timeout is not None else 30.0)
        while b'\n' not in chunks and time.time() < deadline:
            try:
                part = conn.recv(4096)
            except socket.timeout:
                break
            if not part:
                break
            chunks.extend(part)
        # the refusing agent closes the connection right after the notice
        notice = parse_busy_notice(bytes(chunks))
        closed_by_peer = conn.recv(64) == b''
        conn.close()
        self.accepted.append({'kind': 'busy_refusal', 'peer': list(peer), 'closed': closed_by_peer,
                              'notice': notice})
        return notice

    def finish(self, timeout: float = 30.0) -> dict:
        """Wait for the daemon, parse its own report line, return both."""
        if self.proc is None:
            raise RuntimeError('not started')
        try:
            out, err = self.proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            out, err = self.proc.communicate()
            raise
        finally:
            if self.srv is not None:
                self.srv.close()
        report = None
        for line in (out or '').splitlines():
            line = line.strip()
            if line.startswith('{') and '"state"' in line:
                report = json.loads(line)
        return {'exit_code': self.proc.returncode, 'report': report, 'stdout': (out or '').strip(),
                'stderr': (err or '').strip(), 'accepted': self.accepted}

    def abort(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            self.proc.communicate()
        if self.srv is not None:
            self.srv.close()


def report_is_consistent(report: dict | None) -> list[str]:
    """Cheap, explicit invariants over the daemon's own report (returns the violations).

    These are *derived checks on reported data*, not an authority: the evidence records what the
    agent reported and what the controller observed, side by side.
    """
    problems: list[str] = []
    if report is None:
        return ['no daemon report']
    if report.get('state') not in DAEMON_STATES:
        problems.append(f'unknown state {report.get("state")!r}')
    if report.get('exit_reason') not in DAEMON_EXIT_REASONS:
        problems.append(f'unknown exit reason {report.get("exit_reason")!r}')
    if report.get('stop') not in DAEMON_STOP_REASONS:
        problems.append(f'unknown stop reason {report.get("stop")!r}')
    if report.get('stop') == 'EXIT_CONDITION' and report.get('exit_reason') == 'NONE':
        problems.append('the run stopped on an exit condition without naming one')
    if report.get('stop') == 'DRIVER_BUDGET' and report.get('exit_reason') != 'NONE':
        problems.append('the run stopped on the driver budget but names an exit reason')
    served = report.get('sessions_served')
    ids = report.get('session_ids')
    if not isinstance(served, int) or not isinstance(ids, list):
        problems.append('sessions_served/session_ids missing')
    else:
        if len(ids) != min(served, 8):
            problems.append(f'session ids {len(ids)} do not match served sessions {served}')
        if len(set(ids)) != len(ids):
            problems.append('a session id was used twice (no session isolation)')
    return problems
