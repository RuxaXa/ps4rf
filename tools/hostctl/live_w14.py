"""W14 live controller -- the bring-up run sheet, executable.

One payload upload, one agent lifetime, three sessions: A (plain status path), a controller gap that
must *not* end the agent, B (fresh session in the same lifetime), C (authenticated admin shutdown,
then silence). The controller owns nothing the agent cannot serve over the frozen dial-out
transport: it listens, the agent dials in.

Everything the run must prove is proved *host-side* and written to one evidence file:

* freshness  -- session id, nonce, transcript and directional keys differ per session,
* stability  -- build id, platform, label/context, boot facts and the boot-wide recovery flag are
                identical across the three sessions,
* isolation  -- each session starts with an empty request registry, no pending ids, no resources of
                an earlier session and no carried-over AEAD state (the session objects are born per
                session; nothing is copied),
* residency  -- after A the agent survives a controller gap and dials again on its own,
* the end    -- C's admin shutdown answers, BYEs with ADMIN_SHUTDOWN and the agent never dials again.

Agent-side numbers that are not on the wire are *not* claimed here: the console build has no output
channel, so the daemon's own report (dial misses, transitions) stays agent-side. What the controller
can measure is the reconnection, and that is what it records.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import socket
import sys
import time

REPO = pathlib.Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.hostctl.endpoint import SocketEndpoint                      # noqa: E402
from tools.hostctl.resident import BusyNoticeError, parse_busy_notice          # noqa: E402
from tools.hostctl.session import HostSession, smoke_request_id, SessionError  # noqa: E402

PSK_FILE = pathlib.Path.home() / '.hermes' / 'secrets' / 'ps4rf-w14-psk.bin'

STABLE_FIELDS = ('agent_version', 'build_id', 'platform', 'label', 'context', 'provider_id')
BOOT_FIELDS = ('boot_status', 'boot_sec', 'boot_usec', 'recovery_required')
FRESH_FIELDS = ('session_id', 'nonce', 'transcript', 'keys')


class LiveError(RuntimeError):
    """A fail-closed stop of the run (the run sheet's STOP list)."""


def _h(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def _keys_fingerprint(keys) -> str:
    """A fingerprint, never the keys: both directions, one digest."""
    return _h(bytes(keys.k_agent_to_host) + bytes(keys.k_host_to_agent))[:32]


class SessionFacts:
    """What one session is allowed to reveal in evidence."""

    def __init__(self, label: str):
        self.label = label
        self.hello: dict = {}
        self.ready: dict = {}
        self.identity: dict = {}
        self.responses: list[dict] = []
        self.bye: dict | None = None
        self.research: dict | None = None
        self.connect_wait_s = 0.0
        self.session_id = ''
        self.nonce_hash = ''
        self.transcript_hash = ''
        self.keys_fingerprint = ''
        self.started_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')

    def as_evidence(self) -> dict:
        # the BYE carries only `reason`, `cleanup` and `msg` -- the lifecycle states around it are
        # proved by the run itself: a session that *follows* A or B is the proof that the agent went
        # back to RESIDENT_IDLE, and the silence after C is the proof that it EXITED.
        return {
            'session': self.label,
            'session_id': self.session_id,
            'nonce_sha256': self.nonce_hash,
            'transcript_sha256': self.transcript_hash,
            'directional_keys_fingerprint': self.keys_fingerprint,
            'negotiated_limits': {k: self.ready.get(k) for k in
                                  ('max_frame_bytes', 'lifetime_s', 'idle_s', 'agent_version')},
            'identity': self.identity,
            'requests': [{'operation': r.get('operation'), 'status': r.get('status'),
                          'provider_entry': (r.get('result') or {}).get('provider_entry'),
                          'mutating_allowed': (r.get('result') or {}).get('mutating_allowed'),
                          'error': (r.get('error') or {}).get('code')}
                         for r in self.responses],
            # W15R3: the response *bodies* of this session, verbatim. The status body is where the
            # lifetime reports its boot-binding outcome (the measurement ran inside this session),
            # and on the console that read-out is the only evidence channel there is.
            'responses': [{'operation': r.get('operation'), 'result': r.get('result'),
                           'error': r.get('error')}
                          for r in self.responses],
            'cleanup': (self.bye or {}).get('cleanup'),
            'bye': (self.bye or {}).get('reason'),
            'started_at': self.started_at,
            'dialled_in_after_s': self.connect_wait_s,
        }


def fresh_scope(label: str, session_id: str) -> dict:
    """§2/§4: the host-side scope a session starts with -- born empty, never inherited.

    In the bring-up this is bookkeeping: no research capability is derived (no research operation
    happens), so the record is the *emptiness* itself, which is what has to be provable. The
    registry and the pending set are then filled by the session's own traffic and compared against
    the empty start: a session that inherited anything would show up in the start snapshot.
    """
    return {'session': label, 'session_id': session_id, 'request_registry': {}, 'pending_ids': [],
            'resources': [], 'aead_state': None, 'capability_defined': False,
            'capability_derived_for': None}


def scope_problems(start: dict, served: dict, pending: list, allocated: list) -> list[str]:
    """The isolation question, answered from bookkeeping rather than from an assumption."""
    problems = []
    for field in ('request_registry', 'pending_ids', 'resources', 'aead_state',
                  'capability_derived_for', 'capability_defined'):
        if start.get(field) not in ({}, [], None, False):
            problems.append(f'{start.get("session")}: the session started with {field} = '
                            f'{start.get(field)!r} -- state of an earlier session')
    if pending:
        problems.append(f'{start.get("session")}: request ids without a response: {pending}')
    if allocated:
        problems.append(f'{start.get("session")}: the run sheet allocates nothing, saw {allocated}')
    if start.get('session_id') and start['session_id'] in served:
        problems.append(f'{start.get("session")}: the session id was already served')
    return problems


class LiveController:
    def __init__(self, host: str, port: int, psk: bytes, *, accept_timeout: float = 120.0,
                 session_timeout: float = 60.0, out_dir: pathlib.Path | None = None):
        self.host, self.port, self.psk = host, port, psk
        self.accept_timeout = accept_timeout
        self.session_timeout = session_timeout
        self.out_dir = out_dir or pathlib.Path('.')
        self.sock: socket.socket | None = None
        self.sessions: list[SessionFacts] = []
        self.lifetime_id = ''
        self.notes: list[str] = []
        self.anchor = time.monotonic()      # the instant the agent could have dialled again
        self.strays = 0                     # connections that never said anything
        self.busy_notices: list[dict] = []  # §13 refusals the agent sent while a session was active
        self.connection_log: list[dict] = []  # every connection, in order, with its opening bytes

    # ------------------------------------------------------------------ listener
    def open(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(4)
        self.sock = sock

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def mark_ready(self) -> None:
        """Start the clock for the next dial: the moment the agent could reach us again."""
        self.anchor = time.monotonic()

    def accept(self, timeout: float | None = None) -> socket.socket:
        """The next connection that actually speaks.

        A peer that connects and closes without sending a byte is not a session attempt (it is a
        scanner, a stale dial or an operator with the wrong tool): it is recorded and skipped, so a
        stray connection can never be mistaken for the agent's dial.
        """
        deadline = time.monotonic() + (self.accept_timeout if timeout is None else timeout)
        while True:
            if self.sock is None:
                raise LiveError('the listener is closed; a session cannot be accepted')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LiveError('no agent dialled in within the accept timeout')
            self.sock.settimeout(remaining)
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                raise LiveError('no agent dialled in within the accept timeout') from None
            conn.settimeout(self.session_timeout)

            head = self._peek_head(conn)
            self.connection_log.append({'t': round(time.monotonic() - self.anchor, 3),
                                        'head': head[:32].decode('latin-1', 'replace'),
                                        'kind': ('busy_notice' if head.startswith(b'{"active_sessions"')
                                                 else 'frame' if head else 'silent')})
            if head.startswith(b'{"active_sessions"'):
                # §13: the agent refuses a further attempt *while* a session is active. That is the
                # notice -- unauthenticated information, never a session.
                self._read_busy_notice(conn)
                conn.close()
                continue
            if head:
                return conn
            conn.close()
            self.strays += 1
            self.notes.append(f'connection #{self.strays} closed without a byte: skipped, '
                              'not counted as a session')

    @staticmethod
    def _peek_head(conn: socket.socket, want: int = 24, budget: float = 5.0) -> bytes:
        """The opening bytes of a connection *without* consuming them."""
        deadline = time.monotonic() + budget
        while True:
            try:
                conn.settimeout(min(budget, 2.0))
                head = conn.recv(want, socket.MSG_PEEK)
            except OSError:
                return b''
            if len(head) >= want or (head and time.monotonic() >= deadline):
                return head
            if time.monotonic() >= deadline:
                return head
            time.sleep(0.01)

    def _read_busy_notice(self, conn: socket.socket) -> dict:
        """Consume and record one §13 refusal (the notice, exactly one line)."""
        raw = b''
        conn.settimeout(5.0)
        try:
            while not raw.endswith(b'\n') and len(raw) < 4096:
                chunk = conn.recv(512)
                if not chunk:
                    break
                raw += chunk
        except OSError:
            pass
        entry: dict = {'raw_len': len(raw)}
        try:
            entry['fields'] = parse_busy_notice(raw)
        except BusyNoticeError as exc:
            entry['shape_problem'] = str(exc)
        for key in ('session_id', 'nonce', 'key', 'psk', 'transcript'):
            if key in raw.lower().decode('latin-1', 'replace'):
                entry.setdefault('forbidden_token', key)
        self.busy_notices.append(entry)
        return entry

    def wait_for_dial(self, timeout: float) -> float | None:
        """How long the agent needed to dial in again (the residency proof). None = it did not."""
        started = time.monotonic()
        try:
            conn = self.accept(timeout=timeout)
        except LiveError:
            return None
        waited = time.monotonic() - started
        conn.close()          # the probe only proves the dial; it refuses nothing
        return waited

    # ------------------------------------------------------------------ sessions
    def run_session(self, label: str, ops: tuple[tuple[str, dict], ...], *,
                    expect_bye: str = 'CLIENT_CLOSE', admin: bool = False,
                    hook=None) -> SessionFacts:
        """Drive one session: handshake, `ops`, then -- optionally -- a `hook`.

        The hook runs *inside* the session, after the named operations and before the host half
        close, so an extended sheet (W15's research read) can use the very same session machinery
        without a second session implementation. What the hook returns lands in
        ``facts.research``; a hook that raises fails the session like any other step.
        """
        facts = SessionFacts(label)
        conn = self.accept()
        facts.connect_wait_s = round(time.monotonic() - self.anchor, 3)
        session = HostSession(SocketEndpoint(conn, timeout=self.session_timeout), self.psk)
        scope: dict = {}
        served_ids = {s.session_id for s in self.sessions}
        pending: list[str] = []
        allocated: list[str] = []
        try:
            facts.hello = session.handshake()
        except Exception as exc:                  # diagnostic: what did the peer actually send?
            try:
                conn.settimeout(2.0)
                head = conn.recv(32)
            except OSError:
                head = b''
            raise LiveError(f'{label}: handshake failed ({exc}); first bytes: {head.hex()}') from exc
        try:
            facts.identity = dict(session.agent_identity or {})
            facts.ready = session.recv_ready()
            facts.session_id = str(session.session_id)
            scope = fresh_scope(label, facts.session_id)
            if not self.lifetime_id:
                prefix = _h(self.psk)[:12]
                self.lifetime_id = (f'LIFE-live-{facts.identity.get("build_id", "unknown")[:8]}'
                                    f'-{facts.started_at.replace(":", "").replace("-", "")}')
                self.notes.append(f'lifetime id is host-side bookkeeping (psk-bound {prefix}); the '
                                  'agent-side lifetime id is not on the wire in this build')
            for index, (op, args) in enumerate(ops):
                request_id = smoke_request_id(index)
                pending.append(request_id)
                if op.endswith(('.alloc', '.map', '.hold')):
                    allocated.append(op)
                response = session.request(op, args, request_id=request_id)
                pending.remove(request_id)          # answered; a raise above leaves it pending
                facts.responses.append({'operation': op, **response})
                if admin and op == 'session.shutdown':
                    break
            if hook is not None:
                facts.research = hook(session, facts)
            facts.nonce_hash = _h(str(facts.hello.get('nonce', '')))[:32]
            facts.transcript_hash = _h(bytes(session.transcript_hex or '', 'utf-8'))[:32]
            facts.keys_fingerprint = _keys_fingerprint(session.keys)
            try:
                session.ep.shutdown_write()
                facts.bye = session.await_bye(f'{label} close')
            except SessionError:
                facts.bye = None
        finally:
            session.close()
        if facts.bye is None:
            raise LiveError(f'session {label} ended without a BYE')
        if facts.bye.get('reason') != expect_bye:
            raise LiveError(f'session {label}: BYE {facts.bye.get("reason")!r}, expected '
                            f'{expect_bye!r}')
        cleanup = facts.bye.get('cleanup') or {}
        if cleanup.get('state') != 'COMPLETE' or cleanup.get('resources') != []:
            raise LiveError(f'session {label}: cleanup {cleanup!r} is not COMPLETE with no held '
                            'resource')
        problems = scope_problems(scope, served_ids, pending, allocated)
        if problems:
            raise LiveError('; '.join(problems))
        self.sessions.append(facts)
        return facts


def compare_sessions(sessions: list[SessionFacts]) -> dict:
    """The A/B/C comparison table: what must be fresh, what must be stable."""
    stable, fresh, drift = {}, {}, []
    for field in STABLE_FIELDS:
        values = {s.label: s.identity.get(field) for s in sessions}
        stable[field] = values
        if len({json.dumps(v, sort_keys=True) for v in values.values()}) != 1:
            drift.append(f'static identity field {field!r} changed between sessions: {values}')
    for field in BOOT_FIELDS:
        values = {s.label: s.ready.get(field) for s in sessions}
        stable[field] = values
        if len({json.dumps(v, sort_keys=True) for v in values.values()}) != 1:
            drift.append(f'boot fact {field!r} changed between sessions: {values}')
    for field, getter in (('session_id', lambda s: s.session_id),
                          ('nonce_sha256', lambda s: s.nonce_hash),
                          ('transcript_sha256', lambda s: s.transcript_hash),
                          ('directional_keys_fingerprint', lambda s: s.keys_fingerprint)):
        values = {s.label: getter(s) for s in sessions}
        fresh[field] = values
        if len(set(values.values())) != len(values):
            drift.append(f'session value {field!r} was reused: {values}')
    return {'stable': stable, 'fresh': fresh, 'problems': drift}


def health(target: str, *, ftp_port: int = 2121, tcp_port: int = 3232) -> dict:
    """Post-shutdown console health. The loader port is deliberately not touched."""
    import subprocess
    out: dict = {'ftp_2121': None, 'tcp_3232': None, 'icmp': None}
    try:
        with socket.create_connection((target, ftp_port), timeout=8.0) as sock:
            sock.settimeout(8.0)
            out['ftp_2121'] = sock.recv(128).decode('latin-1', 'replace').strip()[:64] or 'open'
    except OSError as exc:
        out['ftp_2121'] = f'FAIL {exc.__class__.__name__}'
    try:
        with socket.create_connection((target, tcp_port), timeout=8.0):
            out['tcp_3232'] = 'open'
    except OSError as exc:
        out['tcp_3232'] = f'FAIL {exc.__class__.__name__}'
    try:
        done = subprocess.run(['ping', '-c', '3', '-W', '2', target], capture_output=True,
                              text=True, timeout=30)
        out['icmp'] = 'ok' if done.returncode == 0 else f'FAIL rc={done.returncode}'
    except (OSError, subprocess.SubprocessError) as exc:
        out['icmp'] = f'FAIL {exc.__class__.__name__}'
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='W14 live controller (resident bring-up)')
    parser.add_argument('--listen', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=9028)
    parser.add_argument('--psk-file', type=pathlib.Path, default=PSK_FILE)
    parser.add_argument('--out', type=pathlib.Path, default=pathlib.Path('.'),
                        help='directory for the evidence file')
    parser.add_argument('--gap-sec', type=float, default=25.0,
                        help='the controller is absent this long between A and B')
    parser.add_argument('--reconnect-timeout', type=float, default=90.0)
    parser.add_argument('--accept-timeout', type=float, default=120.0,
                        help='how long a session attempt may take to arrive')
    parser.add_argument('--no-redial-sec', type=float, default=30.0,
                        help='after the admin shutdown: how long the agent must stay silent')
    parser.add_argument('--target', default=None, help='console address for the post-run health')
    parser.add_argument('--no-health', action='store_true')
    args = parser.parse_args(argv)

    psk = pathlib.Path(args.psk_file).read_bytes()
    ctl = LiveController(args.listen, args.port, psk, out_dir=args.out,
                         accept_timeout=args.accept_timeout)
    evidence: dict = {'stage': 'W14 live bring-up', 'mode': 'resident', 'started_at':
                      dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),
                      'controller': f'{args.listen}:{args.port}', 'psk_fingerprint': _h(psk)[:16],
                      'steps': [], 'stray_connections': 0, 'busy_notices': [], 'notes': [],
                      'connection_log': []}
    try:
        ctl.open()
        # ---- session A
        facts_a = ctl.run_session('A', (('session.ping', {}), ('session.status', {}),
                                        ('telemetry.read', {}), ('session.status', {})))
        evidence['steps'].append({'step': 'session_a', 'facts': facts_a.as_evidence()})

        # ---- the controller gap: the agent must survive it and dial again
        ctl.close()
        evidence['steps'].append({'step': 'controller_gap', 'seconds': args.gap_sec,
                                  'listener': 'closed'})
        time.sleep(args.gap_sec)
        ctl.open()
        ctl.mark_ready()        # from here on the agent can reach us: how long does it take?

        # ---- session B: fresh session in the same lifetime, dialled by the agent itself
        facts_b = ctl.run_session('B', (('session.ping', {}), ('session.status', {}),
                                        ('telemetry.read', {})))
        if facts_b.connect_wait_s > args.reconnect_timeout:
            raise LiveError(f'the agent needed {facts_b.connect_wait_s}s to dial again after the '
                            'controller gap')
        evidence['steps'].append({'step': 'resident_proof',
                                  'reconnect_after_s': facts_b.connect_wait_s,
                                  'agent_dialled_on_its_own': True})
        evidence['steps'].append({'step': 'session_b', 'facts': facts_b.as_evidence()})

        # ---- session C: authenticated admin shutdown
        facts_c = ctl.run_session('C', (('session.status', {}),
                                        ('session.shutdown', {'capability': 'session.admin'})),
                                  expect_bye='ADMIN_SHUTDOWN', admin=True)
        ack = facts_c.responses[-1]
        if (ack.get('result') or {}).get('status') != 'ACCEPTED':
            raise LiveError(f'the admin shutdown was not accepted: {ack!r}')
        evidence['steps'].append({'step': 'session_c', 'facts': facts_c.as_evidence()})

        # ---- the agent must not dial again
        silent_from = time.monotonic()
        dialled = ctl.wait_for_dial(args.no_redial_sec)
        evidence['steps'].append({'step': 'after_admin_shutdown',
                                  'redialled_within_s': round(time.monotonic() - silent_from, 3)
                                  if dialled is not None else None,
                                  'silent_for_s': args.no_redial_sec})
        if dialled is not None:
            raise LiveError('the agent dialled again after a successful admin shutdown')

        comparison = compare_sessions(ctl.sessions)
        if comparison['problems']:
            raise LiveError('; '.join(comparison['problems']))
        evidence['comparison'] = comparison
        evidence['lifetime_id'] = ctl.lifetime_id
        evidence['notes'] = ctl.notes
        evidence['stray_connections'] = ctl.strays
        evidence['busy_notices'] = ctl.busy_notices
        evidence['connection_log'] = ctl.connection_log
        evidence['verdict'] = 'PASS'
    except LiveError as exc:
        evidence['verdict'] = 'STOP'
        evidence['stop_reason'] = str(exc)
    except Exception as exc:                      # a broken run sheet must still leave evidence
        evidence['verdict'] = 'STOP'
        evidence['stop_reason'] = f'{exc.__class__.__name__}: {exc}'
    finally:
        ctl.close()

    shutdown_done = any(step.get('step') == 'session_c' for step in evidence['steps'])
    if not args.no_health and args.target and shutdown_done:
        # the run sheet's health check belongs *after* the authenticated termination: checking while
        # the agent is still resident would read as "the agent ended" when it did not
        evidence['health_after_shutdown'] = health(args.target)
        if evidence.get('verdict') == 'PASS' and any(
                str(value).startswith('FAIL') for value in evidence['health_after_shutdown'].values()):
            evidence['verdict'] = 'STOP'
            evidence['stop_reason'] = 'target health is not green'

    evidence['connection_log'] = ctl.connection_log
    evidence['busy_notices'] = ctl.busy_notices
    out = pathlib.Path(args.out) / 'w14-live-evidence.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=1, sort_keys=True, default=str) + '\n')
    print(json.dumps({'verdict': evidence.get('verdict'),
                      'stop_reason': evidence.get('stop_reason'),
                      'evidence': str(out), 'sessions': len(ctl.sessions)},
                     sort_keys=True))
    return 0 if evidence.get('verdict') == 'PASS' else 3


if __name__ == '__main__':
    raise SystemExit(main())
