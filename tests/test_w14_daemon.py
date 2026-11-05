"""W14 -- the resident daemon (ps4rfd): lifecycle, session acceptance, exit conditions.

Four layers, all against production code:

1. the **state machine harness** (``tests/harness/daemon_state_check.c``) links the production
   ``native/target/ps4rf_daemon.c`` and asks the gate questions without any socket: the frozen
   lifecycle vocabulary, ACCEPT only in RESIDENT_IDLE, SESSION_BUSY in every other state, and
   the refusal notice / run report as valid canonical JSON with the documented field sets;
2. **structural checks** on the daemon, the agent seam and the driver: the daemon dispatches no
   operation, has exactly one session call site behind the acceptance gate, never listens, and
   never leaves the checkpoint installed;
3. the **offline controller** (``tools/hostctl/resident.py``): the host listens per session and
   the daemon dials in -- one session at a time, a further connection refused with the §13
   notice, several sessions per run with fresh session ids;
4. the **four exit conditions** end to end, each with its own scenario, plus the two
   session-scoped cases that must *not* end the agent.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import socket
import struct
import subprocess
import sys
import time

import pytest

from tools.hostctl import resident as R
from tools.hostctl.endpoint import SocketEndpoint
from tools.hostctl.session import HostSession, smoke_request_id
from tools.primitive_iface import schema as SCHEMA

REPO = pathlib.Path(__file__).resolve().parents[1]
TARGET = REPO / 'native' / 'target'
HARNESS = REPO / 'tests' / 'harness' / 'daemon_state_check.c'
PSK = bytes(range(1, 33))

pytestmark = pytest.mark.skipif(shutil.which('gcc') is None, reason='host toolchain missing')


def _strip_c_comments(text: str) -> str:
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
    return re.sub(r'//[^\n]*', ' ', text)


def _code(name: str) -> str:
    return _strip_c_comments((TARGET / name).read_text())


def _generated_counts() -> dict:
    """The target table's counts as generated (W17F: never a literal in a test).

    The driver's self check reports its own compiled-in table; comparing it against the generated
    header + the authoritative wired designations keeps the invariant ("the driver knows the same
    table the generator produced") without freezing a number a correct new operation would move.
    """
    header = (TARGET / 'ps4rf_optable_data.h').read_text()
    return {name: int(re.search(rf'PS4RF_OP_{name}_COUNT (\d+)u', header).group(1))
            for name in ('TABLE', 'WIRED', 'DEFERRED')}


def _authoritative_wired_ops() -> list:
    """The wired target surface: the generator's stub-wired set plus the named route overrides."""
    import importlib.util as _ilu
    from tools.dispatch import matrix as _matrix
    spec = _ilu.spec_from_file_location('ps4rf_gen_optable_probe', TARGET / 'gen_optable.py')
    gen = _ilu.module_from_spec(spec)
    spec.loader.exec_module(gen)
    return sorted(set(gen.TARGET_WIRED_OPS) | set(_matrix.TARGET_ROUTE_OVERRIDES))


# --------------------------------------------------------------------- builds (module scope)

@pytest.fixture(scope='module')
def daemon_binary(tmp_path_factory) -> pathlib.Path:
    """The host build of the target agent *with* the resident daemon (default profile)."""
    out = tmp_path_factory.mktemp('w14-host') / 'host'
    proc = subprocess.run(['sh', str(TARGET / 'build_host.sh'), str(out)], cwd=REPO,
                          capture_output=True, text=True, env={'PATH': '/usr/bin:/bin'})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return out / 'ps4rfd_host'


@pytest.fixture(scope='module')
def daemon_binary_bootid(tmp_path_factory) -> pathlib.Path:
    """A build with the W11 boot binding compiled in (bootstrap must then fail closed when the
    binding cannot be formed)."""
    out = tmp_path_factory.mktemp('w14-host-bootid') / 'host'
    proc = subprocess.run(['sh', str(TARGET / 'build_host.sh'), str(out)], cwd=REPO,
                          capture_output=True, text=True,
                          env={'PATH': '/usr/bin:/bin', 'PS4RF_TARGET_BOOTID': '1'})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return out / 'ps4rfd_host'


@pytest.fixture(scope='module')
def state_check(tmp_path_factory) -> dict:
    """Build and run the production-code state machine harness."""
    out = tmp_path_factory.mktemp('w14-harness')
    binary = out / 'daemon_state_check'
    cmd = ['gcc', '-std=c11', '-O1', '-Wall', '-Wextra', '-Wno-unused-parameter',
           '-I', str(TARGET), '-I', str(REPO / 'native/src'), '-o', str(binary),
           str(HARNESS),
           str(TARGET / 'ps4rf_daemon.c'), str(TARGET / 'ps4rf_agent.c'),
           str(TARGET / 'ps4rf_router.c'), str(TARGET / 'ps4rf_stub.c'),
           str(TARGET / 'ps4rf_resources.c'), str(TARGET / 'ps4rf_evidence.c'),
           str(TARGET / 'ps4rf_telemetry.c'), str(TARGET / 'ps4rf_shim.c'),
           str(TARGET / 'ps4rf_platform_host.c'),
           str(REPO / 'native/src/ps4rf_protocol.c'), str(REPO / 'native/src/sha256.c'),
           str(REPO / 'native/src/chacha20poly1305.c'), str(REPO / 'native/src/jcs.c')]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert not result.stderr.strip(), f'the harness build emitted warnings:\n{result.stderr}'
    run = subprocess.run([str(binary)], capture_output=True, text=True,
                         env={'PATH': '/usr/bin:/bin'})
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout.strip().splitlines()[-1])


# ------------------------------------------------------------------ 1. the state machine

def test_lifecycle_vocabulary_is_the_frozen_one(state_check):
    assert state_check['state_vocabulary'] == ['BOOTSTRAP', 'RESIDENT_IDLE', 'SESSION_ACTIVE',
                                               'SESSION_CLEANUP', 'EXITED']
    assert state_check['exit_vocabulary'] == ['NONE', 'ADMIN_SHUTDOWN', 'PROTOCOL_CORRUPTION',
                                              'RECOVERY_REQUIRED_UNSAFE',
                                              'INTERNAL_INTEGRITY_FAILURE']
    assert state_check['stop_vocabulary'] == ['DRIVER_BUDGET', 'EXIT_CONDITION',
                                              'BOOTSTRAP_FAILED', 'NO_CONTROLLER']
    assert state_check['busy_msg'] == 'SESSION_BUSY'


def test_acceptance_gate_accepts_only_in_resident_idle(state_check):
    assert state_check['accept_bootstrap'] == 'SESSION_BUSY', 'bootstrap is not a serving state'
    assert state_check['accept_idle'] == 'ACCEPT'
    assert state_check['accept_active'] == 'SESSION_BUSY', '§13: a second session is refused'
    assert state_check['accept_cleanup'] == 'SESSION_BUSY'
    assert state_check['accept_after_active'] == 'SESSION_BUSY', \
        'the active flag alone must keep the gate closed even in RESIDENT_IDLE'


def test_bootstrap_records_what_the_build_can_prove(state_check):
    assert state_check['bootstrap_rc'] == 0
    # no boot binding compiled, no PS4RF_HOST_BOOTTIME in the harness env: the honest answer
    assert state_check['boot_inputs'] in ('MEASURED', 'UNRESOLVED')


def test_refusal_notice_is_a_strict_canonical_document(state_check):
    notice = state_check['notice_active']
    validated = R.parse_busy_notice(json.dumps(notice).encode())
    assert validated == notice
    assert tuple(sorted(notice)) == tuple(sorted(R.BUSY_NOTICE_KEYS))
    assert notice['msg'] == 'SESSION_BUSY'
    assert notice['state'] == 'SESSION_ACTIVE'
    assert notice['active_sessions'] == 1
    # canonical JSON: sorted keys, no whitespace (the notice is built with the frozen serializer)
    assert json.dumps(notice, sort_keys=True, separators=(',', ':')) == json.dumps(
        json.loads(json.dumps(notice, sort_keys=True, separators=(',', ':'))),
        sort_keys=True, separators=(',', ':'))
    # the idle-shape notice is *not* a refusal: active_sessions must be 0 there
    idle = state_check['notice_idle']
    assert tuple(sorted(idle)) == tuple(sorted(R.BUSY_NOTICE_KEYS))
    assert idle['active_sessions'] == 0
    assert idle['state'] == 'RESIDENT_IDLE'
    with pytest.raises(R.BusyNoticeError):
        R.parse_busy_notice(json.dumps(idle).encode())


def test_run_report_is_valid_and_consistent(state_check):
    report = state_check['report']
    assert state_check['run_rc'] == 0
    assert report['exit_reason'] == 'NONE'
    assert report['stop'] == 'NO_CONTROLLER'
    assert report['state'] == 'EXITED'
    assert report['dial_misses'] >= 1
    assert report['sessions_served'] == 0 and report['session_ids'] == []
    assert report['transitions'] >= 3, 'BOOTSTRAP -> RESIDENT_IDLE -> EXITED at least'
    assert R.report_is_consistent(report) == []
    # no key material and no host input in a report
    assert PSK.hex() not in json.dumps(report)


# ----------------------------------------------------------------- 2. structural properties

def test_daemon_dispatches_no_operation():
    code = _code('ps4rf_daemon.c')
    for forbidden in ('kernel.read', 'ps4rf_router_handle', 'ps4rf_provider_enter',
                      'ps4rf_stub_invoke', 'jval_parse', 'jval_get'):
        assert forbidden not in code, f'the daemon must not reach {forbidden}'
    # the only productive path of a session is the frozen agent runner
    assert code.count('ps4rf_agent_run(') == 1
    # ... and it sits behind the acceptance gate
    assert code.index('ps4rf_daemon_accept(d)') < code.index('ps4rf_agent_run(')


def test_daemon_never_listens_and_keeps_the_dial_out_transport():
    code = _code('ps4rf_daemon.c')
    # the module's own acceptance gate is named ps4rf_daemon_accept(); no *socket* accept exists
    code_without_gate = code.replace('ps4rf_daemon_accept(', 'GATE(')
    for forbidden in ('listen(', 'accept(', 'bind(', 'SO_REUSEADDR', 'select('):
        assert forbidden not in code_without_gate, \
            f'the resident agent dials out; it must not {forbidden}'
    assert 'net_connect' in code and code.count('net_connect') >= 1


def test_only_four_exit_reasons_have_a_producer():
    header = (TARGET / 'ps4rf_daemon.h').read_text()
    code = _code('ps4rf_daemon.c')
    # §9: all four exit reasons have a producer now -- §15 landed the last one. The reason is
    # returned in exactly one place, and the bye reason that triggers it is written in one place.
    for reason in ('PS4RF_DAEMON_EXIT_PROTOCOL', 'PS4RF_DAEMON_EXIT_RECOVERY',
                   'PS4RF_DAEMON_EXIT_INTEGRITY', 'PS4RF_DAEMON_EXIT_ADMIN'):
        assert reason in header and reason in code, f'{reason} has no producer'
    assert code.count('return PS4RF_DAEMON_EXIT_ADMIN;') == 1
    assert code.count('d_eq(bye, "ADMIN_SHUTDOWN")') == 1


def test_checkpoint_is_installed_and_always_uninstalled():
    code = _code('ps4rf_daemon.c')
    assert code.count('ps4rf_agent_set_checkpoint(daemon_checkpoint, d)') == 1
    body = code[code.index('int ps4rf_daemon_run('):]
    body = body[:body.index('\n}\n')]
    install = body.index('ps4rf_agent_set_checkpoint(daemon_checkpoint, d)')
    # the bootstrap failure path returns *before* the install: nothing to uninstall there
    assert body.index('return 1;') < install, 'the bootstrap-failure return must come first'
    exits = [m.start() for m in re.finditer(r'return [01];', body[install:])]
    assert len(exits) == 3, 'the run has three exit paths (budget, no controller, exit condition)'
    for offset in exits:
        window = body[install:install + offset]
        assert 'ps4rf_agent_set_checkpoint(NULL, NULL)' in window, \
            'a run path returns without uninstalling the checkpoint'


def test_agent_seam_is_narrow_and_documented():
    agent = _code('ps4rf_agent.c')
    header = (TARGET / 'ps4rf_agent.h').read_text()
    # the seam carries no request and no operation
    assert agent.count('g_checkpoint(g_checkpoint_ctx)') == 1
    assert 'typedef int (*ps4rf_agent_checkpoint_fn)(void *ctx);' in header
    assert 'ps4rf_agent_set_checkpoint' in header and 'ps4rf_agent_set_checkpoint' in agent
    # stage A still holds: the session loop names no read operation and no read state
    assert 'kernel.read' not in agent
    assert 'kread' not in agent.lower()
    # the console entry point and the single-session driver install no checkpoint
    for name in ('ps4rfd_target.c', 'ps4rfd_host.c'):
        assert 'ps4rf_agent_set_checkpoint' not in (TARGET / name).read_text()


def test_notice_and_report_field_sets_are_pinned():
    code = _code('ps4rf_daemon.c')
    notice = code[code.index('size_t ps4rf_daemon_busy_notice('):]
    notice = notice[:notice.index('\n}\n')]
    keys = set(re.findall(r'jval_obj_set\(obj, "([^"]+)"', notice))
    assert keys == set(R.BUSY_NOTICE_KEYS), keys
    assert 'session_id' not in notice, 'an unauthenticated notice must not name a session'
    report = code[code.index('size_t ps4rf_daemon_report_json('):]
    keys = set(re.findall(r'jval_obj_set\(obj, "([^"]+)"', report))
    assert keys == {'attempts', 'boot_inputs', 'boot_sec', 'boot_usec', 'bootstrap_failures',
                    'busy_refusals', 'cleanup_reaped', 'cleanup_refusals', 'cleanup_state',
                    'dial_backoff_us', 'dial_misses', 'dial_misses_total', 'exit_detail',
                    'exit_reason', 'held_after_cleanup', 'last_bye', 'recovery_required',
                    'lifetime_id', 'lifetime_start_sec', 'recovery_source',
                    'recovery_transitions', 'session_ids', 'session_records',
                    'session_records_total', 'sessions_failed', 'sessions_served', 'state', 'stop',
                    'transitions', 'undelivered_mutations', 'undelivered_responses'}, keys


def test_host_driver_offers_the_resident_mode():
    text = (TARGET / 'ps4rfd_host.c').read_text()
    for token in ('--resident', '--sessions', '--idle-rounds', '--idle-pause-ms',
                  '--no-refuse-while-busy', 'ps4rf_daemon_run', 'ps4rf_daemon_report_json'):
        assert token in text, f'the driver does not offer {token}'
    # the single-session mode is untouched
    assert '--connect' in text and 'ps4rf_agent_run(fd, psk' in text


def test_the_c_selftest_of_the_driver_still_passes(daemon_binary):
    """The driver's own in-process self check is part of the suite (it was silently stale for one
    wave: the R3 route change moved kernel.read into the provider)."""
    run = subprocess.run([str(daemon_binary), '--selftest'], capture_output=True, text=True,
                         env={'PATH': '/usr/bin:/bin'})
    assert run.returncode == 0, run.stdout + run.stderr
    doc = json.loads(run.stdout.strip().splitlines()[-1])
    assert doc['selftest'] == 'PASS', doc
    counts = _generated_counts()
    assert doc['ops'] == counts['TABLE'] == counts['WIRED'] + counts['DEFERRED'], doc
    assert doc['wired'] == counts['WIRED'] and doc['deferred'] == counts['DEFERRED'], doc
    assert doc['wired'] == len(_authoritative_wired_ops()), doc
    assert doc['provider_entries'] == 2 and doc['invalid_total'] == 1


# ------------------------------------------------------------------ 3. the controller helper

def test_controller_parses_the_documented_notice():
    notice = {'active_sessions': 1, 'agent_version': 'ps4rfd-daemon-w14', 'build_id': 'host-build',
              'msg': 'SESSION_BUSY', 'sessions_served': 1, 'state': 'SESSION_ACTIVE'}
    raw = json.dumps(notice, sort_keys=True, separators=(',', ':')).encode() + b'\n'
    assert R.parse_busy_notice(raw) == notice
    for broken in (b'not json\n', b'{"msg":"SESSION_BUSY"}\n',
                   json.dumps({**notice, 'msg': 'HELLO'}).encode(),
                   json.dumps({**notice, 'active_sessions': 0}).encode(),
                   json.dumps({**notice, 'state': 'NOWHERE'}).encode(),
                   json.dumps({**notice, 'session_id': 'SES-x'}).encode(),
                   json.dumps({**notice, 'region': 'image_elf'}).encode()):
        with pytest.raises(R.BusyNoticeError):
            R.parse_busy_notice(broken)


def test_report_consistency_check_catches_the_impossible():
    good = {'state': 'EXITED', 'exit_reason': 'NONE', 'stop': 'DRIVER_BUDGET',
            'sessions_served': 2, 'session_ids': ['SES-a', 'SES-b'], 'recovery_required': False}
    assert R.report_is_consistent(good) == []
    assert R.report_is_consistent({**good, 'exit_reason': 'NOPE'})
    assert R.report_is_consistent({**good, 'stop': 'EXIT_CONDITION'})
    assert R.report_is_consistent({**good, 'session_ids': ['SES-a', 'SES-a']})
    assert R.report_is_consistent({**good, 'sessions_served': 2, 'session_ids': []})
    assert R.report_is_consistent(None) == ['no daemon report']


# ------------------------------------------------------------- 4. end to end (real sockets)

def _drive(ctl: R.ResidentController, *, ops=(('session.ping', {}),), session_id=None,
           busy=True, expect_notice=True) -> dict:
    """One accepted session: handshake, READY, the §13 refusal of a further connection, the
    requests, a controlled exit. Returns everything the caller needs to assert."""
    conn = ctl.accept_session()
    session = HostSession(SocketEndpoint(conn, timeout=30.0), PSK, session_id=session_id)
    session.handshake()
    ready = session.recv_ready()
    notice = ctl.accept_busy_notice() if (busy and expect_notice) else None
    responses = []
    for index, (op, args) in enumerate(ops):
        responses.append(session.request(op, args, request_id=smoke_request_id(index)))
    session.ep.shutdown_write()
    bye = session.await_bye('host half close (SHUT_WR)')
    session.close()
    return {'session': session, 'ready': ready, 'notice': notice, 'responses': responses,
            'bye': bye, 'session_id': session.session_id, 'hello': session.hello_seen,
            'transcript': session.transcript_hex,
            'keys': bytes(session.keys.k_agent_to_host).hex() + bytes(session.keys.k_host_to_agent).hex()}


def _run(ctl: R.ResidentController) -> dict:
    out = ctl.finish()
    return out


def test_01_two_sessions_with_a_refusal_on_a_further_connection(daemon_binary, tmp_path):
    """§2/§13: two sessions over one endpoint, each refusing exactly one further connection."""
    ctl = R.ResidentController(daemon_binary, PSK, sessions=2, tmpdir=tmp_path).start()
    try:
        first = _drive(ctl, ops=(('session.ping', {}), ('session.status', {})))
        second = _drive(ctl, ops=(('session.ping', {}),))
        out = ctl.finish()
    finally:
        ctl.abort()

    assert first['notice']['state'] == 'SESSION_ACTIVE'
    assert first['notice']['msg'] == 'SESSION_BUSY'
    assert first['notice']['active_sessions'] == 1
    assert second['notice']['msg'] == 'SESSION_BUSY'
    assert first['bye']['reason'] == 'CLIENT_CLOSE' and second['bye']['reason'] == 'CLIENT_CLOSE'
    assert first['responses'][0]['result']['pong'] is True
    assert first['responses'][1]['status'] == 'OK'
    # §4: a session gets a fresh session id -- nothing session-bound is inherited
    assert first['session_id'] != second['session_id']
    assert first['ready']['msg'] == 'READY' and second['ready']['msg'] == 'READY'
    assert first['ready']['capabilities']['wired_count'] == _generated_counts()['WIRED']

    report = out['report']
    assert out['exit_code'] == 0, out
    assert report['sessions_served'] == 2
    assert report['sessions_failed'] == 0
    assert report['busy_refusals'] == 2, 'one refusal per active session'
    assert report['exit_reason'] == 'NONE'
    assert report['stop'] == 'DRIVER_BUDGET'
    assert report['state'] == 'EXITED'
    assert len(set(report['session_ids'])) == 2
    assert R.report_is_consistent(report) == []
    # the controller saw exactly two sessions and two refusals
    kinds = [entry['kind'] for entry in out['accepted']]
    assert kinds == ['session_connection', 'busy_refusal', 'session_connection', 'busy_refusal']
    assert all('SES-' not in json.dumps(entry.get('notice', {})) for entry in out['accepted'])


def test_02_no_refuse_while_busy_serves_sequentially(daemon_binary, tmp_path):
    """With the refusal switched off the agent still serves one session at a time and never
    listens; nothing is offered on a further connection."""
    ctl = R.ResidentController(daemon_binary, PSK, sessions=1, tmpdir=tmp_path,
                               extra_args=['--no-refuse-while-busy']).start()
    try:
        conn = ctl.accept_session()
        session = HostSession(SocketEndpoint(conn, timeout=30.0), PSK)
        session.handshake()
        session.recv_ready()
        with pytest.raises(socket.timeout):
            ctl.accept_busy_notice(timeout=0.7)
        session.request('session.ping', {}, request_id=smoke_request_id(0))
        session.ep.shutdown_write()
        bye = session.await_bye('host half close (SHUT_WR)')
        session.close()
        out = ctl.finish()
    finally:
        ctl.abort()
    assert bye['reason'] == 'CLIENT_CLOSE'
    assert out['report']['busy_refusals'] == 0
    assert out['report']['sessions_served'] == 1
    assert out['report']['exit_reason'] == 'NONE'


def test_03_transport_loss_with_a_sound_state_keeps_the_agent_resident(daemon_binary, tmp_path):
    """§3/§5: a lost transport is session-scoped. Nothing was in flight, the session handed its
    resources back empty and nothing was left undelivered -- so the peer that disappeared merely
    ended a session: the agent stays resident and the boot-wide flag stays clear. A plain EOF is a
    host-side signal, never a boot state."""
    ctl = R.ResidentController(daemon_binary, PSK, sessions=2, tmpdir=tmp_path).start()
    try:
        conn = ctl.accept_session()
        session = HostSession(SocketEndpoint(conn, timeout=30.0), PSK)
        session.handshake()
        session.recv_ready()
        alloc = session.request('memory.alloc', {'size': 4096, 'alignment': 16},
                                request_id=smoke_request_id(0))
        session.request('memory.free', {'ref': alloc['result']['ref']},
                        request_id=smoke_request_id(1))
        ctl.accept_busy_notice()
        # a hard reset: the agent cannot send its BYE and must not treat it as an exit condition
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        conn.close()

        second = _drive(ctl, ops=(('session.ping', {}),))
        out = ctl.finish()
    finally:
        ctl.abort()
    report = out['report']
    assert second['responses'][0]['result']['pong'] is True
    assert report['sessions_served'] == 2, report
    assert report['recovery_required'] is False, \
        'a transport loss with a sound state is not a recovery condition (§5)'
    assert report['recovery_source'] == 'NONE' and report['recovery_transitions'] == 0
    assert report['held_after_cleanup'] == 0 and report['cleanup_refusals'] == 0
    assert report['exit_reason'] == 'NONE', 'a lost transport must not end the agent'
    assert out['exit_code'] == 0
    assert R.report_is_consistent(report) == []


def test_04_the_session_teardown_hands_the_set_back_empty(daemon_binary, tmp_path):
    """§2/§10: a session ends with held resources = [] and cleanup COMPLETE -- *achieved* by the
    session teardown, which releases whatever the session itself forgot, before the BYE reports the
    state. Allocating without freeing leaves nothing behind: the BYE says COMPLETE, the report
    counts the object it reaped, and the agent is still there for the next session."""
    ctl = R.ResidentController(daemon_binary, PSK, sessions=2, tmpdir=tmp_path).start()
    try:
        first = _drive(ctl, ops=(('memory.alloc', {'size': 4096, 'alignment': 16}),
                                 ('memory.alloc', {'size': 8192, 'alignment': 16})))
        second = _drive(ctl, ops=(('session.status', {}),))
        out = ctl.finish()
    finally:
        ctl.abort()
    report = out['report']
    assert first['bye']['reason'] == 'CLIENT_CLOSE'
    assert first['bye']['cleanup'] == {'resources': [], 'state': 'COMPLETE'}, first['bye']
    assert second['responses'][0]['result']['held_resources'] == []
    assert out['exit_code'] == 0 and report['exit_reason'] == 'NONE'
    assert report['sessions_served'] == 2
    assert report['held_after_cleanup'] == 0 and report['cleanup_refusals'] == 0
    assert report['cleanup_state'] == 'COMPLETE'


def test_05_protocol_corruption_ends_the_agent(daemon_binary, tmp_path):
    """§3: fatal protocol corruption (a frame whose type is not in the frozen table)."""
    ctl = R.ResidentController(daemon_binary, PSK, sessions=2, tmpdir=tmp_path).start()
    try:
        conn = ctl.accept_session()
        session = HostSession(SocketEndpoint(conn, timeout=30.0), PSK)
        session.handshake()
        session.recv_ready()
        # 4B length | 1B unknown type | 8B sequence: refused before any operation is reached
        session.ep.send_all(bytes([0, 0, 0, 0, 0x7f]) + b'\x00' * 8)
        with pytest.raises(Exception):
            for index in range(2):
                session.request('session.ping', {}, request_id=smoke_request_id(index))
        session.close()
        out = ctl.finish()
    finally:
        ctl.abort()
    report = out['report']
    assert out['exit_code'] == 1, out
    assert report['exit_reason'] == 'PROTOCOL_CORRUPTION', report
    assert report['stop'] == 'EXIT_CONDITION'
    assert report['sessions_served'] == 1
    assert 'RECOVERY_REQUIRED' in report['last_bye']


def test_06_handshake_garbage_is_refused_and_never_ends_the_agent(daemon_binary, tmp_path):
    """§8/§15: a peer that cannot complete the frozen handshake never becomes a session -- and an
    attempt that never became a session is refused, not fatal. A wrong PSK, a truncated answer or a
    port scanner cannot corrupt the target, so none of them may end the agent: the attempt is
    counted and the agent keeps serving with exactly the state it had. Frame-level corruption
    *inside* a session stays fatal (test_05)."""
    ctl = R.ResidentController(daemon_binary, PSK, sessions=2, tmpdir=tmp_path).start()
    try:
        conn = ctl.accept_session()
        conn.sendall(b'\x00' * 32)
        # the agent refuses the handshake and closes; unread bytes make the close a reset
        try:
            for _ in range(4):
                if conn.recv(64) == b'':
                    break
        except (ConnectionResetError, socket.timeout):
            pass
        conn.close()
        served = _drive(ctl, ops=(('session.ping', {}),))
        out = ctl.finish()
    finally:
        ctl.abort()
    report = out['report']
    assert served['responses'][0]['result']['pong'] is True, 'the agent stayed reachable'
    assert out['exit_code'] == 0, out
    assert report['exit_reason'] == 'NONE', report
    assert report['sessions_failed'] == 1 and report['sessions_served'] == 1
    assert report['recovery_required'] is False, 'an unauthenticated attempt changes no boot state'


def test_07_replayed_session_id_ends_the_agent(daemon_binary, tmp_path):
    """§4/§17: the same session id must never be served twice (a replayed handshake)."""
    pinned = 'SES-' + 'ab' * 16
    ctl = R.ResidentController(daemon_binary, PSK, sessions=2, tmpdir=tmp_path).start()
    try:
        first = _drive(ctl, ops=(('session.ping', {}),), session_id=pinned)
        # the replay is detected at the first checkpoint of the second session, so that session
        # ends before any request and without a §13 refusal (nothing else is served)
        second = _drive(ctl, ops=(), session_id=pinned, expect_notice=False)
        out = ctl.finish()
    finally:
        ctl.abort()
    report = out['report']
    assert first['bye']['reason'] == 'CLIENT_CLOSE'
    assert second['bye']['reason'] == 'SERVER_CLOSE', \
        'the agent must end the replayed session itself, before serving a request'
    assert out['exit_code'] == 1, out
    assert report['exit_reason'] == 'PROTOCOL_CORRUPTION', report
    assert 'replayed' in report['exit_detail']
    assert len(report['session_ids']) == 2 and len(set(report['session_ids'])) == 1


def test_08_boot_input_drift_refuses_the_session_before_any_frame(daemon_binary, tmp_path):
    """§5: the boot inputs cached at bootstrap are re-read for every session; a change means the
    cache no longer describes this boot, so no session may start."""
    env = {'PATH': '/usr/bin:/bin', 'PS4RF_HOST_BOOTTIME': '1789000000.123456',
           'PS4RF_HOST_BOOTTIME_DRIFT_USEC': '1000'}
    ctl = R.ResidentController(daemon_binary, PSK, sessions=1, tmpdir=tmp_path, env=env).start()
    try:
        conn = ctl.accept_session()
        conn.settimeout(10.0)
        assert conn.recv(64) == b'', 'the agent must close without sending a single frame'
        conn.close()
        out = ctl.finish()
    finally:
        ctl.abort()
    report = out['report']
    assert out['exit_code'] == 1, out
    assert report['exit_reason'] == 'INTERNAL_INTEGRITY_FAILURE', report
    assert 'changed' in report['exit_detail']
    assert report['boot_inputs'] == 'MEASURED'
    assert report['sessions_served'] == 0 and report['sessions_failed'] == 1


def test_09_bootstrap_failure_ends_the_agent(daemon_binary_bootid, tmp_path):
    """A build with the boot binding compiled in must fail closed when the binding cannot be
    formed at bootstrap (here: a partial read of the timeval)."""
    env = {'PATH': '/usr/bin:/bin', 'PS4RF_HOST_BOOTDIAG': 'name=0:0:16:8:f0dcaf6a00000000'}
    ctl = R.ResidentController(daemon_binary_bootid, PSK, sessions=1, tmpdir=tmp_path,
                               env=env).start()
    try:
        out = ctl.finish(timeout=20.0)
    finally:
        ctl.abort()
    report = out['report']
    assert out['exit_code'] == 1, out
    assert report['stop'] == 'BOOTSTRAP_FAILED', report
    assert report['exit_reason'] == 'INTERNAL_INTEGRITY_FAILURE'
    assert report['bootstrap_failures'] == 1
    assert report['sessions_served'] == 0
    assert out['accepted'] == [], 'a failed bootstrap must not accept any session'


def test_10_no_controller_is_not_an_exit_condition(daemon_binary, tmp_path):
    """A missing controller is a run stop, not an agent exit condition (§3)."""
    probe = socket.socket()
    probe.bind(('127.0.0.1', 0))
    free_port = probe.getsockname()[1]
    probe.close()                      # nothing listens on the endpoint
    ctl = R.ResidentController(daemon_binary, PSK, sessions=0, port=free_port, listen=False,
                               tmpdir=tmp_path,
                               extra_args=['--idle-rounds', '2', '--idle-pause-ms', '10'])
    ctl.start()
    try:
        out = ctl.finish(timeout=20.0)
    finally:
        ctl.abort()
    report = out['report']
    assert out['exit_code'] == 0, out
    assert report['stop'] == 'NO_CONTROLLER'
    assert report['exit_reason'] == 'NONE'
    assert report['dial_misses'] >= 2
    assert report['sessions_served'] == 0
    assert R.report_is_consistent(report) == []


def test_11_identity_is_static_and_every_session_is_fresh(daemon_binary, tmp_path):
    """§14/§4: session A and session B see the same agent/boot identity, but nothing session-bound
    is inherited -- no nonce, no session id, no transcript, no key material."""
    ctl = R.ResidentController(daemon_binary, PSK, sessions=2, tmpdir=tmp_path).start()
    try:
        first = _drive(ctl, ops=(('session.ping', {}),))
        second = _drive(ctl, ops=(('session.ping', {}),))
        out = ctl.finish()
    finally:
        ctl.abort()

    observations = [{k: s[k] for k in ('hello', 'session_id', 'transcript', 'keys')}
                    for s in (first, second)]
    assert R.freshness_report(observations) == [], R.freshness_report(observations)

    # the identity block is the documented one (host stand-in: no boot binding, no profile)
    identity = R.S.IDENTITY_FIELDS
    hello_a = first['hello']
    assert set(identity) <= set(hello_a)
    assert hello_a['platform'] == 'host-standin'
    assert hello_a['profile_id'] is None
    assert hello_a['boot_id'] is None and hello_a['boot_sec'] is None and hello_a['boot_usec'] is None
    assert hello_a['boot_status'] == 'UNRESOLVED'
    assert hello_a['session_state'] == 'READY' and hello_a['recovery_required'] is False
    assert hello_a['provider'] == 'ps4rfd-native-stub'
    for field in ('agent_version', 'build_id', 'context', 'label', 'transport'):
        assert hello_a[field] == second['hello'][field], field

    # no key material survives a session: session A's channel cannot open session B's frames
    channel_a = first['session']._ch_a2h
    with pytest.raises(Exception):
        channel_a.open('RESPONSE', 0, b'\x00' * 32)
    assert first['session'].keys.k_agent_to_host != second['session'].keys.k_agent_to_host
    assert first['session'].keys.k_host_to_agent != second['session'].keys.k_host_to_agent
    assert out['exit_code'] == 0 and out['report']['sessions_served'] == 2


def test_12_session_keys_are_wiped_on_every_exit_path():
    """§2: the session's key material and session id must die with the session -- on *every*
    path, not only on the happy one."""
    code = _code('ps4rf_agent.c')
    after_hello = code[code.index('hello = build_hello('):]
    bare = re.findall(r'return PS4RF_AGENT_\w+;', after_hello)
    assert bare == [], f'unguarded returns after the keys exist: {bare}'
    assert after_hello.count('return agent_finish(&sk,') == 8, after_hello.count('return agent_finish(&sk,')
    assert 'volatile unsigned char *p = (volatile unsigned char *)sk;' in code
    # and the identity block is what HELLO announces (field names are the §14 contract)
    for field in ('agent_version', 'build_id', 'platform', 'profile_id', 'boot_id', 'boot_sec',
                  'boot_usec', 'boot_status', 'session_state', 'recovery_required'):
        assert f'"{field}"' in code, field


def test_13b_the_recovery_rule_and_the_teardown_are_production_decisions(state_check):
    """§2/§5/§9/§11: the two decisions about a finished session, exercised on the production code.
    What the rule must NOT do is as important as what it must: a clean session leaves the boot
    alone, and a set the teardown cannot attribute is refused rather than destroyed."""
    rules = state_check['recovery_rule']
    assert rules['clean'] == 0, 'a clean session must not park the boot in recovery'
    assert rules['null_rt'] == 1, 'no session state to judge must fail closed'
    for key in ('violations', 'undelivered', 'leftover', 'pending_cleanup', 'refused_teardown'):
        assert rules[key] == 1, key
    assert rules['teardown_status'] == 0 and rules['teardown_reaped'] == 1
    assert rules['live_after'] == 0, 'the teardown hands the set back empty'
    assert rules['foreign_status'] == 4 and rules['foreign_freed'] == 0
    assert rules['foreign_live_after'] == 1, 'a set without a session is refused, not destroyed'


def test_13_freshness_report_catches_reuse_and_identity_breaks():
    base = {'agent_version': 'ps4rfd-target-w8', 'build_id': 'b1', 'platform': 'host-standin',
            'profile_id': None, 'boot_id': None, 'boot_sec': None, 'boot_usec': None,
            'boot_status': 'UNRESOLVED', 'context': 'c', 'label': 'l', 'provider': 'p',
            'transport': 'reverse-tcp', 'msg': 'HELLO', 'nonce': 'n1',
            'recovery_required': False, 'session_state': 'READY'}
    a = {'hello': dict(base), 'session_id': 'SES-a', 'transcript': 't1', 'keys': 'k1'}
    b = {'hello': {**base, 'nonce': 'n2'}, 'session_id': 'SES-b', 'transcript': 't2', 'keys': 'k2'}
    assert R.freshness_report([a, b]) == []
    assert R.freshness_report([]) == ['no sessions observed']
    reused = {**b, 'hello': {**base, 'nonce': 'n1'}}
    assert 'a session reused its nonce' in R.freshness_report([a, reused])
    same_id = {**b, 'session_id': 'SES-a'}
    assert 'a session reused its session_id' in R.freshness_report([a, same_id])
    changed = {**b, 'hello': {**base, 'nonce': 'n2', 'build_id': 'other'}}
    assert any('identity field build_id changed' in p for p in R.freshness_report([a, changed]))
    incomplete = {**b, 'hello': {'msg': 'HELLO', 'nonce': 'n2'}}
    assert any('no W14 identity block' in p for p in R.freshness_report([a, incomplete]))
    # the boot-wide recovery flag may be raised, never lowered
    raised = {**b, 'hello': {**base, 'nonce': 'n2', 'recovery_required': True,
                             'session_state': 'RECOVERY_REQUIRED'}}
    assert R.freshness_report([a, raised]) == []
    assert any('was lowered' in p for p in R.freshness_report([raised, b]))


def test_14_boot_recovery_persists_across_sessions_and_refuses_before_the_provider(daemon_binary,
                                                                                  tmp_path):
    """§11/§4/§5: a boot that comes up in recovery stays in recovery for *every* session of that
    agent lifetime, refuses mutating work before any provider entry, keeps serving the
    recovery-safe paths -- and a session can never clear it. Only a fresh agent lifetime can."""
    env = {'PATH': '/usr/bin:/bin', 'PS4RF_HOST_FORCE_RECOVERY': '1'}
    ctl = R.ResidentController(daemon_binary, PSK, sessions=2, tmpdir=tmp_path, env=env).start()
    try:
        first = _drive(ctl, ops=(('memory.alloc', {'size': 64, 'alignment': 8}),
                                 ('session.status', {}), ('telemetry.read', {})))
        second = _drive(ctl, ops=(('memory.alloc', {'size': 64, 'alignment': 8}),
                                  ('session.status', {})))
        out = ctl.finish()
    finally:
        ctl.abort()

    for session in (first, second):
        hello = session['hello']
        assert hello['recovery_required'] is True
        assert hello['session_state'] == 'RECOVERY_REQUIRED'
        assert session['bye']['reason'] == 'CLIENT_CLOSE'
        refused = session['responses'][0]
        assert refused['status'] == 'ERROR'
        assert refused['error']['code'] == 'SESSION_RECOVERY_REQUIRED'
        status = session['responses'][1]['result']
        assert status['session_state'] == 'RECOVERY_REQUIRED'
        assert status['mutating_allowed'] is False
        assert status['held_resources'] == []
    # recovery-safe paths stay open
    assert first['responses'][2]['status'] == 'OK'
    assert isinstance(first['responses'][2]['result'], dict) and first['responses'][2]['result']

    # no session lowered the flag: the freshness rule checks exactly that
    assert R.freshness_report([{k: s[k] for k in ('hello', 'session_id', 'transcript', 'keys')}
                               for s in (first, second)]) == []
    report = out['report']
    assert report['recovery_required'] is True
    assert report['recovery_source'] == 'BOOT'
    assert report['recovery_transitions'] == 1
    assert report['exit_reason'] == 'NONE' and out['exit_code'] == 0
    assert report['sessions_served'] == 2 and report['held_after_cleanup'] == 0

    # a real agent lifecycle reset (a new lifetime, no boot recovery) is the *only* thing that
    # clears it -- not a session, not a reconnect
    ctl2 = R.ResidentController(daemon_binary, PSK, sessions=1, tmpdir=tmp_path).start()
    try:
        fresh = _drive(ctl2, ops=(('memory.alloc', {'size': 64, 'alignment': 8}),))
        out2 = ctl2.finish()
    finally:
        ctl2.abort()
    assert fresh['hello']['recovery_required'] is False
    assert fresh['hello']['session_state'] == 'READY'
    assert 'ref' in fresh['responses'][0]['result'], 'mutating work is served again'
    assert out2['report']['recovery_required'] is False
    assert out2['report']['recovery_source'] == 'NONE'


def test_15_lost_transport_never_exits_and_never_leaves_an_object(daemon_binary, tmp_path):
    """§5: five ways for a controller to vanish, none of which may end the agent or leave a
    session object behind. The agent must be serving again after each one."""
    cases = []
    # five abandoned sessions, each probed by a clean one, plus one final clean session: the run
    # budget must cover all of them, otherwise the *budget* would end the run, not the losses
    ctl = R.ResidentController(daemon_binary, PSK, sessions=2 * 5 + 1, tmpdir=tmp_path).start()
    try:
        def session_for(ops, *, idle_s=0.0):
            """One session the controller abandons mid-flight: RST, no BYE, no goodbye."""
            conn = ctl.accept_session()
            s = HostSession(SocketEndpoint(conn, timeout=20.0), PSK)
            s.handshake()
            s.recv_ready()
            ctl.accept_busy_notice()      # the agent's own §13 probe dial, refused once per session
            for index, (op, args) in enumerate(ops):
                s.request(op, args, request_id=smoke_request_id(index))
            if idle_s:
                time.sleep(idle_s)
            R.rst(conn)

        # 1. before the first request
        session_for(())
        cases.append(('before_first_request', _drive(ctl, ops=(('session.ping', {}),))['bye']['reason']))
        # 2. during idle
        session_for((), idle_s=0.3)
        cases.append(('during_idle', _drive(ctl, ops=(('session.ping', {}),))['bye']['reason']))
        # 3. after a completed read
        session_for((('telemetry.read', {}),))
        cases.append(('after_completed_read', _drive(ctl, ops=(('session.ping', {}),))['bye']['reason']))
        # 4. with an allocated userland resource the session never frees
        session_for((('memory.alloc', {'size': 4096, 'alignment': 16}),))
        cases.append(('with_held_resource', _drive(ctl, ops=(('session.ping', {}),))['bye']['reason']))
        # 5. while a refused operation is being answered
        session_for((('kernel.read', {'region_index': 0}),))
        cases.append(('during_refused_op', _drive(ctl, ops=(('session.ping', {}),))['bye']['reason']))
        # the last session ends cleanly and forgets an object on purpose: the BYE must still report
        # a COMPLETE cleanup, and the run must not end up in recovery
        last = _drive(ctl, ops=(('memory.alloc', {'size': 2048, 'alignment': 8}),
                                ('session.ping', {})))
        out = ctl.finish()
    finally:
        ctl.abort()

    # every probe session was served: the agent never exited on a lost transport
    assert [name for name, _ in cases] == ['before_first_request', 'during_idle',
                                           'after_completed_read', 'with_held_resource',
                                           'during_refused_op']
    assert all(bye == 'CLIENT_CLOSE' for _, bye in cases)
    assert last['bye']['reason'] == 'CLIENT_CLOSE'
    assert last['bye']['cleanup']['state'] == 'COMPLETE'
    assert last['bye']['cleanup']['resources'] == []

    report = out['report']
    assert out['exit_code'] == 0
    assert report['exit_reason'] == 'NONE', 'a lost transport is not an exit condition'
    assert report['stop'] == 'DRIVER_BUDGET'
    # all eleven were *served* (every one reached a session id); none failed to become a session
    assert report['sessions_served'] == 11 and report['sessions_failed'] == 0
    assert len(report['session_ids']) == 11, 'the run records the sessions it served'
    # each session's §13 refusal happened: the agent dialed back while it was busy
    assert report['busy_refusals'] >= 10
    assert report['held_after_cleanup'] == 0 and report['cleanup_refusals'] == 0
    assert report['cleanup_state'] == 'COMPLETE'
    assert report['cleanup_reaped'] >= 1, 'the forgotten object was reaped, not leaked'
    assert report['recovery_required'] is False, 'a safe cleanup does not park the boot'


def test_16_dial_backoff_is_bounded_and_touches_no_state(daemon_binary, tmp_path):
    """§6: no controller must cost time, never a busy loop and never stuck state."""
    psk_file = tmp_path / 'psk.bin'
    psk_file.write_bytes(PSK)

    def run(extra, *, env=None):
        # a port nothing listens on: every dial misses
        probe = socket.socket()
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
        probe.close()
        started = time.monotonic()
        proc = subprocess.run([str(daemon_binary), '--resident', '--connect', '127.0.0.1', str(port),
                               '--psk-file', str(psk_file), '--idle-rounds', '3', *extra],
                              capture_output=True, text=True, timeout=60,
                              env=env or {'PATH': '/usr/bin:/bin'})
        elapsed = time.monotonic() - started
        assert proc.returncode == 0, proc.stderr
        return json.loads(proc.stdout.strip().splitlines()[-1]), elapsed

    report, elapsed = run(['--idle-pause-ms', '0'])
    assert report['stop'] == 'NO_CONTROLLER' and report['exit_reason'] == 'NONE'
    # the floor is enforced even when the config asks for 0: no busy loop
    assert report['dial_backoff_us'] >= 50000
    assert report['dial_misses'] == 3 and report['dial_misses_total'] == 3
    assert elapsed >= 0.1, f'three floored pauses must take at least ~100 ms, took {elapsed:.3f}s'
    assert elapsed < 10.0, 'the backoff must not turn into an unbounded wait'
    # a missing controller touches nothing: no session, no boot change, no recovery
    assert report['sessions_served'] == 0 and report['session_ids'] == []
    assert report['recovery_required'] is False and report['recovery_source'] == 'NONE'
    assert report['recovery_transitions'] == 0
    assert report['attempts'] == 0

    # the growth is bounded by the cap: a base far above the cap still waits at most the cap
    capped, elapsed_capped = run(['--idle-pause-ms', '1000', '--backoff-max-ms', '20'])
    # a cap below the floor is lifted to the floor: the no-busy-loop guarantee wins over a
    # misconfigured cap, and the wait is still capped -- 1 s + 2 s uncapped would show in the clock
    assert capped['dial_backoff_us'] == 50000, capped['dial_backoff_us']
    assert elapsed_capped < 1.5, f'a capped backoff took {elapsed_capped:.3f}s'


def test_17_authenticated_admin_shutdown_ends_the_lifetime_cleanly(daemon_binary, tmp_path):
    """§15/§9: the producer of `ADMIN_SHUTDOWN` -- an operation inside an ACTIVE, authenticated
    session. Stop accepting new sessions, the current session cleans up, the resources are back, the
    evidence is the report, and the process leaves cleanly. No kernel change, no reboot, no loader,
    no persistence: the only thing it touches is the agent's own lifetime."""
    ctl = R.ResidentController(daemon_binary, PSK, sessions=4, tmpdir=tmp_path).start()
    try:
        conn = ctl.accept_session()
        session = HostSession(SocketEndpoint(conn, timeout=30.0), PSK)
        session.handshake()
        session.recv_ready()
        ctl.accept_busy_notice()
        # work first, so the session has something to clean up
        alloc = session.request('memory.alloc', {'size': 2048, 'alignment': 8},
                                request_id=smoke_request_id(0))
        assert 'ref' in alloc['result']
        ack = session.request('session.shutdown', {'capability': 'session.admin'},
                              request_id=smoke_request_id(1))
        bye = session.await_bye('admin shutdown')
        session.close()
        out = ctl.finish()
    finally:
        ctl.abort()

    assert ack['status'] == 'OK' and ack['result'] == {'status': 'ACCEPTED'}
    # the answer still reflects the live session (it holds the object the controller never freed);
    # the bye, sent after the session teardown, reports the state the session *ends* in
    assert ack['cleanup']['state'] == 'PENDING', ack['cleanup']
    assert bye['reason'] == 'ADMIN_SHUTDOWN'
    assert bye['cleanup'] == {'resources': [], 'state': 'COMPLETE'}, bye
    report = out['report']
    assert out['exit_code'] == 0, 'a clean shutdown is not a fault'
    assert report['exit_reason'] == 'ADMIN_SHUTDOWN'
    assert report['stop'] == 'EXIT_CONDITION' and report['state'] == 'EXITED'
    assert report['exit_detail'] == 'authenticated admin shutdown'
    # no new session was accepted: the lifetime ended instead
    assert report['attempts'] == 1 and report['sessions_served'] == 1
    assert report['held_after_cleanup'] == 0 and report['cleanup_state'] == 'COMPLETE'
    assert report['cleanup_reaped'] >= 1, 'the session object was reaped before the exit'
    assert ctl.proc.poll() is not None, 'the agent process is gone'


def test_18_unauthenticated_and_unauthorised_attempts_are_refused(daemon_binary, tmp_path):
    """§15: the shutdown is authenticated (it needs an established session) and authorised (it needs
    the capability the catalogue binds to it). Neither a pre-handshake attempt nor a wrong claim may
    end the agent -- an unauthenticated peer with a kill switch is exactly what must not exist."""
    ctl = R.ResidentController(daemon_binary, PSK, sessions=1, tmpdir=tmp_path).start()
    try:
        conn = ctl.accept_session()
        session = HostSession(SocketEndpoint(conn, timeout=30.0), PSK)
        session.handshake()
        session.recv_ready()
        # (a) an unauthenticated attempt: the agent's own §13 refusal connection is a peer without a
        #     session -- asking it for a shutdown must be answered with the refusal, never served
        probe = ctl.accept_session()
        probe.settimeout(10.0)
        raw = probe.recv(4096)
        notice = R.parse_busy_notice(raw)
        assert notice['msg'] == 'SESSION_BUSY' and notice['active_sessions'] == 1
        assert 'session.shutdown' not in raw.decode()
        try:
            probe.sendall(b'{"body":{"operation":"session.shutdown","arguments":'
                          b'{"capability":"session.admin"}},'
                          b'"header":{"request_id":"REQ-00000000000000000000000000000000","seq":0}}\n')
            closed = probe.recv(64) == b''
        except OSError:
            closed = True
        assert closed, 'the refusal connection is closed: nothing is served on it'
        probe.close()

        # (b) a wrong capability inside a real session: refused, and the session lives on
        refused = session.request('session.shutdown', {'capability': 'kernel.read'},
                                  request_id=smoke_request_id(0))
        assert refused['status'] == 'ERROR'
        assert refused['error']['code'] == 'CAPABILITY_REQUIRED'
        still = session.request('session.ping', {}, request_id=smoke_request_id(1))
        assert still['result']['pong'] is True, 'a refused shutdown does not end the session'
        # (c) a second wrong claim, this time without the argument at all
        missing = session.request('session.shutdown', {}, request_id=smoke_request_id(2))
        assert missing['error']['code'] in ('ARGUMENT_INVALID', 'CAPABILITY_REQUIRED')
        session.ep.shutdown_write()
        bye = session.await_bye('host half close')
        session.close()
        out = ctl.finish()
    finally:
        ctl.abort()

    assert bye['reason'] == 'CLIENT_CLOSE', 'only an accepted shutdown ends the lifetime'
    report = out['report']
    assert out['exit_code'] == 0 and report['exit_reason'] == 'NONE'
    assert report['stop'] == 'DRIVER_BUDGET', 'the agent stayed resident after the attempts'
    assert report['sessions_served'] >= 1
    assert report['recovery_required'] is False, 'an unauthorised attempt changes no boot state'


def test_19_admin_shutdown_is_recovery_safe_and_scoped_to_the_resident_mode(daemon_binary, tmp_path):
    """§15: the policy says the operation is recovery-safe -- a controller that has to stop an agent
    whose boot is in recovery must be able to -- and it is served *only* by the resident agent: the
    single-session profiles keep exactly the served set they had."""
    # (a) recovery boot: the shutdown is served
    env = {'PATH': '/usr/bin:/bin', 'PS4RF_HOST_FORCE_RECOVERY': '1'}
    ctl = R.ResidentController(daemon_binary, PSK, sessions=1, tmpdir=tmp_path, env=env).start()
    try:
        conn = ctl.accept_session()
        session = HostSession(SocketEndpoint(conn, timeout=30.0), PSK)
        hello = session.handshake()
        session.recv_ready()
        ctl.accept_busy_notice()
        ack = session.request('session.shutdown', {'capability': 'session.admin'},
                              request_id=smoke_request_id(0))
        bye = session.await_bye('admin shutdown in recovery')
        session.close()
        out = ctl.finish()
    finally:
        ctl.abort()
    assert hello['recovery_required'] is True and hello['session_state'] == 'RECOVERY_REQUIRED'
    assert ack['status'] == 'OK' and ack['result'] == {'status': 'ACCEPTED'}
    assert bye['reason'] == 'ADMIN_SHUTDOWN'
    assert out['report']['exit_reason'] == 'ADMIN_SHUTDOWN' and out['exit_code'] == 0
    assert out['report']['recovery_required'] is True, 'the boot flag survives the shutdown'

    # (b) the single-session driver: the operation is deferred, the served set is unchanged
    psk_file = tmp_path / 'psk.bin'
    psk_file.write_bytes(PSK)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    proc = subprocess.Popen([str(daemon_binary), '--connect', '127.0.0.1', str(port),
                             '--psk-file', str(psk_file), '--lifetime', '30', '--idle', '30'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env={'PATH': '/usr/bin:/bin'})
    try:
        conn, _ = listener.accept()
        session = HostSession(SocketEndpoint(conn, timeout=20.0), PSK)
        session.handshake()
        session.recv_ready()
        deferred = session.request('session.shutdown', {'capability': 'session.admin'},
                                   request_id=smoke_request_id(0))
        assert deferred['status'] == 'ERROR', deferred
        assert deferred['error']['code'] == 'OPERATION_DEFERRED', deferred
        session.ep.shutdown_write()
        session.await_bye('host half close')
        session.close()
        stdout, _ = proc.communicate(timeout=30)
    finally:
        listener.close()
        if proc.poll() is None:
            proc.kill()
    # the single-session profile served exactly one session and refused the operation
    assert '"served": 1' in stdout and '"bye_reason": "CLIENT_CLOSE"' in stdout, stdout


def test_20_evidence_has_a_lifetime_and_a_session_record_per_session(daemon_binary, tmp_path):
    """§18: two evidence levels. The daemon-lifetime record carries the boot facts, the recovery
    history and the exit reason; every session that became a session has its own record (what it
    was, did, held and how it ended). Every session record belongs to the lifetime, and every
    session the host drove must be found in it -- evidence that cannot be tied to a lifetime is not
    evidence."""
    ctl = R.ResidentController(daemon_binary, PSK, sessions=2, tmpdir=tmp_path).start()
    driven = []
    try:
        for _ in range(2):
            result = _drive(ctl, ops=(('session.ping', {}),
                                      ('memory.alloc', {'size': 256, 'alignment': 16})))
            driven.append(result['session_id'])
        out = ctl.finish()
    finally:
        ctl.abort()

    report = out['report']
    assert R.lifetime_evidence(report, driven) == [], R.lifetime_evidence(report, driven)
    # the lifetime half
    assert report['lifetime_id'].startswith('LIFE-host-standin-'), report['lifetime_id']
    assert report['recovery_source'] == 'NONE' and report['recovery_transitions'] == 0
    assert report['exit_reason'] == 'NONE' and report['boot_inputs'] in ('MEASURED', 'UNRESOLVED')
    # the session half: one record per session, in order, each with its own facts
    records = report['session_records']
    assert [rec['session_id'] for rec in records] == driven
    assert report['session_records_total'] == 2
    for rec in records:
        assert rec['bye'] == 'CLIENT_CLOSE'
        assert rec['cleanup_state'] == 'COMPLETE' and rec['held_after_cleanup'] == 0
        assert rec['reaped'] >= 1, 'the object the session forgot was reaped, and recorded'
        assert rec['requests'] == 2 and rec['provider_entries'] >= 1
        assert rec['violations'] == 0 and rec['recovery_at_start'] is False
        assert rec['boot_recheck_ok'] is True, '§5: the boot inputs were re-checked per session'
    # the evidence carries no key material and no host input
    text = json.dumps(report)
    assert PSK.hex() not in text and PSK[:8].hex() not in text


def test_21_fifty_plus_sessions_stay_bounded_and_clean(daemon_binary, tmp_path):
    """§17: 50+ sequential sessions, offline. After every one: nothing held, nothing pending, no
    session secret, RESIDENT_IDLE again. The registries stay bounded and the process does not grow:
    a resident agent that leaks per session is not a resident agent."""
    count = 60
    ctl = R.ResidentController(daemon_binary, PSK, sessions=count, tmpdir=tmp_path,
                               accept_timeout=60.0).start()
    driven, statuses = [], []
    try:
        for index in range(count):
            result = _drive(ctl, ops=(('session.ping', {}),
                                      ('session.status', {}),
                                      ('memory.alloc', {'size': 128, 'alignment': 8})))
            driven.append(result['session_id'])
            statuses.append(result['responses'][1]['result'])
            # every session ends the same way, whatever it did inside
            assert result['bye']['cleanup'] == {'resources': [], 'state': 'COMPLETE'}
            assert result['bye']['reason'] == 'CLIENT_CLOSE'
            if index == 1:
                first = _process_footprint(ctl.proc.pid)
            elif index == count - 2:
                # before the last session: the daemon exits when its budget is spent
                last = _process_footprint(ctl.proc.pid)
        out = ctl.finish()
    finally:
        ctl.abort()

    report = out['report']
    # per session: the invariants the reviewer named
    assert len(set(driven)) == count, 'every session got its own session id'
    for status in statuses:
        assert status['held_resources'] == [], status
        assert status['mutating_allowed'] is True and status['session_state'] == 'ACTIVE'
    assert report['sessions_served'] == count and report['sessions_failed'] == 0
    assert report['exit_reason'] == 'NONE' and report['stop'] == 'DRIVER_BUDGET'
    assert report['held_after_cleanup'] == 0 and report['cleanup_refusals'] == 0
    assert report['recovery_required'] is False
    # the registries are bounded: the evidence list keeps its capacity, the ids ring its own, and
    # the totals count the whole run
    assert len(report['session_records']) == R.SESSION_RECORD_CAPACITY
    assert report['session_records_total'] == count
    assert len(report['session_ids']) == min(count, R.SESSION_ID_CAPACITY)
    assert R.lifetime_evidence(report, driven) == [], R.lifetime_evidence(report, driven)
    # and the process did not grow with the run
    assert last['fds'] <= first['fds'] + 2, (first, last)
    assert last['rss_kb'] <= first['rss_kb'] + 4096, (first, last)


def _process_footprint(pid: int) -> dict:
    """Open descriptors and resident size of the agent process -- the leak evidence of §17."""
    import os
    with open(f'/proc/{pid}/status') as handle:
        rss = next(line for line in handle if line.startswith('VmRSS:')).split()[1]
    return {'fds': len(os.listdir(f'/proc/{pid}/fd')), 'rss_kb': int(rss)}


def test_22_two_session_end_to_end_with_derivation_and_admin_shutdown(daemon_binary, tmp_path):
    """§11 (§16): the full offline end-to-end the reviewer described.

    Session A: handshake, status, a bounded allowed operation, BYE, cleanup COMPLETE -- the agent
    stays resident. Session B: a *new* handshake, a new session id, new nonce and keys, the stored
    VerificationEvidence is reloaded, rehashed and re-bound to this session as a new SESSION
    capability, a bounded operation, BYE, cleanup COMPLETE -- the agent is still resident. Then the
    authenticated admin shutdown ends the lifetime with exit 0.
    """
    sys.path.insert(0, str(REPO))
    from tools.hostctl import kreadlive as KL
    from tools.hostctl import kreadstore as KS
    from tools.hostctl import sessioncaps as SC

    # --- the host side of §4/§6: one store, one ledger, one derivation per session
    store = KS.VerificationEvidenceStore(tmp_path / 'evidence')
    verification = KL.run_verification(
        KL.OfflineSession(session_id=KL.SIM_SESSION_A,
                          event=KL.synthetic_bounded_event(runtime_kbase=KL.SIM_KBASE)),
        profile=KL.synthetic_profile()[0], boot_binding=KL.synthetic_boot_binding(
            KL.synthetic_profile()[0]), store=store,
        provider=KL.sim_provider(live_approved=False), verification_run_id=KL.SIM_VERIFICATION_RUN,
        read_run_id=KL.SIM_BOOT_READ_RUN)
    evidence_sha = verification['evidence']['evidence_sha256']
    profile, profile_sha = KL.synthetic_profile()
    binding = KL.synthetic_boot_binding(profile)

    ctl = R.ResidentController(daemon_binary, PSK, sessions=3, tmpdir=tmp_path).start()
    ledger = SC.ResidentCapabilityLedger(lifetime_id='LIFE-pending')      # rebound to the report
    try:
        # ---- session A
        first = _drive(ctl, ops=(('session.status', {}),
                                 ('memory.alloc', {'size': 512, 'alignment': 16})))
        assert first['bye']['reason'] == 'CLIENT_CLOSE'
        assert first['bye']['cleanup'] == {'resources': [], 'state': 'COMPLETE'}
        assert first['responses'][0]['result']['session_state'] == 'ACTIVE'
        assert first['responses'][0]['result']['held_resources'] == []

        # ---- session B: a new session in the same lifetime, with its own capability
        second = _drive(ctl, ops=(('session.ping', {}),
                                  ('memory.alloc', {'size': 512, 'alignment': 16})))
        assert second['bye']['cleanup']['state'] == 'COMPLETE'
    finally:
        pass

    # the host derives the capability for each session from the *stored, rehashed* evidence
    kwargs = dict(store=store, evidence_sha256=evidence_sha, run_id=KL.SIM_BOOT_READ_RUN,
                  profile_sha256=profile_sha, boot_id=binding.boot_id, provider=KL.sim_provider(),
                  context=KL.CONTEXT, approval=KL.SIM_APPROVAL,
                  expected=KL.bootstrap_expectation(profile))
    record_a = ledger.derive_for_session(session_id=first['session_id'], **kwargs)
    record_b = ledger.derive_for_session(session_id=second['session_id'], **kwargs)
    assert record_a['assurance'] == 'PROVEN' and record_b['assurance'] == 'PROVEN'
    assert record_a['session_id'] == first['session_id'] != second['session_id']
    assert record_a['derivation']['receipt_id'] != record_b['derivation']['receipt_id']
    assert ledger.accept(record_b, session_id=second['session_id'], store=store,
                         boot_id=binding.boot_id, profile_sha256=profile_sha) == []
    with pytest.raises(KL.DerivationRejected):
        ledger.accept(record_a, session_id=second['session_id'], store=store,
                      boot_id=binding.boot_id, profile_sha256=profile_sha)

    # same agent, same identity, nothing session-bound carried over between the two sessions
    assert R.freshness_report([{k: s[k] for k in ('hello', 'session_id', 'transcript', 'keys')}
                               for s in (first, second)]) == []
    assert first['session_id'] != second['session_id']
    assert first['hello']['nonce'] != second['hello']['nonce']

    # ---- the authenticated admin shutdown ends the lifetime
    try:
        conn = ctl.accept_session()
        session = HostSession(SocketEndpoint(conn, timeout=30.0), PSK)
        session.handshake()
        session.recv_ready()
        ctl.accept_busy_notice()
        ack = session.request('session.shutdown', {'capability': 'session.admin'},
                              request_id=smoke_request_id(0))
        bye = session.await_bye('admin shutdown after two sessions')
        session.close()
        out = ctl.finish()
    finally:
        ctl.abort()

    assert ack['result'] == {'status': 'ACCEPTED'} and bye['reason'] == 'ADMIN_SHUTDOWN'
    report = out['report']
    assert out['exit_code'] == 0 and report['exit_reason'] == 'ADMIN_SHUTDOWN'
    assert report['sessions_served'] == 3 and report['session_records_total'] == 3
    # the agent lifetime the capability ledger was bound to is the one the report names
    assert report['lifetime_id'].startswith('LIFE-host-standin-')
    assert R.lifetime_evidence(report, [first['session_id'], second['session_id'],
                                       session.session_id]) == []


def test_23_no_batch_or_multi_read_interface_was_promoted():
    """§15 (review): a resident agent serves many sessions, but every research authorisation stays
    exactly as explicit as it was -- no batch interface, no multi-read, no implicit rearm. The wave
    added one *lifetime* operation (`session.shutdown`) and nothing else."""
    schema = (pathlib.Path(REPO) / 'tools' / 'primitive_iface' / 'schema.py').read_text()
    names = re.findall(r"Op\('([a-z_.]+)'", schema)
    assert names, 'the interface table must be readable'
    banned = [name for name in names
              if any(word in name for word in ('batch', 'multi', 'bulk', 'sweep'))]
    assert banned == [], f'a batch-shaped operation appeared: {banned}'
    # the kernel namespace is the interface table's own kernel surface (no literal list), and the
    # W17E additions are named: the bounded recipe read and the generic ioctl invoke.
    assert sorted(name for name in names if name.startswith('kernel.')) == \
        sorted(op.op for op in SCHEMA.OPS if op.op.startswith('kernel.'))
    # W17E restated this row: the kernel namespace grew by exactly the bounded recipe read, which
    # is an operation of its own (its own frozen argument form, no raw address) rather than a
    # widened kernel.read. Every op the target wires as a privileged provider must stay
    # address-free and bounded; the raw explicit-range form exists only as a *deferred* interface.
    assert 'kernel.snapshot.recipe' in names and 'ioctl.invoke' in names
    wired_privileged = [name for name in _authoritative_wired_ops()
                        if name in ('kernel.read', 'kernel.snapshot.recipe', 'ioctl.invoke')]
    assert wired_privileged == ['ioctl.invoke', 'kernel.read', 'kernel.snapshot.recipe'], \
        wired_privileged
    for op_name in wired_privileged:
        fields = [f.name for f in SCHEMA.OPS_BY_NAME[op_name].args]
        assert not {'addr', 'size', 'address'} & set(fields), (op_name, fields)
    assert SCHEMA.OPS_BY_NAME['kernel.snapshot'].status == SCHEMA.STATUS_DEFER_PRIVILEGE
    assert 'kernel.snapshot' not in _authoritative_wired_ops(), \
        'the raw explicit-range read must not be reachable through a wired target route'
    assert 'session.shutdown' in names and len(names) == len(SCHEMA.OPS)
    # the one-shot guard stays a *session* entry re-arm: one release buys one provider entry
    stub = _code('ps4rf_stub.c')
    assert 'ps4rf_stub_session_begin' in stub
    kread = _code('ps4rf_kread.c')
    assert kread.count('ps4rf_stub_session_begin') == 0, 'the re-arm lives in the router entry'
    assert 'called' in kread, 'the one-shot guard is still there'


# ------------------------------------------------------- 5. the daemon is in both builds

def test_daemon_is_compiled_into_the_console_build_too():
    """The console artefact carries the daemon module (its entry point still uses the single
    session path until the §19 artefact step; an unused module is not a behaviour change)."""
    ps4 = (TARGET / 'build_ps4.sh').read_text()
    host = (TARGET / 'build_host.sh').read_text()
    assert 'ps4rf_daemon.c' in ps4 and 'ps4rf_daemon.o' in ps4
    assert 'ps4rf_daemon.c' in host
    # no forbidden platform call sneaked in with the new module
    code = _code('ps4rf_daemon.c')
    for forbidden in ('kexec', 'system(', 'fopen(', 'pfs', 'klog', '9090'):
        assert forbidden not in code, f'the daemon module contains {forbidden}'
