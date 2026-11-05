"""W14 live run sheet, proved offline before it is ever pointed at a console.

`tools/hostctl/live_w14.py` is the controller the live bring-up uses. The only difference between
this test and the live run is *who* dials in: here the dev-host build of the very same daemon
(`ps4rfd_host --resident`) dials the controller, live the console payload does. So the sequence,
the freshness/stability comparison, the residency proof, the admin shutdown and the silence
afterwards are all exercised for real -- offline, before any upload is authorised.
"""
from __future__ import annotations

import json
import pathlib
import socket
import subprocess
import sys
import time

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
PSK = bytes(range(1, 33))
DEV_HOST = pathlib.Path('/home/hermes/.hermes/cache/scratch/ps4rf-w14/dev-host/ps4rfd_host')


def free_port() -> int:
    probe = socket.socket()
    probe.bind(('127.0.0.1', 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _run(tmp_path: pathlib.Path, *, gap: float, silent: float) -> dict:
    if not DEV_HOST.exists():
        raise AssertionError(f'the dev-host daemon is missing: {DEV_HOST}')
    psk_file = tmp_path / 'psk.bin'
    psk_file.write_bytes(PSK)
    port = free_port()
    out = tmp_path / 'evidence'
    out.mkdir()

    controller = subprocess.Popen(
        [sys.executable, str(REPO / 'tools' / 'hostctl' / 'live_w14.py'), '--listen', '127.0.0.1',
         '--port', str(port), '--psk-file', str(psk_file), '--out', str(out),
         '--gap-sec', str(gap), '--no-redial-sec', str(silent), '--reconnect-timeout', '60',
         '--no-health'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # the listener has to be up before the agent starts dialling -- and it must be probed *without*
    # connecting: a connection to the controller port is a session attempt by definition
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        probe = socket.socket()
        try:
            probe.bind(('127.0.0.1', port))
        except OSError:
            probe.close()
            break
        probe.close()
        time.sleep(0.05)
    else:
        controller.kill()
        raise AssertionError('the live controller never opened its listener')

    driver = subprocess.Popen(
        # the session budget is a *run* bound, not a session count: the sheet's three sessions must
        # not be consumed by a refused attempt, and the lifetime ends with the admin shutdown
        [str(DEV_HOST), '--resident', '--connect', '127.0.0.1', str(port), '--psk-file',
         str(psk_file), '--sessions', '0', '--idle-rounds', '0', '--idle-pause-ms', '250',
         '--backoff-max-ms', '2000', '--lifetime', '600', '--idle', '600',
         '--label', 'ps4rfd-live-w14', '--context', 'fw13-52-resident-w14'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env={'PATH': '/usr/bin:/bin'})

    controller_out, controller_err = controller.communicate(timeout=300)
    if controller.returncode != 0:
        driver.kill()
        driver.communicate(timeout=30)
        raise AssertionError((controller_err[-2000:], controller_out[-500:]))
    try:
        driver_out, driver_err = driver.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        driver.kill()
        driver_out, driver_err = driver.communicate()
        raise AssertionError('the daemon did not end its run; the admin shutdown did not take '
                             f'effect (stdout tail: {driver_out[-400:]!r})') from None
    evidence = json.loads((out / 'w14-live-evidence.json').read_text())
    evidence['_controller_stdout'] = controller_out.strip()
    evidence['_driver_report'] = json.loads(driver_out.strip().splitlines()[-1])
    evidence['_driver_exit'] = driver.returncode
    evidence['_driver_stderr'] = driver_err[-400:]
    return evidence


def test_the_live_run_sheet_passes_offline_against_the_same_daemon(tmp_path):
    evidence = _run(tmp_path, gap=1.0, silent=3.0)

    assert evidence['verdict'] == 'PASS', evidence.get('stop_reason')
    steps = {step['step']: step for step in evidence['steps']}
    assert set(steps) == {'session_a', 'controller_gap', 'resident_proof', 'session_b', 'session_c',
                          'after_admin_shutdown'}

    # one session each, in order, with the operations the run sheet names
    a, b, c = steps['session_a']['facts'], steps['session_b']['facts'], steps['session_c']['facts']
    assert [r['operation'] for r in a['requests']] == ['session.ping', 'session.status',
                                                       'telemetry.read', 'session.status']
    assert [r['operation'] for r in b['requests']] == ['session.ping', 'session.status',
                                                       'telemetry.read']
    assert [r['operation'] for r in c['requests']] == ['session.status', 'session.shutdown']
    assert c['bye'] == 'ADMIN_SHUTDOWN' and a['bye'] == b['bye'] == 'CLIENT_CLOSE'
    for facts in (a, b, c):
        assert facts['cleanup'] == {'resources': [], 'state': 'COMPLETE'}

    # nothing session-bound is reused; everything lifetime-bound is stable
    assert evidence['comparison']['problems'] == []
    for field in ('session_id', 'nonce_sha256', 'transcript_sha256',
                  'directional_keys_fingerprint'):
        values = list(evidence['comparison']['fresh'][field].values())
        assert len(set(values)) == 3, f'{field} was reused: {values}'
    for field in ('build_id', 'platform', 'agent_version'):
        values = list(evidence['comparison']['stable'][field].values())
        assert len(set(json.dumps(v) for v in values)) == 1, f'{field} drifted: {values}'

    # the agent survived the gap and dialled again on its own
    assert steps['resident_proof']['agent_dialled_on_its_own'] is True
    assert steps['resident_proof']['reconnect_after_s'] < 60.0
    # ... and stayed silent after the admin shutdown
    assert steps['after_admin_shutdown']['redialled_within_s'] is None

    # the agent side agrees: three sessions served, one lifetime, an admin ending
    report = evidence['_driver_report']
    assert report['sessions_served'] == 3
    assert report['exit_reason'] == 'ADMIN_SHUTDOWN' and report['stop'] == 'EXIT_CONDITION'
    assert report['recovery_required'] == 0 and report['held_after_cleanup'] == 0
    assert report['cleanup_state'] == 'COMPLETE' and report['cleanup_refusals'] == 0
    # the controller gap is visible agent-side as dial misses (the consecutive counter is reset by
    # the session that follows, the total is not)
    assert report['session_records_total'] == 3 and report['dial_misses_total'] >= 1
    assert report['busy_refusals'] >= 1, 'the §13 refusal must have been exercised at least once'
    assert evidence['_driver_exit'] == 0, evidence['_driver_stderr']


def test_the_silence_check_can_actually_see_a_redial(tmp_path):
    """The stop rule's producer, tested in both directions on the real function.

    "the agent must not dial again" is only worth something if a dial *would* be seen: the same
    `wait_for_dial` that reports silence here reports a connection when one arrives.
    """
    import threading

    from tools.hostctl import live_w14 as LW

    port = free_port()
    ctl = LW.LiveController('127.0.0.1', port, PSK, accept_timeout=5.0)
    ctl.open()
    try:
        assert ctl.wait_for_dial(1.0) is None, 'silence must read as silence'

        def knock():
            time.sleep(0.2)
            with socket.create_connection(('127.0.0.1', port), timeout=5.0) as sock:
                # a *speaking* connection: the agent's redial would carry a HELLO, and a silent
                # connection is not a session attempt (it is skipped as a stray, by design)
                sock.sendall(b'{"body":{}}\n')
                time.sleep(0.2)

        thread = threading.Thread(target=knock)
        thread.start()
        waited = ctl.wait_for_dial(5.0)
        thread.join()
        assert waited is not None and waited >= 0.0, 'a connection must read as a connection'
    finally:
        ctl.close()
