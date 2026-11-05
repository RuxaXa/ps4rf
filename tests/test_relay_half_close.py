"""Half-close / BYE regression tests for the PS4RF live harness.

The W8 live run lost the agent's BYE because the relay (OrbisProbe's ``console_bridge.py``)
tears both sockets down with ``shutdown(SHUT_RDWR)`` as soon as one direction ends. The BYE
is sent *after* the host's half close, so it could never traverse. These tests pin the fixed
behaviour: ``tools/relay/half_close_bridge.py`` half-closes only the write side it owns and
keeps the reverse direction alive, and the full offline topology (agent connects out -> relay
-> controller) captures the BYE.
"""

from __future__ import annotations

import pathlib
import socket
import subprocess
import sys
import time

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
RELAY = REPO_ROOT / 'tools' / 'relay' / 'half_close_bridge.py'
AGENT = REPO_ROOT / 'native' / 'build' / 'target-host' / 'ps4rfd_host'


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def start_relay(payload_port: int, host_port: int, lifetime: float = 30.0) -> subprocess.Popen:
    proc = subprocess.Popen([sys.executable, str(RELAY), '--payload-port', str(payload_port),
                             '--host-port', str(host_port), '--lifetime', str(lifetime)],
                            stdout=subprocess.PIPE, text=True)
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if 'RELAY-READY' in line:
            return proc
    proc.kill()
    raise RuntimeError('relay did not become ready')


def stop(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover
        proc.kill()


def test_relay_delivers_a_frame_sent_after_the_host_half_close():
    """The exact BYE situation: host half-closes first, agent speaks afterwards."""
    payload_port, host_port = free_port(), free_port()
    relay = start_relay(payload_port, host_port)
    try:
        agent = socket.create_connection(('127.0.0.1', payload_port), timeout=10)
        host = socket.create_connection(('127.0.0.1', host_port), timeout=10)
        agent.settimeout(10)
        host.settimeout(10)
        try:
            host.sendall(b'REQUEST')
            assert agent.recv(7) == b'REQUEST'
            agent.sendall(b'RESPONSE')
            assert host.recv(8) == b'RESPONSE'

            host.shutdown(socket.SHUT_WR)          # controlled exit trigger (W8)
            assert agent.recv(3) == b''            # the agent sees EOF on its read side
            agent.sendall(b'BYE')                  # ... and answers with its BYE
            assert host.recv(3) == b'BYE'          # which must still reach the host
        finally:
            agent.close()
            host.close()
    finally:
        stop(relay)


def test_relay_propagates_both_half_closes():
    payload_port, host_port = free_port(), free_port()
    relay = start_relay(payload_port, host_port)
    try:
        agent = socket.create_connection(('127.0.0.1', payload_port), timeout=10)
        host = socket.create_connection(('127.0.0.1', host_port), timeout=10)
        agent.settimeout(10)
        host.settimeout(10)
        try:
            agent.sendall(b'PING')
            assert host.recv(4) == b'PING'
            agent.shutdown(socket.SHUT_WR)
            assert host.recv(1) == b''            # agent's half close reaches the host too
            host.sendall(b'LAST')
            # the reverse direction is gone, so the socket eventually errors or is closed
            try:
                assert agent.recv(4) in (b'', b'LAST')
            except OSError:
                pass
        finally:
            agent.close()
            host.close()
    finally:
        stop(relay)


@pytest.mark.skipif(not AGENT.exists(),
                    reason='host build missing (run native/target/build_host.sh)')
def test_full_offline_topology_captures_the_bye(tmp_path):
    """Same topology as the live run, with the host build of the agent standing in for the PS4:
    the agent connects *out* to the relay, the controller connects through the other side."""
    sys.path.insert(0, str(REPO_ROOT))
    from tools.hostctl import smoke, evidence
    from tools.hostctl.cli import drive
    from tools.hostctl.endpoint import SocketEndpoint
    from tools.hostctl.session import HostSession

    payload_port, host_port = free_port(), free_port()
    relay = start_relay(payload_port, host_port)
    psk = tmp_path / 'psk.bin'
    psk.write_bytes(bytes(range(1, 33)))
    agent_proc = None
    try:
        agent_proc = subprocess.Popen(
            [str(AGENT), '--connect', '127.0.0.1', str(payload_port), '--psk-file', str(psk),
             '--label', 'relay-offline-agent', '--context', 'offline-relay',
             '--lifetime', '60', '--idle', '30'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 10.0
        host = None
        while time.monotonic() < deadline:
            try:
                host = socket.create_connection(('127.0.0.1', host_port), timeout=5)
                break
            except OSError:
                time.sleep(0.1)
        assert host is not None, 'controller could not reach the relay'
        host.settimeout(30)
        ep = SocketEndpoint(host, timeout=30)
        session = HostSession(ep, psk.read_bytes())
        rec = evidence.RunRecord(run_id='RUN-relay-offline', mode='relay-selftest',
                                 repo={'commit': 'offline'}, payload={'bin_sha256': None},
                                 transport={'kind': 'reverse-tcp-through-relay'})
        result = drive(session, rec, actor_label='offline relay agent')
        assert result['ok'] is True, [c for c in rec.doc['checks'] if not c['ok']]
        assert len(rec.doc['requests']) == len(smoke.sequence())
        # the whole point: the BYE arrives through the relay after the host's half close
        assert result['bye'] is not None, 'BYE lost - half close regression'
        assert result['bye']['reason'] == 'CLIENT_CLOSE'
        assert session.bye is not None
        assert session.bye_raw, 'BYE frame bytes missing'
        agent_proc.wait(timeout=15)
        assert agent_proc.returncode == 0, agent_proc.stderr.read()
    finally:
        stop(relay)
        if agent_proc and agent_proc.poll() is None:  # pragma: no cover
            agent_proc.kill()
