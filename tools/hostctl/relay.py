"""Relay helpers for the live harness: push + start the half-close aware relay on the relay
host, open the two SSH tunnels the topology needs, and tear everything down.

Topology (console agent is the TCP client, exactly like the PS4):
    PS4 agent  --connect-->  relay_host:payload_port --> relay --> 127.0.0.1:host_port
    research side  --ssh -L-->  127.0.0.1:host_port

Nothing here touches the console or the loader port; the relay only ever listens on the two
ports it is given.
"""

from __future__ import annotations

import pathlib
import shlex
import socket
import subprocess
import time

RELAY_SCRIPT = pathlib.Path(__file__).resolve().parent.parent / 'relay' / 'half_close_bridge.py'
REMOTE_SCRIPT = '/tmp/ps4rf_half_close_bridge.py'


def _run_ssh(ssh_target: str, command: str, timeout: float = 30.0) -> subprocess.CompletedProcess:
    return subprocess.run(['ssh', '-o', 'BatchMode=yes', ssh_target, command],
                          capture_output=True, text=True, timeout=timeout)


def free_local_port() -> int:
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def push_and_start(ssh_target: str, payload_port: int, host_port: int, lifetime: float,
                   script: pathlib.Path | None = None) -> dict:
    local = script or RELAY_SCRIPT
    pushed = subprocess.run(['scp', '-q', str(local), f'{ssh_target}:{REMOTE_SCRIPT}'],
                            capture_output=True, text=True, timeout=60)
    if pushed.returncode != 0:
        raise RuntimeError(f'scp failed: {pushed.stderr.strip()}')
    command = (f'nohup python3 {shlex.quote(REMOTE_SCRIPT)} --payload-port {payload_port} '
               f'--host-port {host_port} --lifetime {lifetime} '
               f'> /tmp/ps4rf_relay.log 2>&1 & echo $!')
    started = _run_ssh(ssh_target, command, timeout=30)
    pid = started.stdout.strip().splitlines()[-1] if started.stdout.strip() else ''
    ready = False
    for _ in range(40):
        time.sleep(0.25)
        log = _run_ssh(ssh_target, 'cat /tmp/ps4rf_relay.log 2>/dev/null', timeout=15)
        if 'RELAY-READY' in log.stdout:
            ready = True
            break
    return {'ok': ready, 'pid': pid, 'ssh_target': ssh_target, 'payload_port': payload_port,
            'host_port': host_port, 'script': str(local),
            'log': _run_ssh(ssh_target, 'cat /tmp/ps4rf_relay.log 2>/dev/null', timeout=15).stdout}


def relay_log(ssh_target: str) -> str:
    return _run_ssh(ssh_target, 'cat /tmp/ps4rf_relay.log 2>/dev/null', timeout=15).stdout


def stop(ssh_target: str) -> str:
    return _run_ssh(ssh_target,
                    'pkill -f ps4rf_half_close_bridge.py && echo RELAY-STOPPED || echo no-relay',
                    timeout=20).stdout.strip()


def local_listener_present(local_port: int) -> bool:
    """Is the local end of the tunnel bound? Checked with ss only.

    Never probe the tunnel with a connection: the relay has a *single* accept per side, so a
    probe would be forwarded to the relay and consume it (that is exactly the mistake the W8
    rules forbid for the loader port, and the same reasoning applies here).
    """
    try:
        out = subprocess.run(['ss', '-lnt'], capture_output=True, text=True, timeout=10).stdout
    except Exception:  # pragma: no cover - ss missing
        return True
    return f'127.0.0.1:{local_port} ' in out or f'127.0.0.1:{local_port}\t' in out


def open_tunnel(ssh_target: str, local_port: int, remote_port: int) -> subprocess.Popen:
    proc = subprocess.Popen(['ssh', '-o', 'BatchMode=yes', '-N',
                             '-o', 'ExitOnForwardFailure=yes',
                             '-L', f'{local_port}:127.0.0.1:{remote_port}', ssh_target],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    for _ in range(60):
        time.sleep(0.2)
        if proc.poll() is not None:
            raise RuntimeError(f'ssh tunnel died: {proc.stderr.read() if proc.stderr else ""}')
        if local_listener_present(local_port):
            return proc
    return proc


def close_tunnel(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover
        proc.kill()
