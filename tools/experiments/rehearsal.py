"""W17F: the offline end-to-end RPC rehearsal (phase 5) and the driver the live run reuses.

The rehearsal is the full path, with nothing short-circuited:

    experiment (frozen q6.py / own1.py)
      -> host RPC (HostSession, the frozen handshake/request frames)
        -> ps4rfd (a host build of the same agent the console runs, same dispatch, same providers)
          -> provider (ps4rf_recipe_run / ps4rf_ioctl_invoke)
            -> response (validated against the frozen response schema)
              -> the experiment's own classifier

The console side of that run is a *tape* (see tools/experiments/tape.py): the recorded answers of
the experiment layer's simulated console, replayed by tests/harness/ps4rf_recipe_sim.c. So the
classification the RPC path produces must equal the classification the simulation produced, and
both must equal the oracle vector -- a divergence is a wiring fault, not a modelling choice.

The same ``run_experiment`` is what the live run calls with a live session; only the platform seam
differs (a console instead of the tape player).
"""
from __future__ import annotations

import json
import os
import pathlib
import secrets
import socket
import subprocess
import time

from tools.experiments import q6, tape
from tools.experiments.rpc import RpcTarget
from tools.hostctl.endpoint import SocketEndpoint, listen
from tools.hostctl.session import HostSession

REPO = pathlib.Path(__file__).resolve().parents[2]
HOST_BUILD = REPO / 'native' / 'target' / 'build_host.sh'
OWN1 = __import__('tools.experiments.own1', fromlist=['own1'])


def free_port() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return int(s.getsockname()[1])


def build_rehearsal_agent(out_dir: pathlib.Path, host: str, port: int) -> pathlib.Path:
    env = dict(os.environ, PS4RF_TARGET_RECIPE='1', PS4RF_TARGET_IOCTL='1',
               PS4RF_TARGET_RECIPE_SIM='1', PS4RF_TARGET_IOCTL_SIM='1',
               PS4RF_AGENT_HOST=host, PS4RF_AGENT_PORT=str(port))
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(['sh', str(HOST_BUILD), str(out_dir)], env=env,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError('rehearsal build failed: ' + (proc.stdout + proc.stderr)[-2000:])
    return out_dir / 'ps4rfd_host'


def write_psk(path: pathlib.Path) -> bytes:
    if not path.exists():
        path.write_bytes(secrets.token_bytes(32))
        path.chmod(0o600)
    return path.read_bytes()


class RehearsalAgent:
    """One agent process plus the host side of the session, for one tape."""

    def __init__(self, binary: pathlib.Path, psk_file: pathlib.Path, tape_path: pathlib.Path,
                 out_dir: pathlib.Path) -> None:
        self.binary = binary
        self.psk_file = psk_file
        self.tape_path = tape_path
        self.out_dir = out_dir
        self.proc: subprocess.Popen | None = None
        self.session: HostSession | None = None
        self.ready: dict = {}
        self.stderr_path = out_dir / (tape_path.stem + '.stderr')

    def __enter__(self) -> 'RehearsalAgent':
        listener = listen(0, host='127.0.0.1', backlog=1, timeout=30.0)
        port = listener.getsockname()[1]
        env = dict(os.environ, PS4RF_RPC_TAPE=str(self.tape_path))
        self.stderr_file = open(self.stderr_path, 'wb')
        self.proc = subprocess.Popen(
            [str(self.binary), '--connect', '127.0.0.1', str(port), '--psk-file',
             str(self.psk_file), '--label', 'w17-rehearsal', '--context',
             'offline-rpc-rehearsal'], env=env, stdout=self.stderr_file, stderr=self.stderr_file)
        conn, _addr = listener.accept()
        listener.close()
        ep = SocketEndpoint(conn, timeout=60.0)
        psk = self.psk_file.read_bytes()
        session = HostSession(ep, psk, session_id='w17-rehearsal-' + self.tape_path.stem)
        session.handshake()
        self.ready = session.recv_ready()
        self.session = session
        return self

    def __exit__(self, *exc) -> None:
        try:
            if self.session is not None:
                self.session.close()
        finally:
            if self.proc is not None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
            self.stderr_file.close()


def run_experiment(name: str, session, policy=None) -> dict:
    """Run one frozen experiment through the RPC path and return its report and classification."""
    experiment = q6 if name == 'q6' else OWN1
    tokens = tape.SUBMIT_TOKENS if name == 'q6' else (tape.SUBMIT_TOKENS[0],)
    target = RpcTarget(session, policy, submit_payloads=tokens)
    report = experiment.run(target)
    return {'experiment': name, 'classification': report.classification,
            'report': report.as_dict(),
            'requests': [e['request']['operation'] for e in target.exchanges],
            'exchanges': target.exchanges}


def rehearsal(out_dir: pathlib.Path, *, keep_tapes: bool = True) -> dict:
    """Phase 5: every scenario of both experiments, end to end, against the tape player."""
    out_dir = pathlib.Path(out_dir)
    tape_dir = out_dir / 'tapes'
    psk_file = out_dir / 'psk.bin'
    psk_file.parent.mkdir(parents=True, exist_ok=True)
    write_psk(psk_file)
    expected = dict(tape.expected_classifications())
    # the instrumentation controls have no oracle vector; their expectation is fixed by the
    # control tests and merged in so they still run over the full path
    expected.update(tape.CONTROL_EXPECTED)
    recorded = {name: tape.write(name, experiment, tape_dir)
                for experiment, names in (('q6', tape.scenarios('q6')), ('own1', tape.scenarios('own1')))
                for name in names}
    port = free_port()
    binary = build_rehearsal_agent(out_dir / 'agent', '127.0.0.1', port)
    results = []
    for scenario, info in recorded.items():
        if not info['experiment']:
            continue
        with RehearsalAgent(binary, psk_file, pathlib.Path(info['path']),
                            pathlib.Path(info['path']).parent) as agent:
            outcome = run_experiment(info['experiment'], agent.session)
            outcome['scenario'] = scenario
            outcome['tape_sha256'] = info['sha256']
            outcome['simulated_classification'] = info['oracle_classification']
            outcome['expected_classification'] = expected.get(scenario, '')
            # the fixture states an expectation as a disjunction when the oracle accepted more
            # than one verdict for a scenario; the rehearsal has to land inside it
            want = set(str(expected.get(scenario, '')).split('|'))
            got = set(str(outcome['classification']).split('|'))
            outcome['ok'] = (outcome['classification'] == info['oracle_classification']
                             and bool(got) and got <= want
                             and got == set(str(info['oracle_classification']).split('|')))
            outcome['agent'] = {'version': agent.ready.get('agent_version'),
                                'build_id': agent.ready.get('build_id'),
                                'profile_id': agent.ready.get('profile_id')}
            stderr = agent.stderr_path.read_text(errors='replace').strip()
            outcome['agent_stderr'] = stderr[-500:]
            if stderr:
                outcome['ok'] = False
            results.append(outcome)
    summary = {'schema': 'ps4rf-w17-rpc-rehearsal-v1', 'results': results,
               'passed': sum(1 for r in results if r['ok']),
               'total': len(results),
               'at': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
    (out_dir / 'rehearsal.json').write_text(json.dumps(summary, indent=1))
    return summary
