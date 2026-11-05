#!/usr/bin/env python3
"""W11.1A: offline replay of the live agent-stop capture path (host side only).

The W11.1 live run ended with the agent's own BYE (``BOOT_READ_FAILED``) and ``boot_binding_event``
stayed null in the evidence although the relay counted the console sending the bytes. This tool
reproduces that shape offline with the host code the live mode actually runs:

* the W11.1 host agent (built from the same sources as the target payload; this tool never rebuilds
  or modifies the payload) is started on a loopback listener and driven through the frozen sequence
  with ``drive(..., w11=True)``,
* the host stand-in makes both userland paths report nothing, so the agent reaches
  ``BOOT_READ_FAILED`` and stops itself with BYE -- the live outcome, offline,
* the outcome is assembled by ``cli.live_agent_stop_outcome``, i.e. the live branch itself.

``--legacy-live-behaviour`` reproduces the *pre-fix* live branch (``legacy_live_stop_replica``) so
the before/after is deterministic; the real "before" remains the W11.1 live evidence pack.

No console contact, no port 9090, no upload, no rearm: this is an offline replay.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from core.rpc.handshake import ProtocolError                       # noqa: E402
from tools.hostctl import cli                                      # noqa: E402
from tools.hostctl.endpoint import EndpointClosed, SocketEndpoint  # noqa: E402
from tools.hostctl.session import HostSession, SessionError        # noqa: E402

# both userland paths answer nothing: the stand-in spec the W11.1 diagnosis scenarios used
BOTH_NOT_FOUND = 'name=2:2:0:0:;mib=2:2:0:0:'


def legacy_live_stop_replica(rec, session, exc, *, w11: bool) -> tuple[dict, bool]:
    """The *pre-fix* live branch, verbatim (frozen commit ``bf21c98``, ``tools/hostctl/cli.py``)::

        except (SessionError, ProtocolError, EndpointClosed) as exc:
            rec.check('live session', False, str(exc))
            result = {'ok': False, 'bye': session.bye}

    Three lines, no event capture: the sealed ``boot.binding`` event stayed in the session object
    and never reached the evidence. Reproduced here so the replay can show the before/after without
    touching the console.
    """
    rec.check('live session', False, str(exc))
    rec.doc.setdefault('boot_binding_event', None)
    rec.doc.setdefault('event_capture', None)
    return {'ok': False, 'bye': session.bye}, False


def replay(args) -> dict:
    agent = args.agent_binary
    if not pathlib.Path(agent).exists():
        raise SystemExit(f'agent binary not found: {agent} (native/target/build_host.sh)')
    psk = cli.read_psk(args.psk_file)
    with tempfile.TemporaryDirectory() as tmp:
        psk_path = os.path.join(tmp, 'psk.bin')
        pathlib.Path(psk_path).write_bytes(psk)
        srv = cli.listen(0, timeout=120.0)
        port = srv.getsockname()[1]
        env = dict(os.environ)
        for knob in ('PS4RF_HOST_BOOTDIAG_DRIFT_USEC',):
            env.pop(knob, None)
        env['PS4RF_HOST_BOOTDIAG'] = args.bootdiag
        proc = subprocess.Popen(
            [agent, '--connect', '127.0.0.1', str(port), '--psk-file', psk_path,
             '--label', 'w11-replay-agent', '--context', 'fw13-52-bootid-w11-replay'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        conn, _ = srv.accept()
        ep = SocketEndpoint(conn, timeout=60.0)
        run_id = 'RUN-' + hashlib.sha256(f'replay/{time.time()}'.encode()).hexdigest()[:16]
        rec = cli.build_record(run_id=run_id, mode='offline-live-path-replay',
                               psk_file=args.psk_file,
                               transport={'kind': 'loopback', 'listener': f'127.0.0.1:{port}',
                                          'note': 'offline replay of the live agent-stop path'},
                               payload={'kind': 'host-build (same sources as the payload)',
                                        'path': agent, 'sha256': cli.sha256_file(agent)},
                               repo=cli.repo_state())
        behaviour = ('legacy-live-behaviour (pre-fix replica)' if args.legacy_live_behaviour
                     else 'live_agent_stop_outcome (current live branch)')
        session = HostSession(ep, psk, accept_event=True)
        try:
            result = cli.drive(session, rec, actor_label='live path replay', w11=True)
        except (SessionError, ProtocolError, EndpointClosed) as exc:
            if args.legacy_live_behaviour:
                result, _ = legacy_live_stop_replica(rec, session, exc, w11=True)
            else:
                result, _ = cli.live_agent_stop_outcome(rec, session, exc, w11=True)
        finally:
            session.close()
            srv.close()
        out, err = proc.communicate(timeout=30)
        rec.doc['agent_process'] = {'exit_code': proc.returncode, 'stdout': out.strip()[:4000],
                                    'stderr': err.strip()[:4000]}
        rec.doc['replay'] = {
            'behaviour': behaviour,
            'bootdiag_standin': args.bootdiag,
            'frame_order': session.frame_trace,
            'frames_received': session.counters['frames_received'],
            'bye_reason': (session.bye or {}).get('reason'),
            'requests_served': [r.get('operation') for r in rec.doc['requests']],
            'note': ('the frame order is the live shape: the console answers, reports the '
                     'diagnostics as an EVENT and stops itself with BYE'),
        }
        captured = rec.doc.get('boot_binding_event') is not None
        rec.check('replay:boot.binding event in the evidence', captured,
                  '' if captured else 'the event did not reach the evidence '
                                      '(this is the pre-fix behaviour being reproduced)')
        if captured:
            rec.check('replay:event is the console diagnostics event',
                      rec.doc['boot_binding_event'].get('event') == 'boot.binding',
                      str(rec.doc['boot_binding_event'].get('schema')))
        verdict = ('LEGACY_REPLICA_EVENT_LOST' if (args.legacy_live_behaviour and not captured)
                   else ('PASS' if captured else 'FAIL'))
        doc = rec.finalize(session={'final_state': 'CLOSED',
                                    'cleanup_state': (result['bye'] or {}).get('cleanup')},
                           bye=result['bye'], health=None, verdict=verdict)
        path = cli.write_evidence(doc, args.out)
        return {'verdict': verdict, 'behaviour': behaviour, 'evidence': str(path),
                'event_captured': captured, 'bye_reason': (session.bye or {}).get('reason'),
                'events_seen': len(session.events),
                'checks_failed': [c['name'] for c in doc['checks'] if not c['ok']]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description='offline replay of the live agent-stop EVENT capture path (W11.1A)')
    ap.add_argument('--agent-binary', required=True)
    ap.add_argument('--psk-file', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--bootdiag', default=BOTH_NOT_FOUND,
                    help='host stand-in spec (default: both paths report nothing, the live shape)')
    ap.add_argument('--legacy-live-behaviour', action='store_true',
                    help='reproduce the pre-fix live branch instead of the current one')
    args = ap.parse_args(argv)
    print(json.dumps(replay(args), indent=1))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
