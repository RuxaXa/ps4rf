"""W17F phase 6: the live sheet -- the console run of the two generic primitives.

This is the live counterpart of :mod:`tools.experiments.rehearsal`. It listens for the resident
agent (the payload connects back to this host), takes the session through the frozen handshake and
READY, then walks the wave order:

  1. the agent starts (the payload was delivered by the guarded one-shot uploader)
  2. session and profile binding are confirmed from the agent's own READY/status facts
  3. ``kernel.snapshot.recipe`` is verified live (the Q6 recipe, cell by cell)
  4. ``ioctl.invoke`` is verified live with the bounded provider (the read-only status command)
  5. the Q6 live experiment runs (the frozen deterministic experiment, no race campaign)
  6. Q6 evidence is written
  7. the OWN1 live experiment runs
  8. OWN1 evidence is written

Every step writes its own file under ``--out`` as soon as it has data, so an interruption leaves an
honest partial record. Nothing here probes the loader port, and nothing here talks to the console
except through the agent's own session.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import socket
import sys
import time

from tools.experiments import q6
from tools.experiments.device import build_ioctl_blob
from tools.experiments.rpc import RpcTarget
from tools.experiments.tape import SUBMIT_TOKENS as _FROZEN_TOKENS

#: the live device verifies the staged block's PUP header (memcmp at 0x637120 against
#: 0xffffffffd0aebae3), so the live wave flies the same tokens with the header in front. The
#: frozen tuple stays what the offline vectors and the tape record.
SUBMIT_TOKENS = (q6.host_buffers(with_pup_header=True)["A"],
                 q6.host_buffers(with_pup_header=True)["B"])
FROZEN_TOKENS = _FROZEN_TOKENS
from tools.hostctl.endpoint import SocketEndpoint, listen
from tools.hostctl.session import HostSession

OWN1 = __import__('tools.experiments.own1', fromlist=['own1'])
Q6_RECIPE = q6.RECIPE
STATUS_READ = 0xC010440A
STATUS_BLOB = b'\x00' * 24


def _write(out: pathlib.Path, name: str, doc: dict) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / name).write_text(json.dumps(doc, indent=1, sort_keys=True))


def _stamp() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def wait_for_agent(port: int, *, out: pathlib.Path, timeout: float,
                   backlog: int = 1) -> socket.socket:
    listener = listen(port, host='0.0.0.0', backlog=backlog, timeout=timeout)
    _write(out, 'stage-1-listen.json', {'stage': 'listen', 'port': port, 'at': _stamp(),
                                        'note': 'the payload connects back to this listener'})
    conn, addr = listener.accept()
    listener.close()
    _write(out, 'stage-1-connected.json', {'stage': 'connected', 'peer': f'{addr[0]}:{addr[1]}',
                                           'at': _stamp()})
    return conn


def wait_for_matching_agent(port: int, *, out: pathlib.Path, psk: bytes, session_id: str,
                            timeout: float, want_build: str | None = None) -> tuple:
    """Accept agent connections until one reports the build this wave delivered.

    A payload left over from an earlier wave is still resident and keeps reaching the listener, and
    a session with it would silently measure the *old* binary's policy -- exactly what happened in
    the first bounded attempt: it reported build 417adc64 and answered EINVAL from the old field
    map. Several resident instances may race for the listener and each of them retries in a tight
    loop, so the gate has to be durable: any agent whose build id is not the delivered one is
    closed again (recorded), a connection that breaks mid-handshake is recorded and skipped, and
    the wait continues until the deadline. Nothing is sent to an agent that has not been identified.

    Returns (None, None, None, seen) when no agent with that build showed up inside the deadline.
    """
    deadline = time.time() + timeout
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        remaining = deadline - time.time()
        try:
            # a resident agent retries in a tight loop (hundreds of connects a second in the
            # console's own log), so the accept queue has to be deep enough that every agent --
            # the older ones and the delivered one -- is seen, and a timeout is not a lost round
            conn = wait_for_agent(port, out=out, timeout=min(60.0, max(15.0, remaining)),
                                  backlog=16)
        except (socket.timeout, TimeoutError, OSError) as exc:
            print(f'round {attempt}: no connection ({type(exc).__name__})', flush=True)
            continue
        session = HostSession(SocketEndpoint(conn, timeout=120.0), psk, session_id=session_id)
        try:
            hello = session.handshake()
            ready = session.recv_ready()
        except Exception as exc:                                # noqa: BLE001
            _write(out, f'stage-1-broken-{attempt}.json',
                   {'stage': 'broken', 'error': f'{type(exc).__name__}: {exc}', 'at': _stamp(),
                    'note': 'a connection that did not complete a handshake: skipped, nothing sent'})
            try:
                session.close()
            except Exception:                                   # noqa: BLE001
                pass
            continue
        got = hello.get('build_id')
        print(f'round {attempt}: agent build {got} (want {want_build})', flush=True)
        if want_build in (None, '') or got == want_build:
            return session, hello, ready, attempt
        _write(out, f'stage-1-rejected-{attempt}.json',
               {'stage': 'rejected', 'build_id': got, 'expected': want_build, 'at': _stamp(),
                'note': 'a resident payload of an earlier wave: closed before anything was sent'})
        try:
            session.close()
        except Exception:                                       # noqa: BLE001
            pass
    return None, None, None, attempt


def session_facts(session: HostSession, ready: dict, hello: dict) -> dict:
    return {'hello': hello, 'ready': ready,
            'session_counters': dict(getattr(session, 'counters', {})),
            'identity_fields': {k: hello.get(k) for k in ('agent_version', 'build_id', 'platform',
                                                          'profile_id', 'boot_id', 'boot_sec',
                                                          'boot_usec', 'boot_status', 'context',
                                                          'label')}}


def _cells(snapshot) -> dict:
    """The recipe's cells in the shape both the pre and the post snapshot are recorded with."""
    import hashlib
    return {name: {'status': cell.status, 'why': cell.why, 'length': cell.length,
                   'addr': hex(cell.addr), 'root_value': hex(cell.root_value),
                   'sha256': hashlib.sha256(cell.data).hexdigest()}
            for name, cell in snapshot.cells.items()}


def _own1_evidence(target: RpcTarget, report) -> dict:
    """The OWN1 evidence document: raw cell bytes, per-read hashes and the measurements."""
    cells = {}
    for exchange in target.exchanges:
        response = exchange['response']
        for cell in ((response.get('result') or {}).get('cells') or []):
            cells.setdefault(cell.get('name'), []).append(
                {'status': cell.get('status'), 'length': cell.get('length'),
                 'addr': cell.get('addr'), 'root_value': cell.get('root_value'),
                 'data': cell.get('data'), 'sha256': __import__('hashlib').sha256(
                     bytes.fromhex(cell.get('data') or '')).hexdigest()})
    return {'experiment': 'own1', 'recipe': OWN1.RECIPE, 'at': _stamp(),
            'classification': report.classification,
            'measurements': report.as_dict(),
            'cells_pre_post': cells,
            'requests': [e['request'] for e in target.exchanges],
            'responses': [e['response'] for e in target.exchanges],
            'submit_payload_sha256': __import__('hashlib').sha256(
                SUBMIT_TOKENS[0]).hexdigest()}


def run(port: int, psk_file: pathlib.Path, out: pathlib.Path, *, timeout: float = 900.0,
        session_id: str | None = None, stages: str = 'full',
        expect_build: str | None = None) -> dict:
    out = pathlib.Path(out)
    summary: dict = {'schema': 'ps4rf-w17-live-v1', 'started_at': _stamp(),
                     'port': port, 'out': str(out)}
    psk = pathlib.Path(psk_file).read_bytes()
    sid = session_id or ('w17-live-' + str(int(time.time())))
    expect_build = expect_build or os.environ.get('PS4RF_W17_EXPECT_BUILD') or None
    if stages == 'submit-once' and expect_build is None:
        # the bounded sheet must not run against an unknown binary: put the delivered build id in
        # PS4RF_W17_EXPECT_BUILD (or --expect-build) and the sheet waits for exactly that agent
        summary['verdict'] = 'NO_EXPECTED_BUILD'
        summary['finished_at'] = _stamp()
        _write(out, 'w17-live-summary.json', summary)
        return summary
    summary['expected_build'] = expect_build
    session, hello, ready, rounds = wait_for_matching_agent(
        port, out=out, psk=psk, session_id=sid, timeout=timeout, want_build=expect_build)
    if session is None:
        summary['verdict'] = 'BUILD_MISMATCH'
        summary['connections_seen'] = rounds
        summary['finished_at'] = _stamp()
        _write(out, 'w17-live-summary.json', summary)
        return summary
    try:
        facts = session_facts(session, ready, hello)
        _write(out, 'stage-2-session.json', facts)

        # 2b. the daemon's own status body. This is where the lifetime's boot-binding verdict is
        # published (the measurement runs once per lifetime, inside this session's first loop
        # iteration), so the wave records it as an observation -- a lifetime whose binding is
        # UNRESOLVED is a finding to report, not something this sheet may paper over.
        try:
            status = session.request('session.status', {})
        except Exception as exc:                                # noqa: BLE001
            status = {'error': f'{type(exc).__name__}: {exc}'}
        facts['status'] = status
        summary['session'] = facts
        _write(out, 'stage-2-session.json', facts)

        # 3. kernel.snapshot.recipe, live, cell by cell ---------------------------------------
        target = RpcTarget(session, submit_payloads=SUBMIT_TOKENS)
        try:
            snapshot = target.run_recipe(Q6_RECIPE)
        except Exception as exc:                                # noqa: BLE001
            recipe_facts = {'recipe': Q6_RECIPE, 'refused': f'{type(exc).__name__}: {exc}',
                            'exchange': (target.exchanges or [None])[-1]}
            summary['recipe'] = recipe_facts
            _write(out, 'stage-3-recipe.json', recipe_facts)
            summary['verdict'] = 'RECIPE_REFUSED'
            summary['finished_at'] = _stamp()
            _write(out, 'w17-live-summary.json', summary)
            return summary
        recipe_facts = {'recipe': Q6_RECIPE, 'attach': snapshot.attach,
                        'cells': {name: {'status': cell.status, 'why': cell.why,
                                         'length': cell.length, 'addr': hex(cell.addr),
                                         'root_value': hex(cell.root_value),
                                         'sha256': __import__('hashlib').sha256(
                                             cell.data).hexdigest()}
                                  for name, cell in snapshot.cells.items()}}
        summary['recipe'] = recipe_facts
        _write(out, 'stage-3-recipe.json', recipe_facts)
        pre_cells = _cells(snapshot)

        # 3b. the bounded single submit (W18 submit ABI). One corrected 0xC0184401 only: the
        # argument block carries the proven size (0x4000) and mode word (0), the provider stages
        # its own boundary-aligned region, and the first payload (the A token) is what the caller
        # presents. The post snapshot is taken before anything else is sent.
        if stages == 'submit-once':
            block = build_ioctl_blob(target.policy, q6.SUBMIT, ptr=0x0, size=q6.BUFFER_LEN,
                                     mode=q6.SUBMIT_MODE)
            payload = SUBMIT_TOKENS[0][:target.max_payload]
            rc, errno, output = target.ioctl(target.policy.device, q6.SUBMIT, block)
            submit_facts = {'device': target.policy.device, 'command': hex(q6.SUBMIT),
                            'blob': block.hex(), 'blob_fields': {
                                'cpuaddr': int.from_bytes(block[0:8], 'little'),
                                'size': int.from_bytes(block[8:16], 'little'),
                                'mode': int.from_bytes(block[16:20], 'little')},
                            'payload_len': len(payload),
                            'payload_sha256': __import__('hashlib').sha256(payload).hexdigest(),
                            'rc': rc, 'errno': errno, 'output_len': len(output),
                            'output_sha256': __import__('hashlib').sha256(output).hexdigest(),
                            'accepted': rc == 0,
                            'exchanges': target.exchanges[-1:]}
            summary['submit'] = submit_facts
            _write(out, 'stage-5-submit.json', submit_facts)
            post = target.run_recipe(Q6_RECIPE)
            post_facts = {'recipe': Q6_RECIPE, 'attach': post.attach, 'cells': _cells(post)}
            post_facts['changed_from_pre'] = sorted(
                name for name, cell in post_facts['cells'].items()
                if pre_cells.get(name, {}).get('sha256') != cell['sha256'])
            summary['recipe_post'] = post_facts
            _write(out, 'stage-3b-recipe-post.json', post_facts)
            summary['verdict'] = 'SUBMIT_ACCEPTED' if rc == 0 else 'SUBMIT_REFUSED'
            summary['finished_at'] = _stamp()
            _write(out, 'w17-live-summary.json', summary)
            return summary

        # 3c. the Q6 A->B sequence only (no status read, no OWN1): the two corrected submits with
        # the A and the B token in turn, then the classification from the recipe cells. The status
        # command keeps its undeclared pointer field and OWN1 stays out of the live path.
        if stages == 'q6':
            q6_target = RpcTarget(session, submit_payloads=SUBMIT_TOKENS)
            q6_report = q6.run(q6_target)
            q6_evidence = {'experiment': 'q6', 'recipe': Q6_RECIPE, 'at': _stamp(),
                           'classification': q6_report.classification,
                           'measurements': q6_report.as_dict(),
                           'requests': [e['request'] for e in q6_target.exchanges],
                           'responses': [e['response'] for e in q6_target.exchanges],
                           'submit_payload_sha256': [
                               __import__('hashlib').sha256(p).hexdigest()
                               for p in SUBMIT_TOKENS]}
            _write(out, 'stage-6-q6-evidence.json', q6_evidence)
            summary['q6'] = {'classification': q6_report.classification,
                             'measurements': q6_report.as_dict()}
            summary['verdict'] = q6_report.classification
            summary['finished_at'] = _stamp()
            _write(out, 'w17-live-summary.json', summary)
            return summary

        # 3c-bis. the OWN1-only wave (W18): the frozen OWN1 experiment with the new dynamic
        # windows -- baseline recipe, ONE trigger ioctl, T0 recipe, settle recipe. No submit,
        # no status read, no Q6: no side experiments in this wave.
        if stages == 'own1':
            own1_target = RpcTarget(session, submit_payloads=(SUBMIT_TOKENS[0],))
            own1_report = OWN1.run(own1_target)
            own1_evidence = _own1_evidence(own1_target, own1_report)
            _write(out, 'stage-8-own1-evidence.json', own1_evidence)
            summary['own1'] = {'classification': own1_report.classification,
                               'measurements': own1_report.as_dict()}
            summary['verdict'] = 'COMPLETE'
            summary['finished_at'] = _stamp()
            _write(out, 'w17-live-summary.json', summary)
            return summary

        # 4. ioctl.invoke, live, the bounded read-only command --------------------------------
        rc, errno, output = target.ioctl(target.policy.device, STATUS_READ, STATUS_BLOB)
        ioctl_facts = {'device': target.policy.device, 'command': hex(STATUS_READ),
                       'rc': rc, 'errno': errno, 'output_len': len(output),
                       'output_sha256': __import__('hashlib').sha256(output).hexdigest(),
                       'exchanges': target.exchanges[-1:]}
        summary['ioctl'] = ioctl_facts
        _write(out, 'stage-4-ioctl.json', ioctl_facts)

        # 5./6. the Q6 live experiment and its evidence ---------------------------------------
        q6_target = RpcTarget(session, submit_payloads=SUBMIT_TOKENS)
        q6_report = q6.run(q6_target)
        q6_evidence = {'experiment': 'q6', 'recipe': Q6_RECIPE, 'at': _stamp(),
                       'classification': q6_report.classification,
                       'measurements': q6_report.as_dict(),
                       'requests': [e['request'] for e in q6_target.exchanges],
                       'responses': [e['response'] for e in q6_target.exchanges],
                       'submit_payload_sha256': [
                           __import__('hashlib').sha256(p).hexdigest() for p in SUBMIT_TOKENS]}
        _write(out, 'stage-6-q6-evidence.json', q6_evidence)
        summary['q6'] = {'classification': q6_report.classification,
                         'measurements': q6_report.as_dict()}

        # 7./8. the OWN1 live experiment and its evidence -------------------------------------
        own1_target = RpcTarget(session, submit_payloads=(SUBMIT_TOKENS[0],))
        own1_report = OWN1.run(own1_target)
        own1_evidence = _own1_evidence(own1_target, own1_report)
        _write(out, 'stage-8-own1-evidence.json', own1_evidence)
        summary['own1'] = {'classification': own1_report.classification,
                           'measurements': own1_report.as_dict()}
        summary['finished_at'] = _stamp()
        summary['verdict'] = 'COMPLETE'
        _write(out, 'w17-live-summary.json', summary)
        return summary
    finally:
        try:
            session.close()
        except Exception:                                   # noqa: BLE001
            pass


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='W17F live sheet: the two generic primitives')
    parser.add_argument('--listen', type=int, default=9028)
    parser.add_argument('--psk-file', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--timeout', type=float, default=900.0)
    parser.add_argument('--session-id', default=None)
    parser.add_argument('--stages', choices=('full', 'submit-once', 'q6', 'own1'), default='full',
                        help='submit-once: pre snapshot, ONE corrected 0xC0184401, post snapshot; '
                             'q6: pre snapshot, the A->B submits, classification (no OWN1); '
                             'own1: pre snapshot, the OWN1 trigger wave with T0 and the settle '
                             'read (no submit, no status read, no Q6)')
    parser.add_argument('--expect-build', default=None,
                        help='the build id the wave delivered; an agent reporting anything else is '
                             'closed before a request is sent (submit-once requires it)')
    args = parser.parse_args(argv)
    summary = run(args.listen, pathlib.Path(args.psk_file), pathlib.Path(args.out),
                  timeout=args.timeout, session_id=args.session_id, stages=args.stages,
                  expect_build=args.expect_build)
    print(json.dumps({'verdict': summary.get('verdict'),
                      'q6': (summary.get('q6') or {}).get('classification'),
                      'own1': (summary.get('own1') or {}).get('classification'),
                      'submit': {k: v for k, v in (summary.get('submit') or {}).items()
                                 if k in ('rc', 'errno', 'accepted', 'blob_fields')},
                      'out': summary.get('out')}, indent=1, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
