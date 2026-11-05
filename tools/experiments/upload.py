"""W17F phase 6: the ONE payload delivery to the console's loader.

Discipline (unchanged from the W15 wave, because the lesson was expensive):

  * one ``POST /payload`` per wave, and the guard file is written *before* the request, so a failed
    or half-finished attempt burns the shot as well -- nothing here retries;
  * the artefact must hash to the digest the wave pins, or nothing is sent;
  * the owner's rearm phrase must be given verbatim, because nothing else can prove that the
    console's loader is ready for this wave.

The port is contacted exactly once and never probed: no connectivity check, no HEAD, no retry.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import pathlib
import time

REARM_PHRASE = 'BinLoader rearmed'


def _stamp() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: pathlib.Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, sort_keys=True))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='W17F: the one payload delivery')
    parser.add_argument('--console', required=True)
    parser.add_argument('--port', type=int, default=9090)
    parser.add_argument('--bin', dest='binary', required=True)
    parser.add_argument('--expect-sha256', required=True)
    parser.add_argument('--guard', required=True)
    parser.add_argument('--record', required=True)
    parser.add_argument('--confirm-rearmed', required=True)
    parser.add_argument('--timeout', type=float, default=30.0)
    args = parser.parse_args(argv)

    guard = pathlib.Path(args.guard)
    if args.confirm_rearmed != REARM_PHRASE:
        print(json.dumps({'upload': 'REFUSED', 'sent': False,
                          'reason': f'--confirm-rearmed must be exactly {REARM_PHRASE!r}'}))
        return 2
    if guard.exists():
        print(json.dumps({'upload': 'REFUSED', 'sent': False, 'guard': str(guard),
                          'reason': 'the guard exists: this wave already made its single attempt'}))
        return 2
    binary_path = pathlib.Path(args.binary)
    if not binary_path.is_file():
        print(json.dumps({'upload': 'REFUSED', 'sent': False,
                          'reason': f'no BIN at {binary_path}'}))
        return 2
    binary = binary_path.read_bytes()
    digest = _digest(binary)
    if digest != args.expect_sha256:
        print(json.dumps({'upload': 'REFUSED', 'sent': False, 'bin_sha256': digest,
                          'reason': 'the staged BIN is not the artefact this wave pins'}))
        return 3

    _write(guard, {'schema': 'ps4rf.w17.upload-guard.v1', 'wave': 'W17', 'sent': False,
                   'attempts': 0, 'bin_sha256': digest, 'bin_bytes': len(binary),
                   'guard_written_at': _stamp(),
                   'note': 'written before the request: a second run must be refused'})
    record = {'schema': 'ps4rf.w17.upload-record.v1', 'wave': 'W17', 'attempts': 1,
              'bin_sha256': digest, 'bin_bytes': len(binary), 'bin_path': str(binary_path),
              'console': args.console, 'port': args.port,
              'request': {'method': 'POST', 'path': '/payload',
                          'content_type': 'application/octet-stream'},
              'loader_contacts': 1, 'ok': False, 'started_at': _stamp(),
              'rearm_phrase': args.confirm_rearmed}
    try:
        conn = http.client.HTTPConnection(args.console, args.port, timeout=args.timeout)
        conn.request('POST', '/payload', body=binary,
                     headers={'Content-Type': 'application/octet-stream'})
        response = conn.getresponse()
        record.update({'status': response.status, 'reason': response.reason,
                       'powered_by': response.getheader('X-Powered-By'),
                       'body_bytes': len(response.read() or b'')})
        conn.close()
        record['ok'] = bool(response.status == 200)
    except Exception as exc:                                    # noqa: BLE001
        record.update({'error': f'{type(exc).__name__}: {exc}'})
    record['finished_at'] = _stamp()
    _write(guard, {**json.loads(guard.read_text()), 'sent': True, 'attempts': 1,
                   'ok': record['ok'], 'status': record.get('status'),
                   'note': 'the single attempt was made; the loader port is not touched again'})
    _write(pathlib.Path(args.record), record)
    print(json.dumps({'upload': 'SENT' if record['ok'] else 'FAILED', **record}, sort_keys=True))
    return 0 if record['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
