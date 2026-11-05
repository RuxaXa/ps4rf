#!/usr/bin/env python3
"""Half-close aware TCP relay for the PS4RF live harness.

The OrbisProbe bridge (``console_bridge.py``) tears both sockets down with
``shutdown(SHUT_RDWR)`` as soon as one direction ends. That destroys the payload socket's
read side before the PS4 agent can answer the host's half-close with its BYE, so a live W8
run cannot capture the controlled-exit frame.

This relay propagates the half-close instead: when one direction ends, the *destination* is
told with ``shutdown(SHUT_WR)`` and the other direction keeps pumping until it also ends.
The late BYE therefore traverses, which is exactly what the W8 evidence needs.

Usage (on the relay host):
    python3 half_close_bridge.py --payload-port 9028 --host-port 9029 [--lifetime 1200]
It prints ``RELAY-READY ...`` on stdout once both listeners are up, logs one line per event,
and exits after the session finished or the lifetime expired. The loader port (9090) is never
touched by this program.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time

LOG_LOCK = threading.Lock()


def log(message: str) -> None:
    with LOG_LOCK:
        print(f'[{time.strftime("%H:%M:%S")}] {message}', flush=True)


def pump(src: socket.socket, dst: socket.socket, label: str) -> None:
    """Forward src -> dst, then half-close dst (never kill the reverse direction)."""
    total = 0
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
            total += len(chunk)
    except OSError as exc:
        log(f'{label}: {type(exc).__name__}: {exc}')
    finally:
        log(f'{label}: closed after {total} bytes')
        try:
            dst.shutdown(socket.SHUT_WR)      # half close only: the reverse side still lives
        except OSError:
            pass


def serve(payload_port: int, host_port: int, lifetime: float) -> int:
    payload_listener = socket.socket()
    payload_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    payload_listener.bind(('0.0.0.0', payload_port))
    payload_listener.listen(1)

    host_listener = socket.socket()
    host_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    host_listener.bind(('127.0.0.1', host_port))
    host_listener.listen(1)

    deadline = time.monotonic() + lifetime
    log(f'RELAY-READY payload_port={payload_port} host_port={host_port} lifetime={lifetime}s')

    def accept_with_deadline(listener: socket.socket) -> socket.socket | None:
        listener.settimeout(max(0.5, deadline - time.monotonic()))
        try:
            return listener.accept()[0]
        except (socket.timeout, OSError):
            return None

    payload_sock = accept_with_deadline(payload_listener)
    if payload_sock is None:
        log('no payload connection before the deadline')
        return 2
    peer = payload_sock.getpeername()
    log(f'payload connected from {peer[0]}:{peer[1]}')

    host_sock = accept_with_deadline(host_listener)
    if host_sock is None:
        log('no host connection before the deadline')
        return 3
    peer = host_sock.getpeername()
    log(f'host connected from {peer[0]}:{peer[1]}')

    for sock in (payload_sock, host_sock):
        sock.settimeout(max(5.0, min(60.0, deadline - time.monotonic())))

    t1 = threading.Thread(target=pump, args=(host_sock, payload_sock, 'host->payload'),
                          daemon=True)
    t2 = threading.Thread(target=pump, args=(payload_sock, host_sock, 'payload->host'),
                          daemon=True)
    t1.start()
    t2.start()
    t1.join(timeout=max(1.0, deadline - time.monotonic()))
    t2.join(timeout=max(1.0, deadline - time.monotonic()))

    for sock in (payload_sock, host_sock, payload_listener, host_listener):
        try:
            sock.close()
        except OSError:
            pass
    log('session finished')
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='half-close aware PS4RF relay')
    parser.add_argument('--payload-port', type=int, required=True)
    parser.add_argument('--host-port', type=int, required=True)
    parser.add_argument('--lifetime', type=float, default=1200.0)
    args = parser.parse_args(argv)
    return serve(args.payload_port, args.host_port, args.lifetime)


if __name__ == '__main__':
    sys.exit(main())
