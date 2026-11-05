"""Socket endpoint for the frozen handshake I/O (``send_all`` / ``recv_exact``)."""

from __future__ import annotations

import socket
import time


class EndpointClosed(Exception):
    pass


class SocketEndpoint:
    """Minimal endpoint implementing exactly what ``core.rpc.handshake`` expects."""

    def __init__(self, sock: socket.socket, *, timeout: float = 30.0) -> None:
        self._sock = sock
        self._sock.settimeout(timeout)
        self.bytes_sent = 0
        self.bytes_received = 0

    # --- frozen handshake I/O ---------------------------------------------------
    def send_all(self, data: bytes) -> None:
        self._sock.sendall(data)
        self.bytes_sent += len(data)

    def recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = self._sock.recv(n - len(buf))
            except socket.timeout as exc:  # pragma: no cover - timeout is a failure
                raise EndpointClosed(f'timeout after {len(buf)}/{n} bytes') from exc
            if not chunk:
                raise EndpointClosed(f'peer closed after {len(buf)}/{n} bytes')
            buf.extend(chunk)
        self.bytes_received += len(buf)
        return bytes(buf)

    # --- convenience ------------------------------------------------------------
    def shutdown_write(self) -> None:
        """Half close: the agent sees EOF, sends its BYE, the host still reads it."""
        try:
            self._sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def close(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass

    @property
    def fd(self) -> int:
        return self._sock.fileno()


def listen(port: int, *, host: str = '127.0.0.1', backlog: int = 1, timeout: float = 600.0) -> socket.socket:
    """Binds a listening socket. The bridge on the relay host forwards the agent's
    reverse connection to this port (see docs/P4-W8-LIVE-BRINGUP.md)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(backlog)
    srv.settimeout(timeout)
    return srv


def connect_localhost(port: int, *, host: str = '127.0.0.1', attempts: int = 40,
                      delay: float = 0.25, timeout: float = 30.0) -> SocketEndpoint:
    """Connects to a local listener (self test / tunnel endpoint)."""
    last: Exception | None = None
    for _ in range(attempts):
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return SocketEndpoint(sock, timeout=timeout)
        except OSError as exc:  # pragma: no cover - retry path
            last = exc
            time.sleep(delay)
    raise EndpointClosed(f'no listener on {host}:{port}: {last}')
