"""Regression for the W11.2-D1 health probe correction (ACCEPTED_PROBE_DESIGN_ISSUE).

Port 3232 is GoldHEN's passive log stream: a successful bounded TCP connect is the health fact, and a
silent stream must not fail the target health verdict. `log_activity_observed` is reported separately
and stays outside the verdict-bearing `checks` list.
"""

from __future__ import annotations

import socket
import sys
import threading
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.hostctl.cli import _probe_tcp_port, live_health  # noqa: E402


def _serve(handler, *, ready: threading.Event) -> tuple[threading.Thread, int]:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def loop():
        ready.set()
        try:
            for _ in range(4):
                conn, _ = srv.accept()
                threading.Thread(target=handler, args=(conn,), daemon=True).start()
        except OSError:
            pass

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    ready.wait(2.0)
    return thread, port


def test_tcp_connect_without_data_is_a_pass_not_a_failure():
    """The exact W11.2 live situation: connect succeeds, no log line arrives."""
    ready = threading.Event()

    def silent(conn):
        try:
            conn.recv(64)          # wait until the client gives up; never send anything
        except OSError:
            pass
        finally:
            conn.close()

    _serve(silent, ready=ready)
    health = live_health('127.0.0.1', 9090, ports={'ftp': 2121, 'log': _serve(silent, ready=threading.Event())[1]})
    checks = {name: ok for name, ok, _ in health['checks']}
    assert checks['port-3232-connect'] is True, health
    assert 'port-3232-banner' not in checks
    assert health['observed']['log_activity_observed'] is False
    # the informational flag lives outside `checks`, so `all(c[1] for c in checks)` cannot be flipped
    assert 'log_activity_observed' not in checks
    detail = [d for n, _, d in health['checks'] if n == 'port-3232-connect'][0]
    assert 'passive' in detail and 'not a health failure' in detail


def test_tcp_connect_reporting_a_log_line_sets_log_activity_observed():
    ready = threading.Event()

    def chatty(conn):
        try:
            conn.sendall(b'<118>[SceShellCore] hello\n')
            conn.recv(64)
        except OSError:
            pass
        finally:
            conn.close()

    _, port = _serve(chatty, ready=ready)
    connected, observed, detail = _probe_tcp_port('127.0.0.1', port)
    assert connected is True and observed is True and 'SceShellCore' in detail


def test_closed_port_is_a_real_failure():
    # bind then close to get a port nothing listens on
    probe = socket.socket()
    probe.bind(('127.0.0.1', 0))
    dead_port = probe.getsockname()[1]
    probe.close()
    connected, observed, detail = _probe_tcp_port('127.0.0.1', dead_port, read_timeout=0.5)
    assert connected is False and observed is False and detail


def test_probe_is_bounded():
    """The probe must return promptly even when the peer neither sends nor closes."""
    ready = threading.Event()

    def stubborn(conn):
        try:
            import time
            time.sleep(30)
        finally:
            conn.close()

    _, port = _serve(stubborn, ready=ready)
    import time
    start = time.monotonic()
    connected, observed, _ = _probe_tcp_port('127.0.0.1', port, read_timeout=0.5)
    elapsed = time.monotonic() - start
    assert connected is True and observed is False
    assert elapsed < 5.0, elapsed
