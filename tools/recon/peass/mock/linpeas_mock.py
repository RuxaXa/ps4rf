#!/usr/bin/env python3
"""Offline mock of the linPEAS surface (P4 recon).

Scope: exactly the CLI surface that :mod:`tools.recon.peass.adapter` drives.
This is a *fake* scanner: it never touches a target, never reads the local
system and never runs child processes -- it writes one deterministic, synthetic
linPEAS-style report for a simulated target profile (``linux`` or ``orbisos``).
No network, no PEASS-ng installation, no credentials.

Determinism: for the same target the emitted bytes are identical (sorted
section order, no timestamps, no host-local paths); the committed fixtures are
pinned by sha256 in ``tests/fixtures/peass/README.md`` and in the adapter tests.

CLI surface (v0.1 assumption, documented in tools/recon/peass/README.md):

  linpeas_mock.py --target linux|orbisos --output <path>
  linpeas_mock.py --version

Exit codes: 0 ok, 2 usage, 3 unknown target, 5 injected failure. The mock never
opens sockets, never evaluates strings and never spawns processes.

Test controls (environment, read at process start):

  PS4RF_PEASS_MOCK_LOG      append-only call log (one line per phase)
  PS4RF_PEASS_MOCK_INJECT   ``error`` -> fail after target resolution;
                            ``hang``  -> sleep before writing output
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

MOCK_VERSION = "20231115-mock"

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_UNKNOWN_TARGET = 3
EXIT_INJECTED = 5

_BANNER = [
    "# linPEAS fixture report (SYNTHETIC)",
    "# generated offline by tools/recon/peass/mock/linpeas_mock.py",
    f"# scanner: linPEAS {MOCK_VERSION}",
    "# synthetic: true",
    "# no real host was contacted and no credentials are present",
]

_LINUX_LINES = [
    "╔══════════╣ System Information ╚ offline fixture ╝",
    "╚ hostname: ac-lab-host",
    "╚ uname -a: Linux ac-lab-host 6.8.0-31-generic #31-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux",
    "╚ kernel: 6.8.0-31-generic",
    "╚ /etc/os-release: PRETTY_NAME=\"Ubuntu 24.04.1 LTS\" ID=ubuntu VERSION_ID=\"24.04\"",
    "",
    "╔══════════╣ Filesystem ╚ offline fixture ╝",
    "╚ world-writable file: /srv/app/cache/staging.sock (mode 0777, fixture)",
    "╚ writable directory: /opt/vendor/updates (owned by appuser, fixture)",
    "╚ world-writable directory: /srv/app/backup (mode 0777, fixture)",
    "",
    "╔══════════╣ Mounts ╚ offline fixture ╝",
    "╚ overlay on / (docker-style rootfs, fixture)",
    "╚ /dev/sda2 on /boot type ext4 (rw, fixture)",
    "╚ tmpfs on /run (rw, fixture)",
    "╚ cgroup2 on /sys/fs/cgroup (container hint, fixture)",
    "",
    "╔══════════╣ Permissions ╚ offline fixture ╝",
    "╚ unreadable by scan user: /root (fixture)",
    "╚ world-writable directory: /tmp (sticky, fixture)",
    "╚ group-writable file: /var/log/app.log (mode 0664, fixture)",
    "",
    "╔══════════╣ SUID-SGID binaries ╚ offline fixture ╝",
    "╚ /usr/bin/sudo (SUID root, fixture)",
    "╚ /usr/bin/wall (SGID tty, fixture)",
    "╚ /opt/vendor/helper (SUID root, not package-owned, fixture)",
    "",
    "╔══════════╣ Linux Capabilities ╚ offline fixture ╝",
    "╚ /usr/bin/ping cap_net_raw+ep (fixture)",
    "╚ /opt/vendor/netd cap_net_admin,cap_net_bind_service+ep (fixture)",
    "",
    "╔══════════╣ Services ╚ offline fixture ╝",
    "╚ systemd unit app.service runs as root (fixture)",
    "╚ systemd unit update-agent.service enabled (fixture)",
    "╚ daemon sshd.service running (fixture)",
    "",
    "╔══════════╣ Cron Jobs ╚ offline fixture ╝",
    "╚ /etc/crontab: 17 * * * * root /opt/vendor/update.sh (fixture)",
    "╚ user crontab (appuser): @reboot /srv/app/bin/start.sh (fixture)",
    "",
    "╔══════════╣ Active Sockets ╚ offline fixture ╝",
    "╚ tcp 127.0.0.1:8080 LISTEN (fixture)",
    "╚ unix socket /run/app/control.sock (fixture)",
    "╚ udp 0.0.0.0:5353 (fixture)",
    "",
    "╔══════════╣ Credentials Search ╚ offline fixture ╝",
    "╚ /home/operator/.netrc: credential-like directives observed (values never copied)",
    "╚ /home/operator/.bash_history: credential-like patterns observed (values never copied)",
    "╚ /srv/app/.env: credential-like assignment present (values never copied)",
    "",
    "╔══════════╣ Interesting Binaries ╚ offline fixture ╝",
    "╚ /usr/bin/gdb present (fixture)",
    "╚ /usr/bin/curl present (fixture)",
    "╚ /usr/bin/python3.12 present (fixture)",
    "",
    "╔══════════╣ Container-VM Indicators ╚ offline fixture ╝",
    "╚ /.dockerenv present (container indicator, fixture)",
    "╚ hypervisor cpu flag present (VM indicator, fixture)",
]

_ORBISOS_LINES = [
    "╔══════════╣ System Information ╚ offline fixture ╝",
    "╚ hostname: ps4-fixture-console",
    "╚ uname -a: FreeBSD ps4-fixture-console 9.0-RELEASE-p12 FreeBSD 9.0-RELEASE-p12 #1 r284361: aarch64",
    "╚ model: PS4-family console (SYNTHETIC fixture)",
    "╚ Orbis OS: FreeBSD-derived console OS (SYNTHETIC fixture)",
    "",
    "╔══════════╣ Filesystem ╚ offline fixture ╝",
    "╚ writable directory: /data/self (fixture)",
    "╚ world-writable file: /data/app0/tmp.sock (mode 0777, fixture)",
    "",
    "╔══════════╣ Mounts ╚ offline fixture ╝",
    "╚ ufs on / (rw, fixture)",
    "╚ devfs on /dev (fixture)",
    "╚ /dev/md0 on /system (ro, fixture)",
    "",
    "╔══════════╣ Permissions ╚ offline fixture ╝",
    "╚ directory owned by console user: /user (fixture)",
    "╚ world-writable directory: /data/tmp (fixture)",
    "",
    "╔══════════╣ Services ╚ offline fixture ╝",
    "╚ system daemon with elevated context observed (SYNTHETIC fixture, not a real console sample)",
    "╚ background daemon observed (fixture)",
    "",
    "╔══════════╣ Active Sockets ╚ offline fixture ╝",
    "╚ tcp 127.0.0.1:2222 LISTEN (fixture)",
    "╚ unix socket /data/app0/control.sock (fixture)",
    "",
    "╔══════════╣ Credentials Search ╚ offline fixture ╝",
    "╚ /user/app/.netrc: credential-like directives observed (values never copied)",
    "",
    "╔══════════╣ Interesting Binaries ╚ offline fixture ╝",
    "╚ /usr/bin/console-tool present (SYNTHETIC fixture name)",
    "╚ /data/self/bootstrap present (SYNTHETIC fixture)",
]


def _build_report(lines: list[str]) -> str:
    return "\n".join([*_BANNER, "", *lines]) + "\n"


REPORTS = {
    "linux": _build_report(_LINUX_LINES),
    "orbisos": _build_report(_ORBISOS_LINES),
}


def render_report(target: str) -> str:
    """Deterministic synthetic report for a target profile."""
    if target not in REPORTS:
        raise ValueError(f"unknown mock target: {target!r}")
    return REPORTS[target]


def _logger():
    target = os.environ.get("PS4RF_PEASS_MOCK_LOG")
    if not target:
        return lambda line: None

    def log(line: str) -> None:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    return log


def _parse(argv: list[str]):
    parser = argparse.ArgumentParser(prog="linpeas-mock", add_help=False)
    parser.add_argument("--target")
    parser.add_argument("--output")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    log = _logger()
    if len(argv) == 1 and argv[0] in ("--version", "-version"):
        print(f"linPEAS {MOCK_VERSION} (offline fixture emitter)")
        log("version")
        return EXIT_OK
    try:
        args = _parse(argv)
    except SystemExit:
        print("usage: linpeas_mock.py --target linux|orbisos --output <path>",
              file=sys.stderr)
        log("usage-error")
        return EXIT_USAGE
    if not args.target or not args.output:
        print("ERROR: --target and --output are required", file=sys.stderr)
        log("usage-error")
        return EXIT_USAGE
    log(f"target:{args.target}")
    if args.target not in REPORTS:
        print(f"ERROR: unknown target {args.target!r} (offline mock supports: "
              f"{', '.join(sorted(REPORTS))})", file=sys.stderr)
        log("unknown-target")
        return EXIT_UNKNOWN_TARGET
    inject = os.environ.get("PS4RF_PEASS_MOCK_INJECT")
    if inject == "error":
        print("ERROR: injected failure after target resolution", file=sys.stderr)
        log("inject:error")
        return EXIT_INJECTED
    if inject == "hang":
        log("inject:hang")
        time.sleep(3600)
        return EXIT_INJECTED
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_report(args.target), encoding="utf-8")
    log(f"output:{out_path}")
    log("exit:0")
    print(f"INFO: scan written to {out_path}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
