#!/usr/bin/env python3
"""Inert deterministic generator of synthetic collector documents (offline).

Scope: exactly the two synthetic documents used by the adapter tests and
fixtures -- a Linux variant and a FreeBSD/OrbisOS variant. It is a *generator*,
not a collector: it reads nothing from the machine it runs on (except its own
command line and the log environment variable), it contacts nothing and it
spawns nothing. Fake host names (``synth-*``), generic/typical target paths,
no credentials.

Determinism: for the same variant the bytes are identical (sorted keys, fixed
order, no timestamps). The committed fixtures under
``tests/fixtures/unix_privesc/`` are byte-reproducible outputs of this module.

CLI:

  collector_mock.py --variant {linux,freebsd_orbisos} [--out PATH]

``--out`` omitted -> stdout. Exit codes: 0 ok, 2 usage, 3 unknown variant.

Test controls (environment, read at process start):

  PS4RF_UNIX_PRIVESC_MOCK_LOG   append-only call log (one line per phase)

The call log records the variant and the output target, never file contents.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

MOCK_VERSION = "0.1-mock"
SCHEMA_ID = "ps4rf.unix_privesc.collect/v1"
VARIANTS = ("linux", "freebsd_orbisos")

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_UNKNOWN_VARIANT = 3

_USAGE = ("usage: collector_mock.py --variant {linux,freebsd_orbisos} "
          "[--out PATH]")


def _entry(key: str, value: str) -> dict:
    return {"key": key, "value": value}


def _block(category: str, pairs: list[tuple[str, str]]) -> dict:
    return {"category": category,
            "entries": [_entry(key, value) for key, value in pairs]}


def _linux_document() -> dict:
    return {
        "schema": SCHEMA_ID,
        "collector": {"tool": "ps4rf-unix-collector", "version": MOCK_VERSION},
        "target": {"hostname": "synth-host", "platform_hint": "Linux",
                   "os": "Linux (synthetic)", "kernel": "6.8.0-synth"},
        "categories": [
            _block("os_kernel", [
                ("os.name", "Linux (synthetic)"),
                ("kernel.release", "6.8.0-synth"),
                ("uname.machine", "x86_64"),
            ]),
            _block("identity", [
                ("uid", "1000"),
                ("gid", "1000"),
                ("groups", "synth:synth:adm"),
            ]),
            _block("mounts", [
                ("/", "ext4 rw,relatime"),
                ("/tmp", "tmpfs rw,nosuid,nodev"),
                ("/home", "ext4 rw"),
            ]),
            _block("filesystem_permissions", [
                ("/etc", "drwxr-xr-x root:root"),
                ("/tmp", "drwxrwxrwt root:root"),
                ("/home/synth-user", "drwx------ synth:synth"),
            ]),
            _block("suid", [
                ("/usr/bin/synth-suid-helper", "4755 root:root"),
            ]),
            _block("sgid", [
                ("/usr/bin/synth-sgid-helper", "2755 root:synth"),
            ]),
            _block("path", [
                ("PATH", "/usr/local/bin:/usr/bin:/bin"),
            ]),
            _block("environment", [
                ("HOME", "/home/synth-user"),
                ("LANG", "C.UTF-8"),
                ("PATH", "/usr/local/bin:/usr/bin:/bin"),
                ("SHELL", "/bin/sh"),
            ]),
            _block("processes", [
                ("1", "init"),
                ("4242", "synth-agent"),
            ]),
            _block("services", [
                ("synth-agent.service", "enabled"),
                ("synth-maintenance.timer", "static"),
            ]),
            _block("sockets", [
                ("unix:/run/synth.sock", "synth-agent listening"),
                ("tcp:127.0.0.1:8080", "synth-agent listening"),
            ]),
            _block("cron", [
                ("/etc/crontab",
                 "0 3 * * * synth-user /usr/local/bin/synth-maintenance"),
            ]),
            _block("writable_executables", [
                ("/usr/local/bin/synth-tool", "mode 0777 owner synth"),
            ]),
            _block("writable_libraries", [
                ("/usr/local/lib/libsynth.so", "mode 0777 owner synth"),
            ]),
            _block("writable_configuration", [
                ("/etc/synth-agent.conf", "mode 0666 owner synth"),
            ]),
            _block("device_nodes", [
                ("/dev/synth-ctl", "crw-rw-rw- root:root"),
            ]),
            _block("loaded_modules", [
                ("synth_mod", "loaded refcount 1"),
            ]),
            _block("sysctls", [
                ("kernel.randomize_va_space", "2"),
                ("net.ipv4.ip_forward", "0"),
            ]),
            _block("procfs", [
                ("/proc/sys/kernel/randomize_va_space", "2"),
                ("/proc/self/status", "synthetic capture"),
            ]),
            _block("systemd", [
                ("synth-agent.service", "enabled active"),
                ("synth-maintenance.timer", "enabled waiting"),
            ]),
            _block("shells", [
                ("/bin/sh", "present"),
                ("/bin/bash", "present"),
            ]),
            _block("installed_binaries", [
                ("/usr/bin/synth-tool", "1.0"),
                ("/usr/local/bin/synth-maintenance", "1.0"),
            ]),
        ],
    }


def _freebsd_orbisos_document() -> dict:
    return {
        "schema": SCHEMA_ID,
        "collector": {"tool": "ps4rf-unix-collector", "version": MOCK_VERSION},
        "target": {"hostname": "synth-orbis",
                   "platform_hint": "OrbisOS (FreeBSD 12.1, synthetic)",
                   "os": "OrbisOS (synthetic)", "kernel": "12.1-SYNTH"},
        "categories": [
            _block("os_kernel", [
                ("os.name", "OrbisOS (synthetic)"),
                ("kernel.release", "12.1-SYNTH"),
                ("uname.machine", "x86_64"),
            ]),
            _block("identity", [
                ("uid", "1000"),
                ("gid", "1000"),
                ("groups", "synth:synth"),
            ]),
            _block("mounts", [
                ("/", "ufs rw"),
                ("/system", "ufs ro"),
                ("/user", "ufs rw"),
                ("/dev", "devfs rw"),
            ]),
            _block("filesystem_permissions", [
                ("/system", "drwxr-xr-x root:wheel"),
                ("/user/synth-user", "drwxr-xr-x synth:synth"),
            ]),
            _block("suid", [
                ("/system/bin/synth-suid-helper", "4755 root:wheel"),
            ]),
            _block("sgid", [
                ("/system/bin/synth-sgid-helper", "2755 root:synth"),
            ]),
            _block("path", [
                ("PATH", "/system/bin:/usr/bin:/bin"),
            ]),
            _block("environment", [
                ("HOME", "/user/synth-user"),
                ("LANG", "C"),
                ("PATH", "/system/bin:/usr/bin:/bin"),
                ("SHELL", "/bin/sh"),
            ]),
            _block("processes", [
                ("1", "init"),
                ("77", "synth-orbis-agent"),
            ]),
            _block("services", [
                ("synth-orbis-agent", "running"),
            ]),
            _block("sockets", [
                ("unix:/var/run/synth-orbis.sock", "synth-orbis-agent listening"),
                ("tcp:127.0.0.1:9090", "synth-orbis-agent listening"),
            ]),
            _block("cron", [
                ("/etc/crontab",
                 "0 4 * * * synth-user /system/bin/synth-maintenance"),
            ]),
            _block("writable_executables", [
                ("/user/app/synth-tool", "mode 0777 owner synth"),
            ]),
            _block("writable_libraries", [
                ("/user/app/libsynth.so", "mode 0777 owner synth"),
            ]),
            _block("writable_configuration", [
                ("/user/app/synth.conf", "mode 0666 owner synth"),
            ]),
            _block("device_nodes", [
                ("/dev/synth-ctl", "crw-rw-rw- root:operator"),
            ]),
            _block("loaded_modules", [
                ("synth_kld", "kldstat present"),
            ]),
            _block("sysctls", [
                ("security.bsd.unprivileged_proc_debug", "0"),
                ("kern.osreldate", "1201000"),
            ]),
            _block("jails", [
                ("jails.count", "1"),
                ("synth-jail", "path=/synth/jails/synth ip4=inherit"),
            ]),
            _block("shells", [
                ("/bin/sh", "present"),
                ("/rescue/sh", "present"),
            ]),
            _block("installed_binaries", [
                ("/system/bin/synth-tool", "present"),
                ("/usr/bin/synth-util", "present"),
            ]),
        ],
        "platform_specific": [
            _entry("orbisos.family_marker", "synthetic"),
            _entry("ps4.target_family", "orbisos (synthetic)"),
        ],
    }


_BUILDERS = {
    "linux": _linux_document,
    "freebsd_orbisos": _freebsd_orbisos_document,
}


def build_document(variant: str) -> dict:
    """Deterministic synthetic collector document for ``variant``."""
    try:
        builder = _BUILDERS[variant]
    except KeyError:
        raise ValueError(
            f"unknown variant: {variant!r} (expected one of "
            f"{', '.join(VARIANTS)})") from None
    return builder()


def dump_document(document: dict) -> str:
    """Canonical serialization: sorted keys, two-space indent, trailing newline."""
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def _logger():
    target = os.environ.get("PS4RF_UNIX_PRIVESC_MOCK_LOG")
    if not target:
        return lambda line: None

    def log(line: str) -> None:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    return log


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    log = _logger()
    parser = argparse.ArgumentParser(prog="collector_mock", add_help=False)
    parser.add_argument("--variant")
    parser.add_argument("--out", default=None)
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        print(_USAGE, file=sys.stderr)
        log("usage-error")
        return EXIT_USAGE
    if not args.variant:
        print(_USAGE, file=sys.stderr)
        log("usage-error")
        return EXIT_USAGE
    try:
        document = build_document(args.variant)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        log(f"unknown-variant:{args.variant}")
        return EXIT_UNKNOWN_VARIANT
    text = dump_document(document)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
        log(f"variant:{args.variant}")
        log(f"out:{out_path}")
    else:
        print(text, end="")
        log(f"variant:{args.variant}")
        log("out:stdout")
    log("exit:0")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
