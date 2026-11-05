"""Offline mock of a rizin CLI session (P3). Loopback-free, inert, deterministic.

Scope: exactly the rizin command surface that :mod:`tools.rizin.adapter` drives
(``aaa``, ``ij``, ``aflj``, ``axtj @ addr``, ``axfj @ addr``, ``agfj @ addr``,
``afbj @ addr`` plus ``?e <text>`` markers). This is a *fake* rizin: it never
parses, loads or executes the artifact -- it hashes the bytes, looks the hash up
in a canned catalog and prints JSON. No rizin, no network, no subprocess.

Real-tool fidelity notes (v0.1 assumptions, see tools/rizin/README.md):
command names, ``?e`` echo markers and ``-q``/``-e``/``-c`` flags follow rizin /
radare2; the mock's JSON keeps a few realistic extra keys so the adapter's
normalization (explicit field picks) is exercised against tolerant input.

CLI surface:

  rizin_mock.py -q [-e k=v]... [-c <cmd>]... <artifact>
  rizin_mock.py -v | --version

Exit codes: 0 ok, 2 usage, 3 unknown artifact, 4 no artifact for a data command,
7 address is not a known function, 8 injected failure, 9 unknown command.

Test controls (environment, read at process start):

  PS4RF_RIZIN_MOCK_LOG      append-only call log (command names / hashes only)
  PS4RF_RIZIN_MOCK_INJECT   ``error`` -> fail before data; ``hang`` -> sleep
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

MOCK_VERSION = "0.7.4-mock"
FIXTURE_SHA256 = "2e2a2432c1032d47fcf55327fbc9518ff4c1f822bfad7ec9f78b8c434a1468b5"

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_UNKNOWN_ARTIFACT = 3
EXIT_NO_ARTIFACT = 4
EXIT_NOT_A_FUNCTION = 7
EXIT_INJECTED = 8
EXIT_UNKNOWN_COMMAND = 9

_INFO = {
    "arch": "x86",
    "bits": 64,
    "endian": "little",
    "os": "linux",
    "bintype": "elf",
    "stripped": False,
    "core": {"type": "DYN (mock)"},
}

# Per function: name + blocks. Blocks carry the realistic extras (opaddr,
# ninstr, traced) that the adapter must tolerate and drop.
_FUNCTIONS = [
    {"offset": "0x401000", "name": "sym.mock_open", "type": "sym",
     "blocks": [{"offset": "0x401000", "size": 72, "jump": None, "fail": None,
                 "ninstr": 12, "opaddr": "0x401000", "traced": False}]},
    {"offset": "0x401048", "name": "sym.mock_read", "type": "sym",
     "blocks": [{"offset": "0x401048", "size": 64, "jump": "0x401088", "fail": None,
                 "ninstr": 9, "opaddr": "0x401048", "traced": False},
                {"offset": "0x401088", "size": 68, "jump": None, "fail": None,
                 "ninstr": 8, "opaddr": "0x401088", "traced": False}]},
    {"offset": "0x4010cc", "name": "sym.mock_write", "type": "sym",
     "blocks": [{"offset": "0x4010cc", "size": 48, "jump": "0x4010fc",
                 "fail": "0x401118", "ninstr": 7, "opaddr": "0x4010cc",
                 "traced": False},
                {"offset": "0x4010fc", "size": 28, "jump": None, "fail": None,
                 "ninstr": 4, "opaddr": "0x4010fc", "traced": False},
                {"offset": "0x401118", "size": 20, "jump": None, "fail": None,
                 "ninstr": 3, "opaddr": "0x401118", "traced": False}]},
    # offset delivered as an int on purpose: the adapter must normalize both
    # int and hex-string offsets to lowercase hex.
    {"offset": int("0x40112c", 16), "name": "sym.mock_close", "type": "sym",
     "blocks": [{"offset": "0x40112c", "size": 44, "jump": None, "fail": None,
                 "ninstr": 5, "opaddr": "0x40112c", "traced": False}]},
    {"offset": "0x401158", "name": "sym.mock_helper", "type": "sym",
     "blocks": [{"offset": "0x401158", "size": 28, "jump": None, "fail": None,
                 "ninstr": 4, "opaddr": "0x401158", "traced": False}]},
]

_XREFS_TO = {
    "0x401048": [{"from": "0x401010", "to": "0x401048", "type": "CALL"}],
    "0x401158": [{"from": "0x401070", "to": "0x401158", "type": "CALL"},
                 {"from": "0x4010d0", "to": "0x401158", "type": "CALL"}],
    "0x404040": [{"from": "0x401090", "to": "0x404040", "type": "DATA"}],
}

_XREFS_FROM = {
    "0x401070": [{"from": "0x401070", "to": "0x401158", "type": "CALL"}],
    "0x4010d0": [{"from": "0x4010d0", "to": "0x401158", "type": "CALL"}],
    "0x401010": [{"from": "0x401010", "to": "0x401048", "type": "CALL"}],
}


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _to_offset(value) -> str:
    """Normalize an address that may be int or 0x-string to lowercase hex."""
    if isinstance(value, int):
        return hex(value)
    return str(value).lower()


def _function_index() -> dict[str, dict]:
    return {_to_offset(fn["offset"]): fn for fn in _FUNCTIONS}


def _edges(blocks: list[dict]) -> list[dict]:
    edges = []
    for block in blocks:
        for kind in ("jump", "fail"):
            if block.get(kind):
                edges.append({"src": _to_offset(block["offset"]),
                              "dst": _to_offset(block[kind]), "type": kind})
    return edges


def build_aflj() -> list[dict]:
    """``aflj`` payload: realistic extra keys included on purpose."""
    payload = []
    for fn in _FUNCTIONS:
        payload.append({
            "offset": _to_offset(fn["offset"]), "name": fn["name"],
            "size": sum(b["size"] for b in fn["blocks"]), "type": fn["type"],
            "nbbs": len(fn["blocks"]), "edges": len(_edges(fn["blocks"])),
            "cc": sum(b["ninstr"] for b in fn["blocks"]),
            "minbound": _to_offset(fn["offset"]),
            "maxbound": hex(sum(b["size"] for b in fn["blocks"])
                            + int(_to_offset(fn["offset"]), 16))})
    return payload


def build_agfj(address: str) -> dict:
    fn = _function_index().get(address)
    if fn is None:
        raise _NotAFunction(address)
    return {"name": fn["name"], "offset": address,
            "size": sum(b["size"] for b in fn["blocks"]),
            "ninstr": sum(b["ninstr"] for b in fn["blocks"]),
            "blocks": [dict(b) for b in fn["blocks"]],
            "edges": _edges(fn["blocks"])}


def build_afbj(address: str) -> list[dict]:
    fn = _function_index().get(address)
    if fn is None:
        raise _NotAFunction(address)
    return [dict(b) for b in fn["blocks"]]


class _NotAFunction(Exception):
    def __init__(self, address: str) -> None:
        self.address = address
        super().__init__(f"no function at {address}")


def _logger():
    target = os.environ.get("PS4RF_RIZIN_MOCK_LOG")
    if not target:
        return lambda line: None

    def log(line: str) -> None:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    return log


def _emit(value) -> None:
    print(json.dumps(value, sort_keys=True))


def _run_command(cmd: str) -> bool:
    """Execute one mock command. Returns True on success, False on exit-worthy error."""
    text = cmd.strip()
    if text == "aaa":
        return True
    if text.startswith("?e "):
        print(text[3:])
        return True
    if text == "ij":
        _emit(_INFO)
        return True
    if text == "aflj":
        _emit(build_aflj())
        return True
    for prefix, handler, kind in (("axtj", lambda a: _XREFS_TO.get(a, []), "to"),
                                  ("axfj", lambda a: _XREFS_FROM.get(a, []), "from")):
        if text == prefix or text.startswith(prefix + " "):
            address = text.split("@", 1)[1].strip().lower() if "@" in text else \
                text.split(" ", 1)[1].strip().lower() if " " in text else ""
            _emit(handler(address))
            return True
    if text.startswith("agfj"):
        address = _address_of(text)
        _emit(build_agfj(address))
        return True
    if text.startswith("afbj"):
        address = _address_of(text)
        _emit(build_afbj(address))
        return True
    print(f"ERROR: unknown command: {text}", file=sys.stderr)
    return False


def _address_of(cmd: str) -> str:
    if "@" not in cmd:
        raise _NotAFunction("")
    return cmd.split("@", 1)[1].strip().lower()


def _parse(argv: list[str]):
    parser = argparse.ArgumentParser(prog="rizin-mock", add_help=False)
    parser.add_argument("artifact", nargs="?")
    parser.add_argument("-q", action="store_true")
    parser.add_argument("-e", action="append", default=[])
    parser.add_argument("-c", action="append", default=[])
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    log = _logger()
    if any(a in ("-v", "--version") for a in argv):
        print(f"rizin {MOCK_VERSION} (offline mock)")
        log("version")
        return EXIT_OK
    try:
        args = _parse(argv)
    except SystemExit:
        print("usage: rizin_mock.py -q [-e k=v] [-c cmd] <artifact>", file=sys.stderr)
        log("usage-error")
        return EXIT_USAGE
    if not args.artifact:
        print("ERROR: no artifact given", file=sys.stderr)
        log("no-artifact")
        return EXIT_NO_ARTIFACT
    artifact = Path(args.artifact)
    if not artifact.is_file():
        print(f"ERROR: file not found: {artifact}", file=sys.stderr)
        log("missing-artifact")
        return EXIT_USAGE
    digest = _sha256_file(artifact)
    log(f"load:{digest}")
    if digest not in (FIXTURE_SHA256,):
        print("ERROR: artifact not in mock catalog (offline mock supports the "
              "committed fixture only)", file=sys.stderr)
        log("unknown-artifact")
        return EXIT_UNKNOWN_ARTIFACT
    inject = os.environ.get("PS4RF_RIZIN_MOCK_INJECT")
    if inject == "error":
        print("ERROR: injected failure before analysis", file=sys.stderr)
        log("inject:error")
        return EXIT_INJECTED
    if inject == "hang":
        log("inject:hang")
        time.sleep(3600)
    for cmd in args.c:
        log(f"cmd:{cmd.split(' ')[0]}")
        try:
            ok = _run_command(cmd)
        except _NotAFunction as exc:
            print(f"ERROR: cannot find function at {exc.address}", file=sys.stderr)
            log(f"not-a-function:{exc.address}")
            return EXIT_NOT_A_FUNCTION
        if not ok:
            return EXIT_UNKNOWN_COMMAND
    log("exit:0")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
