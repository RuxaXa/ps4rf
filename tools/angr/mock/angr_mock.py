"""Offline mock of the angr runner (P3). Loopback-free, inert, deterministic.

Scope: exactly the runner contract that :mod:`tools.angr.adapter` drives
(``run --request <req> --out <export>``, ``--version``). This is a *fake* angr:
it never loads, parses or executes the artifact -- it hashes the bytes, looks
the hash up in a canned catalog and writes a deterministic
``ps4rf.angr.export/v1`` document. No angr, no network, no subprocess.

The export embeds the sha256 of the real, committed runner placeholder
(``tools/angr/scripts/ps4rf_angr_run.py``), so the adapter's runner-hash binding
stays a genuine cross-check between the shipped contract and the recorded run.

CLI surface:

  angr_mock.py run --request <request.json> --out <export.json>
  angr_mock.py --version

Exit codes: 0 ok, 2 usage, 3 unknown/missing artifact, 4 bad request,
7 function/target not found, 8 injected failure, 9 unknown command.

Test controls (environment, read at process start):

  PS4RF_ANGR_MOCK_LOG      append-only call log (mode/ids/hashes only)
  PS4RF_ANGR_MOCK_INJECT   ``error`` -> fail before analysis; ``hang`` -> sleep
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

MOCK_VERSION = "9.2.4-mock"
SCHEMA_ID = "ps4rf.angr.export/v1"
REQUEST_SCHEMA_ID = "ps4rf.angr.request/v1"
RUNNER_ID = "ps4rf_angr_run"
FIXTURE_SHA256 = "efd361839429619ba5d83586dc973688fd21c9e55ae9e5b580fcc63db82238dd"

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_ARTIFACT = 3
EXIT_BAD_REQUEST = 4
EXIT_NOT_FOUND = 7
EXIT_INJECTED = 8
EXIT_UNKNOWN_COMMAND = 9

RUNNER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "ps4rf_angr_run.py"

_INFO = {"arch": "AMD64", "bits": 64, "endian": "little", "os": "linux"}
_ENTRY = "0x401000"

_FUNCTIONS = [
    {"name": "mock_main", "offset": "0x401000", "size": 96,
     "blocks": ["0x401000", "0x401030"]},
    {"name": "mock_parse", "offset": "0x401060", "size": 128,
     "blocks": ["0x401060", "0x4010a0"]},
    {"name": "mock_check", "offset": "0x4010e0", "size": 84,
     "blocks": ["0x4010e0", "0x40110c"]},
    {"name": "mock_tail", "offset": "0x401134", "size": 24,
     "blocks": ["0x401134"]},
]

_BLOCK_SIZES = {
    "0x401000": 48, "0x401030": 48, "0x401060": 64,
    "0x4010a0": 64, "0x4010e0": 44, "0x40110c": 40, "0x401134": 24,
}

_EDGES = [
    {"src": "0x401000", "dst": "0x401030", "type": "fallthrough"},
    {"src": "0x401030", "dst": "0x401060", "type": "call"},
    {"src": "0x401060", "dst": "0x4010a0", "type": "fallthrough"},
    {"src": "0x4010a0", "dst": "0x4010e0", "type": "call"},
    {"src": "0x4010e0", "dst": "0x40110c", "type": "jump"},
    {"src": "0x401134", "dst": "0x40110c", "type": "ret"},
]

_DATAFLOW = {
    "0x401000": [
        {"from": "0x401008", "to": "0x401038", "kind": "reg", "value": "rax"},
        {"from": "0x401010", "to": "0x401040", "kind": "mem", "value": "0x404040"},
    ],
    "0x401060": [
        {"from": "0x401068", "to": "0x4010b4", "kind": "reg", "value": "rax"},
        {"from": "0x401070", "to": "0x4010bc", "kind": "mem", "value": "0x404020"},
        {"from": "0x401060", "to": "0x4010a0", "kind": "stack", "value": "0x8"},
        {"from": "0x401078", "to": "0x4010c0", "kind": "reg", "value": "rdi"},
    ],
    "0x4010e0": [],
    "0x401134": [],
}

_PATHS = {
    "0x40110c": [
        {"path_id": "p0", "reached": "0x40110c",
         "steps": ["0x401000", "0x401030", "0x401060", "0x4010a0", "0x4010e0",
                   "0x40110c"],
         "constraints": [
             {"expr": "rsp != 0", "satisfiable": True, "solution": "0x1"},
             {"expr": "mem[0x404020] == 0x41", "satisfiable": True,
              "solution": "0x41"}]},
        {"path_id": "p1", "reached": "0x40110c",
         "steps": ["0x401000", "0x401030", "0x401060", "0x4010a0", "0x4010e0",
                   "0x40110c"],
         "constraints": [
             {"expr": "mem[0x404020] == 0x41 && mem[0x404020] == 0x42",
              "satisfiable": False, "solution": None}]},
    ],
    "0x401134": [
        {"path_id": "p0", "reached": "0x401134",
         "steps": ["0x401000", "0x401030", "0x401060", "0x4010a0", "0x4010e0",
                   "0x40110c", "0x401134"],
         "constraints": [{"expr": "rax == 0", "satisfiable": True,
                          "solution": "0x0"}]},
    ],
}


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _logger():
    target = os.environ.get("PS4RF_ANGR_MOCK_LOG")
    if not target:
        return lambda line: None

    def log(line: str) -> None:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    return log


def _stamp(mode: str) -> dict:
    return {
        "schema": SCHEMA_ID,
        "mode": mode,
        "artifact": {"sha256": FIXTURE_SHA256},
        "generator": {"tool": "angr", "version": MOCK_VERSION,
                      "runner": RUNNER_ID,
                      "runner_sha256": _sha256_file(RUNNER_PATH)},
    }


def _function_index() -> dict[str, dict]:
    return {fn["offset"]: fn for fn in _FUNCTIONS}


def build_export(mode: str, request: dict) -> dict:
    if mode == "analyze":
        entry = request.get("entry") or _ENTRY
        if entry != _ENTRY:
            raise _NotFound(entry)
        return {**_stamp(mode), "info": _INFO, "entry": _ENTRY,
                "functions": _FUNCTIONS,
                "cfg": {"nodes": [{"offset": block, "size": _BLOCK_SIZES[block]}
                                  for block in sorted(_BLOCK_SIZES)],
                        "edges": _EDGES}}
    if mode == "dataflow":
        address = request.get("function")
        if address not in _DATAFLOW:
            raise _NotFound(address)
        fn = _function_index()[address]
        return {**_stamp(mode),
                "function": {"name": fn["name"], "offset": fn["offset"],
                             "size": fn["size"]},
                "edges": _DATAFLOW[address]}
    if mode == "symbolic":
        target = request.get("target")
        if target not in _PATHS:
            raise _NotFound(target)
        return {**_stamp(mode), "target": target, "paths": _PATHS[target]}
    raise _BadRequest(f"unknown mode {mode!r}")


class _NotFound(Exception):
    def __init__(self, address) -> None:
        self.address = address
        super().__init__(f"not found: {address!r}")


class _BadRequest(Exception):
    pass


def _write_export(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8")


def _parse(argv: list[str]):
    parser = argparse.ArgumentParser(prog="angr-mock", add_help=False)
    parser.add_argument("command", nargs="?")
    parser.add_argument("--request")
    parser.add_argument("--out")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    log = _logger()
    if any(flag in ("-v", "--version") for flag in argv):
        print(f"angr {MOCK_VERSION} (offline mock)")
        log("version")
        return EXIT_OK
    try:
        args = _parse(argv)
    except SystemExit:
        print("usage: angr_mock.py run --request <req.json> --out <export.json>",
              file=sys.stderr)
        log("usage-error")
        return EXIT_USAGE
    if args.command != "run":
        print(f"ERROR: unknown command: {args.command}", file=sys.stderr)
        log("unknown-command")
        return EXIT_UNKNOWN_COMMAND
    if not args.request or not args.out:
        print("ERROR: --request and --out are required", file=sys.stderr)
        log("usage-error")
        return EXIT_USAGE
    request_path = Path(args.request)
    if not request_path.is_file():
        print(f"ERROR: request not found: {request_path}", file=sys.stderr)
        log("missing-request")
        return EXIT_BAD_REQUEST
    try:
        request = json.loads(request_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"ERROR: request is not valid JSON: {exc}", file=sys.stderr)
        log("bad-request")
        return EXIT_BAD_REQUEST
    if request.get("schema") != REQUEST_SCHEMA_ID or "mode" not in request:
        print("ERROR: request does not match ps4rf.angr.request/v1", file=sys.stderr)
        log("bad-request")
        return EXIT_BAD_REQUEST
    artifact_field = request.get("artifact")
    artifact = Path(artifact_field) if artifact_field else None
    if artifact is None or not artifact.is_file():
        print(f"ERROR: artifact not found: {artifact_field}", file=sys.stderr)
        log("missing-artifact")
        return EXIT_ARTIFACT
    digest = _sha256_file(artifact)
    log(f"load:{digest}")
    if digest != FIXTURE_SHA256 or request.get("artifact_sha256") != digest:
        print("ERROR: artifact not in mock catalog (offline mock supports the "
              "committed fixture only)", file=sys.stderr)
        log("unknown-artifact")
        return EXIT_ARTIFACT
    inject = os.environ.get("PS4RF_ANGR_MOCK_INJECT")
    if inject == "error":
        print("ERROR: injected failure before analysis", file=sys.stderr)
        log("inject:error")
        return EXIT_INJECTED
    if inject == "hang":
        log("inject:hang")
        time.sleep(3600)
    log(f"mode:{request['mode']}")
    try:
        document = build_export(request["mode"], request)
    except _NotFound as exc:
        print(f"ERROR: cannot resolve {exc.address}", file=sys.stderr)
        log(f"not-found:{exc.address}")
        return EXIT_NOT_FOUND
    except _BadRequest as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        log("bad-request")
        return EXIT_BAD_REQUEST
    out_path = Path(args.out)
    _write_export(out_path, document)
    log(f"export:{_sha256_file(out_path)}")
    log("exit:0")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
