"""Offline mock of the AFL++ tool surface (P3). Loopback-free, inert, deterministic.

Scope: exactly the workflow commands that :mod:`tools.aflplusplus.adapter`
drives -- corpus coverage (``afl-showmap``), corpus minimization
(``afl-cmin``), reproducer minimization (``afl-tmin``), crash triage
(``afl-collect``) and a version probe (``afl-fuzz``). This is a *fake* AFL++:
it never runs, loads or fuzzes a target -- it reads input bytes, applies
deterministic mock rules and writes a result document. No afl binaries, no
network, no subprocess, no external debugger.

Mock rules (documented as such -- real AFL++ semantics land with real tools):

* coverage ids: four 2-byte big-endian words of the (zero-padded) input head,
  formatted ``0x%04x`` -- deterministic per input content;
* crash signature: ``0x`` + the four payload bytes after the crash magic
  (``PS4RF-AFL-CRASH-v1\\n``); a crash input is a file starting with that magic;
* ``afl-cmin``: greedy keep in sorted name order; a file whose id set is
  already covered is dropped (``duplicate coverage`` if identical to a covered
  set, otherwise ``no new coverage``);
* ``afl-tmin``: minimized reproducer = magic + the four signature payload
  bytes, so the signature is preserved by construction;
* ``afl-collect``: group crash inputs by signature (members and groups sorted).

CLI surface:

  afl_mock.py afl-fuzz --version
  afl_mock.py afl-showmap --target <t> --input <i> --out <result.json>
  afl_mock.py afl-cmin --corpus <dir> --out <result.json>
  afl_mock.py afl-tmin --input <crash> --out-min <file> --out <result.json>
  afl_mock.py afl-collect --crashes <dir> --out <result.json>

Exit codes: 0 ok, 2 usage, 3 target not in catalog, 4 bad input, 8 injected
failure, 9 unknown tool.

Test controls (environment, read at process start):

  PS4RF_AFL_MOCK_LOG      append-only call log (tool/ids/hashes only)
  PS4RF_AFL_MOCK_INJECT   ``error`` -> fail before work; ``hang`` -> sleep
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

MOCK_VERSION = "4.21c-mock"
CRASH_MAGIC = b"PS4RF-AFL-CRASH-v1\n"
TARGET_SHA256 = "7c3408ffce2d37de47dfb79fbf64c91ea94031d185130912b5dd4e1af9ae0a1e"

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_TARGET = 3
EXIT_BAD_INPUT = 4
EXIT_INJECTED = 8
EXIT_UNKNOWN_TOOL = 9

TOOLS = ("afl-fuzz", "afl-showmap", "afl-cmin", "afl-tmin", "afl-collect")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _coverage_ids(data: bytes) -> list[str]:
    head = data[:8].ljust(8, b"\x00")
    return sorted({"0x%04x" % int.from_bytes(head[index:index + 2], "big")
                   for index in (0, 2, 4, 6)})


def _is_crash(data: bytes) -> bool:
    return data.startswith(CRASH_MAGIC) and len(data) >= len(CRASH_MAGIC) + 4


def _signature(data: bytes) -> str:
    payload = data[len(CRASH_MAGIC):len(CRASH_MAGIC) + 4]
    return "0x" + payload.hex()


def _logger():
    target = os.environ.get("PS4RF_AFL_MOCK_LOG")
    if not target:
        return lambda line: None

    def log(line: str) -> None:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    return log


def _write_result(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8")


def _file_entry(path: Path) -> dict:
    data = path.read_bytes()
    return {"name": path.name, "sha256": _sha256_bytes(data), "size": len(data)}


def build_showmap(target: Path, input_path: Path) -> dict:
    if _sha256_file(target) != TARGET_SHA256:
        raise _TargetRefused(str(target))
    data = input_path.read_bytes()
    crash = _is_crash(data)
    return {"tool": "afl-showmap",
            "target": {"sha256": TARGET_SHA256},
            "input": {"sha256": _sha256_bytes(data), "size": len(data)},
            "tuples": _coverage_ids(data),
            "crashes": crash,
            "signature": _signature(data) if crash else None}


def build_cmin(corpus: Path) -> dict:
    files = sorted(path for path in corpus.iterdir() if path.is_file())
    if not files:
        raise _BadInput(f"empty corpus: {corpus}")
    entries, kept, dropped = [], [], []
    covered: set[str] = set()
    covered_sets: list[set[str]] = []
    for path in files:
        data = path.read_bytes()
        entries.append(_file_entry(path))
        ids = set(_coverage_ids(data))
        if ids <= covered:
            reason = "duplicate coverage" if ids in covered_sets else "no new coverage"
            dropped.append({"name": path.name, "reason": reason})
        else:
            kept.append(path.name)
            covered_sets.append(ids)
            covered |= ids
    return {"tool": "afl-cmin",
            "corpus": {"entries": entries, "total": len(entries)},
            "kept": kept, "dropped": dropped,
            "coverage_total": len(covered)}


def build_tmin(crash: Path) -> tuple[dict, bytes]:
    data = crash.read_bytes()
    if not _is_crash(data):
        raise _BadInput(f"not a crash input: {crash}")
    minimized = CRASH_MAGIC + data[len(CRASH_MAGIC):len(CRASH_MAGIC) + 4]
    document = {"tool": "afl-tmin",
                "input": {"sha256": _sha256_bytes(data), "size": len(data)},
                "minimized": {"sha256": _sha256_bytes(minimized),
                              "size": len(minimized)},
                "signature": _signature(data),
                "preserved_signature": _signature(minimized) == _signature(data)}
    return document, minimized


def build_collect(crashes: Path) -> dict:
    files = sorted(path for path in crashes.iterdir() if path.is_file())
    if not files:
        raise _BadInput(f"no crash inputs: {crashes}")
    groups: dict[str, list[str]] = {}
    for path in files:
        data = path.read_bytes()
        if not _is_crash(data):
            raise _BadInput(f"not a crash input: {path}")
        groups.setdefault(_signature(data), []).append(path.name)
    return {"tool": "afl-collect",
            "groups": [{"signature": signature, "members": sorted(members)}
                       for signature, members in sorted(groups.items())],
            "total": len(files)}


class _TargetRefused(Exception):
    pass


class _BadInput(Exception):
    pass


def _parse(argv: list[str]):
    tool = argv[0] if argv else None
    parser = argparse.ArgumentParser(prog="afl-mock", add_help=False)
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--target")
    parser.add_argument("--input")
    parser.add_argument("--out-min")
    parser.add_argument("--corpus")
    parser.add_argument("--crashes")
    parser.add_argument("--out")
    return tool, parser.parse_args(argv[1:])


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    log = _logger()
    if "--version" in argv:
        print(f"afl-fuzz++{MOCK_VERSION} based on afl-fuzz (offline mock)")
        log("version")
        return EXIT_OK
    try:
        tool, args = _parse(argv)
    except SystemExit:
        print("usage: afl_mock.py <tool> [...] --out <result.json>", file=sys.stderr)
        log("usage-error")
        return EXIT_USAGE
    if tool not in TOOLS:
        print(f"ERROR: unknown tool: {tool}", file=sys.stderr)
        log("unknown-tool")
        return EXIT_UNKNOWN_TOOL
    log(f"tool:{tool}")
    inject = os.environ.get("PS4RF_AFL_MOCK_INJECT")
    if inject == "error":
        print("ERROR: injected failure before work", file=sys.stderr)
        log("inject:error")
        return EXIT_INJECTED
    if inject == "hang":
        log("inject:hang")
        time.sleep(3600)

    def require(path_text: str | None, label: str) -> Path:
        if not path_text or not Path(path_text).is_file():
            raise _BadInput(f"{label} not found: {path_text}")
        return Path(path_text)

    try:
        if tool == "afl-fuzz":
            print(f"afl-fuzz++{MOCK_VERSION} based on afl-fuzz (offline mock)")
            log("exit:0")
            return EXIT_OK
        if tool == "afl-showmap":
            document = build_showmap(require(args.target, "target"),
                                     require(args.input, "input"))
        elif tool == "afl-cmin":
            corpus = Path(args.corpus) if args.corpus else None
            if corpus is None or not corpus.is_dir():
                raise _BadInput(f"corpus not found: {args.corpus}")
            document = build_cmin(corpus)
        elif tool == "afl-tmin":
            document, minimized = build_tmin(require(args.input, "crash input"))
            if not args.out_min:
                raise _BadInput("--out-min is required for afl-tmin")
            minimized_path = Path(args.out_min)
            minimized_path.parent.mkdir(parents=True, exist_ok=True)
            minimized_path.write_bytes(minimized)
            log(f"minimized:{_sha256_file(minimized_path)}")
        else:
            crashes = Path(args.crashes) if args.crashes else None
            if crashes is None or not crashes.is_dir():
                raise _BadInput(f"crash dir not found: {args.crashes}")
            document = build_collect(crashes)
        if not args.out:
            raise _BadInput("--out is required")
        _write_result(Path(args.out), document)
        log(f"result:{_sha256_file(Path(args.out))}")
        log("exit:0")
        return EXIT_OK
    except _TargetRefused as exc:
        print(f"ERROR: target not in mock catalog: {exc}", file=sys.stderr)
        log("target-refused")
        return EXIT_TARGET
    except _BadInput as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        log(f"bad-input:{exc}")
        return EXIT_BAD_INPUT


if __name__ == "__main__":
    raise SystemExit(main())
