#!/usr/bin/env python3
"""Offline mock of a Ghidra ``analyzeHeadless`` CLI (P3).

Scope: exactly the CLI surface that :mod:`tools.ghidra.adapter` drives. This is
a *fake* headless runner: it never parses, loads or executes the imported
artifact — it hashes the bytes, looks the hash up in a canned catalog and writes
a deterministic JSON export. No Java, no Ghidra, no network, no subprocess.

Determinism: for the same artifact, project name, script and postScript output
path the export bytes are identical (sorted keys, no timestamps). The export
contains only the artifact *hash*, never its path, so committed fixtures stay
reproducible.

CLI surface (v0.1 assumption, documented in tools/ghidra/README.md):

  headless_mock.py <project_location> <project_name>
      -import <artifact> -scriptPath <dir> -postScript <script> [args] [-deleteProject]
  headless_mock.py --version

Exit codes: 0 ok, 2 usage/import missing, 3 unknown artifact, 4 script missing,
5 injected failure. ``-deleteProject`` is accepted and ignored (no project is
created).

Test controls (environment, read at process start):

  PS4RF_GHIDRA_MOCK_LOG      append-only call log (one line per phase)
  PS4RF_GHIDRA_MOCK_INJECT   ``error`` -> fail after import; ``hang`` -> sleep

The call log records phase markers and the artifact hash, never file contents.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

MOCK_VERSION = "11.0-mock"
SCHEMA_ID = "ps4rf.ghidra.export/v1"
FIXTURE_SHA256 = "bb249eaf3b7666d21e9149147d4c7a1ef04c4695cd5b539e251094d3795e7c95"

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_UNKNOWN_ARTIFACT = 3
EXIT_SCRIPT_MISSING = 4
EXIT_INJECTED = 5

_PROGRAM = {
    "name": "ps4rf-fixture",
    "language": "x86:LE:64:default (mock)",
    "image_base": "0x00400000",
}

_FUNCTIONS = [
    {"name": "mock_init", "entry": "0x401000", "size": 64,
     "body": "mock_init: initialise internal tables"},
    {"name": "mock_parse_header", "entry": "0x401040", "size": 120,
     "body": "mock_parse_header: validate magic and length fields"},
    {"name": "mock_dispatch", "entry": "0x4010b8", "size": 288,
     "body": "mock_dispatch: route opcode via jump table"},
    {"name": "mock_free", "entry": "0x4011d8", "size": 48,
     "body": "mock_free: release tracked buffers"},
    {"name": "mock_helper", "entry": "0x401208", "size": 36,
     "body": "mock_helper: shared bounds-check helper"},
]

_DECOMPILATIONS = [
    {"function": "mock_init", "entry": "0x401000",
     "text": "void mock_init(void)\n{\n  mock_table = mock_alloc(0x100);\n"
             "  mock_state = 0;\n}\n"},
    {"function": "mock_dispatch", "entry": "0x4010b8",
     "text": "int mock_dispatch(int opcode)\n{\n  if (opcode > 7) {\n    return -1;\n  }\n"
             "  return mock_table[opcode](mock_state);\n}\n"},
]

_XREFS = [
    {"from": "0x4010c4", "to": "0x401000", "type": "CALL"},
    {"from": "0x4010e0", "to": "0x401208", "type": "CALL"},
    {"from": "0x401060", "to": "0x401208", "type": "CALL"},
    {"from": "0x401118", "to": "0x404020", "type": "DATA"},
]

# Canned catalog: only artifacts whose bytes are committed as a test fixture are
# analyzable. Everything else is refused (fail closed).
CATALOG = {FIXTURE_SHA256: {"program": _PROGRAM, "functions": _FUNCTIONS,
                            "decompilations": _DECOMPILATIONS, "xrefs": _XREFS}}


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes(text.encode("utf-8"))


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _logger():
    target = os.environ.get("PS4RF_GHIDRA_MOCK_LOG")
    if not target:
        return lambda line: None

    def log(line: str) -> None:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    return log


def build_export(artifact_sha256: str, project_name: str, script: Path) -> dict:
    """Deterministic export document for a catalogued artifact."""
    spec = CATALOG[artifact_sha256]
    return {
        "schema": SCHEMA_ID,
        "artifact": {"sha256": artifact_sha256},
        "program": dict(spec["program"]),
        "functions": [
            {"name": f["name"], "entry": f["entry"], "size": f["size"],
             "body_sha256": _sha256_text(f["body"])}
            for f in spec["functions"]],
        "xrefs": [dict(x) for x in spec["xrefs"]],
        "decompilations": [
            {"function": d["function"], "entry": d["entry"], "text": d["text"],
             "text_sha256": _sha256_text(d["text"])}
            for d in spec["decompilations"]],
        "generator": {"tool": "ghidra-headless", "version": MOCK_VERSION,
                      "script": script.name, "script_sha256": _sha256_file(script)},
    }


def _parse(argv: list[str]):
    parser = argparse.ArgumentParser(prog="analyzeHeadless-mock", add_help=False)
    parser.add_argument("project_location")
    parser.add_argument("project_name")
    parser.add_argument("-import", dest="import_path")
    parser.add_argument("-scriptPath", dest="script_path", default=".")
    parser.add_argument("-postScript", dest="post_script", nargs="+")
    parser.add_argument("-deleteProject", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    log = _logger()
    if len(argv) == 1 and argv[0] in ("--version", "-version"):
        print(f"Ghidra {MOCK_VERSION} (headless, mock)")
        log("version")
        return EXIT_OK
    try:
        args = _parse(argv)
    except SystemExit:
        print("usage: headless_mock.py <project_location> <project_name> "
              "-import <artifact> -scriptPath <dir> -postScript <script> [args]",
              file=sys.stderr)
        log("usage-error")
        return EXIT_USAGE
    if not args.import_path or not args.post_script:
        print("ERROR: -import and -postScript are required", file=sys.stderr)
        log("usage-error")
        return EXIT_USAGE
    artifact = Path(args.import_path)
    if not artifact.is_file():
        print(f"ERROR: import file not found: {artifact}", file=sys.stderr)
        log("import-missing")
        return EXIT_USAGE
    digest = _sha256_file(artifact)
    log(f"import:{digest}")
    inject = os.environ.get("PS4RF_GHIDRA_MOCK_INJECT")
    if inject == "error":
        print("ERROR: injected failure after import", file=sys.stderr)
        log("inject:error")
        return EXIT_INJECTED
    if inject == "hang":
        log("inject:hang")
        time.sleep(3600)
        return EXIT_INJECTED
    if digest not in CATALOG:
        print("ERROR: artifact not in mock catalog (offline mock supports the "
              "committed fixture only)", file=sys.stderr)
        log("unknown-artifact")
        return EXIT_UNKNOWN_ARTIFACT
    script = Path(args.script_path) / args.post_script[0]
    if not script.is_file():
        print(f"ERROR: post script not found: {script}", file=sys.stderr)
        log("script-missing")
        return EXIT_SCRIPT_MISSING
    out_path = Path(args.post_script[1]) if len(args.post_script) > 1 else \
        Path(args.project_location) / "ps4rf-export.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    export = build_export(digest, args.project_name, script)
    out_path.write_text(json.dumps(export, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    log(f"postscript:{script.name}")
    log(f"export:{out_path}")
    log("exit:0")
    print(f"INFO: export written to {out_path}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
