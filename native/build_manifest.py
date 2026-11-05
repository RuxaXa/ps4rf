#!/usr/bin/env python3
"""Emit build/toolchain-manifest.json for the W2 native build (W0/D2 + W0/D4 + W0/D16).

The manifest is *generated from the real build*: artifact hashes, the ELF type
(read via readelf) and the compiler/linker versions are measured, never typed.
It fails closed when an artifact is missing or the agent ELF is not ET_DYN, and
it validates the result with the W1 validator before writing.

Usage: python3 build_manifest.py     (run inside native/, after `make`)
"""
from __future__ import annotations

import datetime
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys

NATIVE = pathlib.Path(__file__).resolve().parent
REPO = NATIVE.parent
BUILD = NATIVE / "build"
OUT = BUILD / "toolchain-manifest.json"

CFLAGS = ("-std=c99 -O2 -Wall -Wextra -Werror -fPIC "
          "-D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L "
          "-ffile-prefix-map=$(CURDIR)=. -fdebug-prefix-map=$(CURDIR)=.")
LDFLAGS = "-pie -Wl,--build-id=none -Wl,-z,relro -Wl,-z,now"
LDLIBS = "-lpthread"


def run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True,
                          cwd=str(REPO)).stdout.strip()


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def first_line(text: str) -> str:
    return text.splitlines()[0] if text else "unknown"


def elf_type(path: pathlib.Path) -> str:
    """Normalized ELF type: binutils may print 'DYN (Position-Independent ...)'."""
    out = run(["readelf", "-h", str(path)])
    aliases = {"DYN": "ET_DYN", "EXEC": "ET_EXEC", "REL": "ET_REL", "CORE": "ET_CORE"}
    for line in out.splitlines():
        if "Type:" in line:
            token = line.split("Type:")[1].strip().split()[0]
            return aliases.get(token, token)
    return "unknown"


def main() -> int:
    missing = [str(p) for p in (BUILD / "ps4rfd.elf", BUILD / "ps4rfd.bin",
                                BUILD / "ps4rf_parity") if not p.exists()]
    if missing:
        print(f"missing build artifacts: {', '.join(missing)} (run `make` first)")
        return 1

    agent_type = elf_type(BUILD / "ps4rfd.elf")
    harness_type = elf_type(BUILD / "ps4rf_parity")
    if agent_type != "ET_DYN":
        print(f"ps4rfd.elf is {agent_type}, must be ET_DYN (W0/D2)")
        return 1

    libc = pathlib.Path("/lib/x86_64-linux-gnu/libc.so.6")
    manifest = {
        "kind": "ps4rf.toolchain-manifest",
        "manifest_version": 1,
        "scope": "P4/W2 native userland skeleton (offline host build)",
        "host_target_triple": run(["gcc", "-dumpmachine"]),
        "external_inputs": [
            {
                "name": "glibc",
                "version": first_line(run(["ldd", "--version"])) if libc.exists() else "unknown",
                "source_id": "host C library /lib/x86_64-linux-gnu/libc.so.6 "
                             "(no SDK is used by the W2 core)",
                "sha256": sha256_file(libc) if libc.exists() else "0" * 64,
                "pinned": True,
            }
        ],
        "sdk": {
            "used": False,
            "note": "W2 protocol core is fully in-repo (W0/D1 'D first'); no libPS4 / "
                    "ps4-payload-sdk helper is required yet, so the A/B comparison still "
                    "awaits a real capability need",
        },
        "build": {
            "compiler": {"name": "gcc", "version": first_line(run(["gcc", "--version"]))},
            "linker": {"name": "ld (via gcc)", "version": first_line(run(["ld", "--version"]))},
            "flags": [CFLAGS, LDFLAGS, LDLIBS],
            "source_commit": run(["git", "rev-parse", "HEAD"]),
            "timestamp": {
                "value": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                "hash_authority": False,
            },
        },
        "artifacts": [
            {
                "name": "ps4rfd",
                "kind": "elf",
                "path": "native/build/ps4rfd.elf",
                "elf_type": agent_type,
                "sha256": sha256_file(BUILD / "ps4rfd.elf"),
            },
            {
                "name": "ps4rfd-payload",
                "kind": "bin",
                "path": "native/build/ps4rfd.bin",
                "sha256": sha256_file(BUILD / "ps4rfd.bin"),
            },
            {
                "name": "ps4rf_parity",
                "kind": "elf",
                "path": "native/build/ps4rf_parity",
                "elf_type": harness_type,
                "sha256": sha256_file(BUILD / "ps4rf_parity"),
            },
        ],
    }
    manifest["pins"] = {a["name"]: a["sha256"] for a in manifest["artifacts"]}

    # validate with the W1 validator (fail closed)
    spec = importlib.util.spec_from_file_location(
        "toolchain_manifest", REPO / "tools" / "toolchain" / "toolchain_manifest.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    errors = module.validate(manifest)
    if errors:
        print("manifest validation failed:")
        for err in errors:
            print(f"  - {err}")
        return 1

    OUT.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT.relative_to(REPO)}")
    print(f"  ps4rfd.elf      {manifest['artifacts'][0]['sha256']}  ({agent_type})")
    print(f"  ps4rfd.bin      {manifest['artifacts'][1]['sha256']}")
    print(f"  ps4rf_parity    {manifest['artifacts'][2]['sha256']}  ({harness_type})")
    print(f"  source_commit   {manifest['build']['source_commit']}")
    print(f"  validator       OK (W1 toolchain manifest rules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
