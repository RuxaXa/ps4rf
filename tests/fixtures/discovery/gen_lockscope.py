#!/usr/bin/env python3
"""Build/check the deterministic D3 x86-64 fixture image."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
SOURCE = HERE / "lockscope-fixtures.S"
OUTPUT = HERE / "lockscope-fixtures.json"
BASE = 4096


def build() -> dict:
    with tempfile.TemporaryDirectory(prefix="ps4rf-d3-") as tmp:
        tmp = pathlib.Path(tmp)
        obj, elf, raw = tmp / "x.o", tmp / "x.elf", tmp / "x.bin"
        subprocess.run(["as", "--64", "-o", str(obj), str(SOURCE)], check=True)
        subprocess.run(["ld", "-z", "noexecstack", "-Ttext", hex(BASE), "-e",
                        "fixture_missing_lock", "-o", str(elf), str(obj)], check=True)
        subprocess.run(["objcopy", "-O", "binary", "--only-section=.text",
                        str(elf), str(raw)], check=True)
        nm = subprocess.run(["nm", "-S", "--defined-only", "--numeric-sort", str(elf)],
                            check=True, text=True, capture_output=True).stdout
        symbols = {}
        for line in nm.splitlines():
            parts = line.split()
            if len(parts) != 4 or parts[2].lower() != "t":
                continue
            addr, size, _typ, name = parts
            symbols[name] = {"rva": hex(int(addr, 16)), "size": hex(int(size, 16))}
        blob = raw.read_bytes()
    return {
        "schema": "ps4rf.discovery.lock-fixtures/1",
        "source": SOURCE.name,
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "base_rva": hex(BASE),
        "image_sha256": hashlib.sha256(blob).hexdigest(),
        "image_hex": blob.hex(),
        "symbols": symbols,
        "cases": {
            "fixture_missing_lock": "PATH_DEPENDENT",
            "fixture_protected": "HELD",
            "fixture_different_lock": "DIFFERENT_LOCK",
            "fixture_alias": "HELD",
            "fixture_early_return": "HELD",
            "fixture_claim_missing": "PATH_DEPENDENT",
            "fixture_claim_fixed": "HELD",
            "fixture_shared_claim_write": "DIFFERENT_LOCK",
            "fixture_unknown": "UNKNOWN",
        },
    }


def rendered() -> str:
    return json.dumps(build(), sort_keys=True, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.write == args.check:
        parser.error("choose exactly one of --write or --check")
    body = rendered()
    if args.write:
        OUTPUT.write_text(body, encoding="utf-8")
        print(f"wrote {OUTPUT}")
        return 0
    if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != body:
        print("lockscope fixture drift")
        return 1
    print("lockscope fixture: up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
