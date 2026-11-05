#!/usr/bin/env python3
"""Build/check the D3_lock_coverage fixture image."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
SOURCE = HERE / "lock-coverage-fixtures.S"
OUTPUT = HERE / "lock-coverage-fixtures.json"
BASE = 4096

CASES = {
    "fixture_d3_lock_on_every_path": "NO_CLAIM",
    "fixture_d3_lock_on_one_path": "UNLOCKED_WRITE",
    "fixture_d3_store_before_lock_same_block": "UNLOCKED_WRITE",
    "fixture_d3_store_after_lock_same_block": "NO_CLAIM",
}

CASE_NOTES = {
    "fixture_d3_lock_on_every_path":
        "NO_CLAIM: both arms take the lock before the join, so no path reaches the store "
        "unlocked -- even though neither lock block dominates it",
    "fixture_d3_lock_on_one_path":
        "the false arm writes the same field without taking the lock",
    "fixture_d3_store_before_lock_same_block":
        "a store preceding the lock in the same basic block has a lock-free path",
    "fixture_d3_store_after_lock_same_block":
        "the store is after the acquisition in the same basic block",
}


def build() -> dict:
    with tempfile.TemporaryDirectory(prefix="ps4rf-d3-") as tmp:
        tmp = pathlib.Path(tmp)
        obj, elf, raw = tmp / "x.o", tmp / "x.elf", tmp / "x.bin"
        subprocess.run(["as", "--64", "-o", str(obj), str(SOURCE)], check=True)
        subprocess.run(["ld", "-z", "noexecstack", "-Ttext", hex(BASE), "-e",
                        "fixture_d3_lock_on_one_path", "-o", str(elf), str(obj)], check=True)
        subprocess.run(["objcopy", "-O", "binary", "--only-section=.text",
                        str(elf), str(raw)], check=True)
        nm = subprocess.run(["nm", "-S", "--defined-only", "--numeric-sort", str(elf)],
                            check=True, text=True, capture_output=True).stdout
        symbols = {}
        for line in nm.splitlines():
            parts = line.split()
            if len(parts) not in (3, 4) or parts[-2].lower() != "t":
                continue
            name = parts[-1]
            if name.startswith("__") or name in ("_edata", "_end"):
                continue
            size = parts[1] if len(parts) == 4 else "0x0"
            symbols[name] = {"rva": hex(int(parts[0], 16)), "size": hex(int(size, 16))}
        blob = raw.read_bytes()
    missing = sorted(name for name in list(CASES) + ["d3_lock"] if name not in symbols)
    if missing:
        raise SystemExit(f"fixture source is missing symbols: {missing}")
    return {
        "schema": "ps4rf.discovery.lock-coverage-fixtures/1",
        "source": SOURCE.name,
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "base_rva": hex(BASE),
        "image_sha256": hashlib.sha256(blob).hexdigest(),
        "image_hex": blob.hex(),
        "symbols": symbols,
        "roots": {"lock": symbols["d3_lock"]["rva"]},
        "cases": CASES,
        "case_notes": CASE_NOTES,
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
        print("lock-coverage fixture drift")
        return 1
    print("lock-coverage fixture: up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
