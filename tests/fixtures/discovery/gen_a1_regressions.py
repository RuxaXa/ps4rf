#!/usr/bin/env python3
"""Build/check the A1 counterexample fixture image.

The independent audit A1 reproduced four defects with synthetic inputs.  This file
turns those inputs into a committed image so the regression tests decode real
instructions instead of stubbing capstone operands themselves.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
SOURCE = HERE / "a1-regressions.S"
OUTPUT = HERE / "a1-regressions.json"
BASE = 4096


def build() -> dict:
    with tempfile.TemporaryDirectory(prefix="ps4rf-a1-") as tmp:
        tmp = pathlib.Path(tmp)
        obj, elf, raw = tmp / "a1.o", tmp / "a1.elf", tmp / "a1.bin"
        subprocess.run(["as", "--64", "-o", str(obj), str(SOURCE)], check=True)
        subprocess.run(["ld", "-z", "noexecstack", "-Ttext", hex(BASE), "-e",
                        "guard_unrelated_cmp", "-o", str(elf), str(obj)], check=True)
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
        "schema": "ps4rf.discovery.a1-regressions/1",
        "source": SOURCE.name,
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "base_rva": hex(BASE),
        "image_sha256": hashlib.sha256(blob).hexdigest(),
        "image_hex": blob.hex(),
        "symbols": symbols,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true",
                        help="fail when the committed image differs from a fresh build")
    args = parser.parse_args()
    doc = build()
    text = json.dumps(doc, indent=1, sort_keys=True) + "\n"
    if args.check:
        committed = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if committed != text:
            print("a1-regressions.json is stale; run this script without --check")
            return 1
        print("a1-regressions.json matches the assembler output")
        return 0
    OUTPUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUTPUT} ({len(doc['image_hex']) // 2} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
