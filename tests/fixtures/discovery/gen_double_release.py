#!/usr/bin/env python3
"""Build/check the deterministic D2_double_release x86-64 fixture image.

Same contract as the D1/D4 generator: real binutils assemble and link the image,
capstone decodes it through the engine's own path, and the release root reaches
the analysis as fixture *data*.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
SOURCE = HERE / "double-release-fixtures.S"
OUTPUT = HERE / "double-release-fixtures.json"
BASE = 4096

#: what D2 must decide for each fixture, before any of it is run
CASES = {
    "fixture_d2_register_positive": "DOUBLE_RELEASE",
    "fixture_d2_register_rebound_all_paths": "NO_CLAIM",
    "fixture_d2_field_positive": "DOUBLE_RELEASE",
    "fixture_d2_field_reset": "NO_CLAIM",
    "fixture_d2_base_rebound": "NO_CLAIM",
    "fixture_d2_caller_saved_base": "NO_CLAIM",
    "fixture_d2_loop_carried": "NO_CLAIM",
    "fixture_d2_refcount_guarded": "NO_CLAIM",
    "fixture_d2_conditional_pair": "DOUBLE_RELEASE",
}

#: why each case exists; "NO_CLAIM" is a refusal, never a statement that the code is safe
CASE_NOTES = {
    "fixture_d2_register_positive":
        "two releases of one callee-saved register, never rewritten between them",
    "fixture_d2_register_rebound_all_paths":
        "NO_CLAIM: the same register label holds a different object on every path to the "
        "second release",
    "fixture_d2_field_positive":
        "two loads of one untouched object's field with no reset in between",
    "fixture_d2_field_reset":
        "NO_CLAIM: the field is reset to NULL after the first release",
    "fixture_d2_base_rebound":
        "NO_CLAIM: byte-identical slot labels, but the base register is rebound on every path",
    "fixture_d2_caller_saved_base":
        "NO_CLAIM: the base register is caller-saved, so the release call itself may clobber it",
    "fixture_d2_loop_carried":
        "NO_CLAIM: the aio_multi_delete shape -- two sites inside a loop, the register is "
        "reloaded per iteration, so each iteration releases a different object",
    "fixture_d2_refcount_guarded":
        "NO_CLAIM: both sites run only when the reference count reached zero, which no "
        "single path can observe twice",
    "fixture_d2_conditional_pair":
        "both releases on one arm: conditional is not a refusal, the arm frees twice",
}


def build() -> dict:
    with tempfile.TemporaryDirectory(prefix="ps4rf-d2-") as tmp:
        tmp = pathlib.Path(tmp)
        obj, elf, raw = tmp / "x.o", tmp / "x.elf", tmp / "x.bin"
        subprocess.run(["as", "--64", "-o", str(obj), str(SOURCE)], check=True)
        subprocess.run(["ld", "-z", "noexecstack", "-Ttext", hex(BASE), "-e",
                        "fixture_d2_register_positive", "-o", str(elf), str(obj)], check=True)
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
    missing = sorted(name for name in list(CASES) + ["d2_free", "d2_alloc"]
                     if name not in symbols)
    if missing:
        raise SystemExit(f"fixture source is missing symbols: {missing}")
    return {
        "schema": "ps4rf.discovery.double-release-fixtures/1",
        "source": SOURCE.name,
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "base_rva": hex(BASE),
        "image_sha256": hashlib.sha256(blob).hexdigest(),
        "image_hex": blob.hex(),
        "symbols": symbols,
        "roots": {
            "free": symbols["d2_free"]["rva"],
            "alloc": symbols["d2_alloc"]["rva"],
        },
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
        print("double-release fixture drift")
        return 1
    print("double-release fixture: up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
