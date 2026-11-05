#!/usr/bin/env python3
"""Build/check the deterministic handle/object identity fixture image (S1.2c)."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
SOURCE = HERE / "handle-fixtures.S"
OUTPUT = HERE / "handle-fixtures.json"
BASE = 4096

#: expected detector per fixture case.  "NO_CLAIM" means the engine stays silent, which
#: is a claim about the analysis, not about the code being safe.
CASES = {
    "fixture_handle_reuse": "D7_handle_object_identity",
    "fixture_object_identity": "NO_CLAIM",
    "fixture_handle_single_drop": "NO_CLAIM",
    "fixture_no_identity_premise": "D8_reference_balance",
    "fixture_two_generations": "NO_CLAIM",
    "fixture_borrowed_reference": "NO_CLAIM",
}

CASE_NOTES = {
    "fixture_handle_reuse": "ownership decided by a 4-byte handle compare, then two drops of "
                            "the acquired object: the surplus drop may land on a foreign object",
    "fixture_object_identity": "NO_CLAIM: identical shape, but the decision compares the 8-byte "
                               "object pointer, so the ownership premise holds",
    "fixture_handle_single_drop": "NO_CLAIM: one drop per acquired reference, even though the "
                                  "decision uses a handle",
    "fixture_no_identity_premise": "two drops and no deciding callee: an accounting question, "
                                   "reported as an observation (rank 3), never a claim",
    "fixture_two_generations": "NO_CLAIM: two acquires, one drop each -- the balance is per "
                               "acquired object, so a global drop count would be wrong",
    "fixture_borrowed_reference": "NO_CLAIM: a second drop is legitimate when the caller took a "
                                  "reference of its own; a count alone never decides",
}

CATALOG = {
    "own_acquire": None,
    "own_fdrop_like": "free",
    "decide_by_handle": None,
    "decide_by_object": None,
}


def build() -> dict:
    with tempfile.TemporaryDirectory(prefix="ps4rf-handles-") as tmp:
        tmp = pathlib.Path(tmp)
        obj, elf, raw = tmp / "h.o", tmp / "h.elf", tmp / "h.bin"
        subprocess.run(["as", "--64", "-o", str(obj), str(SOURCE)], check=True)
        subprocess.run(["ld", "-z", "noexecstack", "-Ttext", hex(BASE), "-e",
                        "fixture_handle_reuse", "-o", str(elf), str(obj)], check=True)
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
        "schema": "ps4rf.discovery.handle-fixtures/1",
        "source": SOURCE.name,
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "base_rva": hex(BASE),
        "image_sha256": hashlib.sha256(blob).hexdigest(),
        "image_hex": blob.hex(),
        "symbols": symbols,
        "roots": {"free": symbols["own_fdrop_like"]["rva"]},
        "catalog": CATALOG,
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
        print("handle fixture drift")
        return 1
    print("handle fixture: up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
