#!/usr/bin/env python3
"""Build/check the deterministic D1/D4 x86-64 fixture image."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
SOURCE = HERE / "lifecycle-fixtures.S"
OUTPUT = HERE / "lifecycle-fixtures.json"
BASE = 4096

CASES = {
    "fixture_d1_direct": "USE_AFTER_RELEASE",
    "fixture_d1_invalidated": "NO_CLAIM",
    "fixture_d1_slot_reuse": "NO_CLAIM",
    "fixture_d1_alias": "USE_AFTER_RELEASE",
    "fixture_d1_path": "PATH_DEPENDENT_USE_AFTER_RELEASE",
    "fixture_d1_unknown_effect": "NO_CLAIM",
    "fixture_d4_same_index": "USE_AFTER_RELEASE",
    "fixture_d4_lea_equal": "USE_AFTER_RELEASE",
    "fixture_d4_shift_equal": "USE_AFTER_RELEASE",
    "fixture_d4_other_index": "MAY_ALIAS_REUSE",
    "fixture_d4_cleared": "NO_CLAIM",
    "fixture_indirect_call": "USE_AFTER_RELEASE",
    # S1.2b counterexamples (see the S1.2b review, proven defects 1-4 + P1)
    "fixture_p0_1_approx_may_set": "MAY_USE_AFTER_RELEASE",
    "fixture_p0_1_never_vs_merged": "NO_CLAIM",
    "fixture_p0_2_may_release": "PATH_DEPENDENT_USE_AFTER_RELEASE",
    "fixture_p0_3_tail_cond": "NO_CLAIM",
    "fixture_p0_3_cond_caller": "PATH_DEPENDENT_USE_AFTER_RELEASE",
    "fixture_p0_4_loop_carried": "MAY_USE_AFTER_RELEASE",
    "fixture_p0_4_loop_recycle": "NO_CLAIM",
    "fixture_p1_store_kill": "NO_CLAIM",
    "fixture_p1_outparam": "MAY_USE_AFTER_RELEASE",
}

#: why each case exists and what "NO_CLAIM" means for it: the engine reports
#: nothing, which is not the same claim as "this is safe"
CASE_NOTES = {
    "fixture_d1_direct": "release through one alias, use through a stale slot copy",
    "fixture_d1_invalidated": "NO_CLAIM: the slot is zeroed, so the later load is not stale",
    "fixture_d1_slot_reuse": "NO_CLAIM: the slot is reused for a different object (the old address-keyed rule fired here)",
    "fixture_d1_alias": "two live aliases, one released, the other used",
    "fixture_d1_path": "release on one arm only: unproven, must not be confirmed",
    "fixture_d1_unknown_effect": "NO_CLAIM: an unknown call may free, which is not evidence that it did",
    "fixture_d4_same_index": "released through a slot, reloaded with the same index",
    "fixture_d4_lea_equal": "same slot via lea instead of an index operand",
    "fixture_d4_shift_equal": "same slot via shl+add instead of a hardware scale",
    "fixture_d4_other_index": "different index expression: may-alias, never confirmed",
    "fixture_d4_cleared": "NO_CLAIM: the slot is cleared before it is read again",
    "fixture_indirect_call": "an indirect call through a field, then a release and a use",
    "fixture_p0_1_approx_may_set": "a merged slot holds one of two live objects: a may-set, never a definite release",
    "fixture_p0_1_never_vs_merged": "NO_CLAIM: the never-written slot identity and the merged one stay distinct (store kill)",
    "fixture_p0_2_may_release": "the released pointer is one of two objects: a may-release only",
    "fixture_p0_3_tail_cond": "NO_CLAIM: a tail jump into a conditional wrapper is not a definite release",
    "fixture_p0_3_cond_caller": "call into a conditional wrapper, then a read: a may-release, so an observation",
    "fixture_p0_4_loop_carried": "read in block A, free in block B, back edge A->B->A: the use of iteration n+1 follows the free of n",
    "fixture_p0_4_loop_recycle": "NO_CLAIM: one call site allocates per iteration, so the freshly allocated object is a different object",
    "fixture_p1_store_kill": "NO_CLAIM: the slot is overwritten with a live object after the release",
    "fixture_p1_outparam": "the slot address escapes to an unknown call, so the stored object stays a candidate",
}

CATALOG = {
    "own_thunk": "free",
    "own_forward": "free",
    "own_cond_free": "conditional",
    "own_wrapper_bad": None,
    "own_unknown": None,
}


def build() -> dict:
    with tempfile.TemporaryDirectory(prefix="ps4rf-d1d4-") as tmp:
        tmp = pathlib.Path(tmp)
        obj, elf, raw = tmp / "x.o", tmp / "x.elf", tmp / "x.bin"
        subprocess.run(["as", "--64", "-o", str(obj), str(SOURCE)], check=True)
        subprocess.run(["ld", "-z", "noexecstack", "-Ttext", hex(BASE), "-e",
                        "fixture_d1_direct", "-o", str(elf), str(obj)], check=True)
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
        "schema": "ps4rf.discovery.lifecycle-fixtures/1",
        "source": SOURCE.name,
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "base_rva": hex(BASE),
        "image_sha256": hashlib.sha256(blob).hexdigest(),
        "image_hex": blob.hex(),
        "symbols": symbols,
        "roots": {
            "free": symbols["own_free"]["rva"],
            "alloc": symbols["own_alloc"]["rva"],
        },
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
        print("lifecycle fixture drift")
        return 1
    print("lifecycle fixture: up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
