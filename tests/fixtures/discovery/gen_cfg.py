#!/usr/bin/env python3
"""Build/check the deterministic CFG fixture image.

The expectations below are written from the source text, before the engine is run: a taken
edge to the label the branch names, a fall-through edge to the label after the branch, no
fall-through for a jmp, and *one* successor when the two coincide.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
SOURCE = HERE / "cfg-fixtures.S"
OUTPUT = HERE / "cfg-fixtures.json"
BASE = 4096

#: expected successor sets, as (source label -> successor labels).  An empty list is a
#: positive claim: that block must have no successor at all.
CFG = {
    "fixture_cfg_cond_two_ways": {
        "successors": {"cfg_two_branch": ["cfg_two_else", "cfg_two_fall"]},
        "empty": ["cfg_two_else", "cfg_two_fall"],
        "note": "a conditional branch has exactly two successors: taken and fall-through",
    },
    "fixture_cfg_jmp_only": {
        "successors": {"cfg_jmp_branch": ["cfg_jmp_target"]},
        "empty": ["cfg_jmp_target", "cfg_jmp_dead"],
        "unreachable": ["cfg_jmp_dead"],
        "note": "a direct jmp has the target only, never a fall-through",
    },
    "fixture_cfg_same_target": {
        "successors": {"cfg_same_branch": ["cfg_same_next"]},
        "unique_edges": ["cfg_same_branch"],
        "note": "taken target == fall-through: one successor, not two identical ones",
    },
    "fixture_cfg_indirect": {
        "successors": {"cfg_indirect_branch": []},
        "unreachable": ["cfg_indirect_after"],
        "note": "an indirect jmp has no direct successor; the next instruction is not one",
    },
    "fixture_cfg_loop": {
        "successors": {"cfg_loop_body": ["cfg_loop_body", "cfg_loop_exit"]},
        "empty": ["cfg_loop_exit"],
        "note": "back edge and loop exit are both edges of the same block",
    },
    "fixture_cfg_tail": {
        "successors": {"cfg_tail_branch": []},
        "tail_jumps": {"cfg_tail_branch": "d2_free"},
        "note": "a jmp out of the function is a tail call, not an internal edge",
    },
}


def build() -> dict:
    with tempfile.TemporaryDirectory(prefix="ps4rf-cfg-") as tmp:
        tmp = pathlib.Path(tmp)
        obj, elf, raw = tmp / "x.o", tmp / "x.elf", tmp / "x.bin"
        subprocess.run(["as", "--64", "-o", str(obj), str(SOURCE)], check=True)
        subprocess.run(["ld", "-z", "noexecstack", "-Ttext", hex(BASE), "-e",
                        "fixture_cfg_cond_two_ways", "-o", str(elf), str(obj)], check=True)
        subprocess.run(["objcopy", "-O", "binary", "--only-section=.text",
                        str(elf), str(raw)], check=True)
        nm = subprocess.run(["nm", "-S", "--defined-only", "--numeric-sort", str(elf)],
                            check=True, text=True, capture_output=True).stdout
        functions, labels = {}, {}
        for line in nm.splitlines():
            parts = line.split()
            # a label without a .size has no size column; ld also emits segment markers
            if len(parts) not in (3, 4) or parts[-2].lower() != "t":
                continue
            addr = parts[0]
            size = parts[1] if len(parts) == 4 else "0x0"
            name = parts[-1]
            if name.startswith("__") or name in ("_edata", "_end"):
                continue
            target = functions if name.startswith("fixture_") else labels
            target[name] = {"rva": hex(int(addr, 16)), "size": hex(int(size, 16))}
        blob = raw.read_bytes()
    needed = {"d2_free"} | set(functions)
    for entry in CFG.values():
        for source in entry.get("successors", {}):
            needed.add(source)
        for source in entry.get("empty", []):
            needed.add(source)
        for source in entry.get("unreachable", []):
            needed.add(source)
        for source, target in entry.get("tail_jumps", {}).items():
            needed.update({source, target})
        for source, targets in entry.get("successors", {}).items():
            needed.update(targets)
    missing = sorted(name for name in needed if name not in labels and name not in functions)
    if missing:
        raise SystemExit(f"fixture source is missing labels: {missing}")
    return {
        "schema": "ps4rf.discovery.cfg-fixtures/1",
        "source": SOURCE.name,
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "base_rva": hex(BASE),
        "image_sha256": hashlib.sha256(blob).hexdigest(),
        "image_hex": blob.hex(),
        "functions": functions,
        "labels": labels,
        "cfg": CFG,
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
        print("cfg fixture drift")
        return 1
    print("cfg fixture: up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
