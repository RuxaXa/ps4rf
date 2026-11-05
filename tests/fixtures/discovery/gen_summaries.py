#!/usr/bin/env python3
"""Build/check the deterministic S1.6 interprocedural-summary fixture image.

Same contract as ``gen_handles.py``: real binutils assemble the bytes, the generated JSON is
committed, and ``--check`` fails when the committed image no longer matches the source. Nothing is
hand-encoded, and the analysis decodes through the same capstone path as the firmware.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
SOURCE = HERE / "summary-fixtures.S"
OUTPUT = HERE / "summary-fixtures.json"
BASE = 4096

#: Symbols that behave like the firmware's release anchor.  Handed in as data, exactly like a
#: firmware anchor: the analysis reads offsets, never a name.
RELEASE_ROOTS = ["own_release"]

#: The claim each fixture supports.  ``REFUSED``/``UNKNOWN`` are claims too: they say what the
#: layer is not allowed to conclude from this shape.
CASES = {
    "callee_deref": "parameter 0 is dereferenced at +0x10, width 4",
    "callee_two_args_same_field": "two parameters touch the same offset and stay distinct effects",
    "callee_drop_guarded": "a lock xadd of -1 followed by cmp 1 is a guarded refcount drop",
    "callee_drop_unguarded": "a lock xadd of -1 with no count test is an unguarded drop",
    "callee_take": "a lock xadd of +1 is a reference take, not a drop",
    "callee_conditional_free": "a release on one arm is conditional, so must becomes may",
    "callee_escape_global": "a store to a global is an escape, not a release",
    "callee_return_arg": "returning the argument is an alias, not a new reference",
    "callee_return_field": "returning a field load is not an alias of the argument",
    "callee_return_alloc": "returning a callee result is an object of unknown ownership",
    "callee_lea_interior": "an interior pointer keeps the base object identity",
    "callee_indirect": "an indirect call forces every postcondition to UNKNOWN",
    "caller_redefined_arg": "the nearest write to an argument register decides the placement",
    "caller_subregister": "a 32-bit write to edi still places the object",
    "caller_lea_arg": "an interior pointer is still placed as the object",
    "caller_no_setup": "a call with no argument setup proves nothing",
    "caller_return_alias_chain": "a returned alias composes into a two-hop ownership proof",
    "caller_return_field_chain": "a returned field is a different object and must not compose",
    "caller_escape": "an escaping argument keeps postcondition LIVE",
}


def build() -> dict:
    with tempfile.TemporaryDirectory(prefix="ps4rf-summaries-") as tmp:
        tmp = pathlib.Path(tmp)
        obj, elf, raw = tmp / "s.o", tmp / "s.elf", tmp / "s.bin"
        subprocess.run(["as", "--64", "-o", str(obj), str(SOURCE)], check=True)
        subprocess.run(["ld", "-z", "noexecstack", "-Ttext", hex(BASE), "-e",
                        "callee_deref", "-o", str(elf), str(obj)], check=True)
        subprocess.run(["objcopy", "-O", "binary", "--only-section=.text",
                        str(elf), str(raw)], check=True)
        nm = subprocess.run(["nm", "-S", "--defined-only", "--numeric-sort", str(elf)],
                            check=True, text=True, capture_output=True).stdout
        symbols = {}
        for line in nm.splitlines():
            parts = line.split()
            if len(parts) != 4 or parts[2].lower() != "t":
                continue
            addr, size, _type, name = parts
            symbols[name] = {"rva": hex(int(addr, 16)), "size": hex(int(size, 16))}
        blob = raw.read_bytes()
    return {
        "base_rva": hex(BASE),
        "image_hex": blob.hex(),
        "image_sha256": hashlib.sha256(blob).hexdigest(),
        "symbols": symbols,
        "release_roots": RELEASE_ROOTS,
        "cases": CASES,
    }


def main(argv: list) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail when the committed JSON does not match the source")
    args = parser.parse_args(argv)
    document = build()
    rendered = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.check:
        if not OUTPUT.exists():
            print(f"missing {OUTPUT.name}; run without --check")
            return 1
        current = OUTPUT.read_text()
        if current != rendered:
            print(f"{OUTPUT.name} is stale; regenerate it")
            return 1
        print(f"{OUTPUT.name} matches the source ({document['image_sha256'][:16]}…)")
        return 0
    OUTPUT.write_text(rendered)
    print(f"wrote {OUTPUT.name}: {len(document['symbols'])} symbols, "
          f"{len(document['image_hex']) // 2} bytes, sha256 {document['image_sha256'][:16]}…")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
