"""Experiment recipe registry (profile data, never code).

The generator ``native/target/gen_recipe.py`` turns these documents into the
compile-time table the target uses for ``kernel.snapshot``. Neither this module
nor the generated header contains hand written addresses: everything comes from
the fixture documents, which carry their own provenance block.

Host rules enforced by the generator:
  * max 16 entries, max 0x1000 bytes per entry
  * every FOLLOW_ONCE entry must name an *earlier* entry as its root
  * indexed follows need a bounded index source and a declared maximum
"""
from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "experiments"
RECIPES = (
    "q6-recipe-v3",
    "own1-recipe-v2",
    "diag1-control",
    "diag2-bmp16",
    "diag2-bmp64",
    "diag2-bmp256",
    "diag2-bmp1024",
    "diag3-pg512-end",
    "diag3-pg512-cross",
    "diag3-pg1024-cross",
    "diag4-pt8",
    "diag4-pt64",
    "diag4-pt512",
    "diag5-pt4096boot",
)
MAX_ENTRIES = 16
MAX_ENTRY_LEN = 0x1000
MAX_INDEX = 0xFFFF


def load_recipe(name: str) -> dict:
    if name not in RECIPES:
        raise KeyError(f"unknown recipe {name!r}; known: {RECIPES}")
    return json.loads((FIXTURES / f"{name}.json").read_text())


def validate_recipe(doc: dict) -> dict:
    entries = doc["entries"]
    if len(entries) > MAX_ENTRIES:
        raise ValueError(f"{doc['name']}: {len(entries)} entries above {MAX_ENTRIES}")
    seen = {}
    for i, e in enumerate(entries):
        if e["i"] != i:
            raise ValueError(f"{doc['name']}: entry {i} carries i={e['i']}")
        if not 0 < int(e["length"]) <= MAX_ENTRY_LEN:
            raise ValueError(f"{doc['name']}.{e['name']}: length out of range")
        if e["type"] == "RVA_READ":
            if "rva" not in e:
                raise ValueError(f"{doc['name']}.{e['name']}: RVA_READ needs an rva")
        elif e["type"] == "FOLLOW_ONCE":
            root = e.get("root_index", -1)
            if not 0 <= root < i:
                raise ValueError(f"{doc['name']}.{e['name']}: root_index must name an earlier entry")
            if not 0 <= int(e.get("disp", 0)) <= 0x1000:
                raise ValueError(f"{doc['name']}.{e['name']}: disp above 0x1000")
            if "index_source" in e and not 0 <= int(e.get("max_index", -1)) <= MAX_INDEX:
                raise ValueError(f"{doc['name']}.{e['name']}: indexed follow without a bounded max_index")
        else:
            raise ValueError(f"{doc['name']}.{e['name']}: unknown type {e['type']!r}")
        seen[e["name"]] = i
    names = [e["name"] for e in entries]
    if len(set(names)) != len(names):
        raise ValueError(f"{doc['name']}: duplicate entry names")
    return doc


def all_recipes() -> dict:
    return {name: validate_recipe(load_recipe(name)) for name in RECIPES}
