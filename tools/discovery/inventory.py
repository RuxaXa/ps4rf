"""Function-inventory adapters.

The primary firmware has a Ghidra-derived inventory (an external artefact this
package only reads).  The reference firmware has none, so its index is derived
by :meth:`FunctionIndex.from_sweep`.  Both paths yield the same
:class:`~tools.discovery.image.FunctionIndex`, which is what the rest of the
engine consumes.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Optional

from .image import FunctionIndex, FunctionRecord, KernelImage


def from_sqlite(path: str, base: int, table: str = "functions") -> FunctionIndex:
    """Read ``functions(addr TEXT hex, size INTEGER, name TEXT)``."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        cur = conn.cursor()
        recs = []
        for addr, size, name in cur.execute(
            f"SELECT addr, size, name FROM {table} ORDER BY addr"
        ):
            try:
                va = int(addr, 16)
            except (TypeError, ValueError):
                continue
            recs.append(FunctionRecord(rva=va - base, size=int(size or 0), name=name or ""))
        return FunctionIndex(recs)
    finally:
        conn.close()


def from_json(path: str, base: Optional[int] = None) -> FunctionIndex:
    with open(path, "rt", encoding="utf-8") as fh:
        doc = json.load(fh)
    if base is not None:
        doc = dict(doc, base=base)
    return FunctionIndex.from_inventory(doc)


def load(
    image: KernelImage,
    hint: Optional[str] = None,
    base: Optional[int] = None,
    kind: str = "sweep",
) -> FunctionIndex:
    if hint and kind.startswith("sqlite"):
        return from_sqlite(hint, base or image.base)
    if hint and kind.startswith("json"):
        return from_json(hint, base or image.base)
    return FunctionIndex.from_sweep(image)
