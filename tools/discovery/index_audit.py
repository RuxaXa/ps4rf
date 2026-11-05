"""Index comparability audit.

Two firmwares can be scanned by the same rules and still produce numbers that
cannot be compared: one index comes from a curated inventory, the other from a
byte sweep.  Before any *global* firmware score is quoted, this module measures
how the two indexes were built and what part of each number is signal.

Measured per firmware, all derivable from the pinned image and the index alone:

* **provider** -- ``inventory`` (named records with real sizes) or ``sweep``
  (starts derived from call targets and prologue bytes, sizes = distance to the
  next start).
* **reference evidence** -- how many records are the target of at least one
  direct ``call``/``jmp rel32`` inside the executable ranges.  A record without
  any reference and without a prologue is a sweep artefact, not a function.
* **prologue evidence** -- the record begins with a known prologue byte pattern.
* **nesting** -- a record that starts inside another record's span is a
  fragment of that record (only meaningful when spans are real).
* **decode** -- how many records fail to decode at all in a bounded prefix.

The module never asserts that one index is "better"; it reports the basis so a
score can be normalised (e.g. "per referenced record") or refused.
"""

from __future__ import annotations

import struct
from typing import Dict, Iterable, List, Optional, Tuple

from .image import FunctionIndex, KernelImage, require_capstone

PROLOGUES = (b"\x55\x48\x89\xe5", b"\x55\x48\x8b\xec")
CHUNK = 1 << 23  # 8 MiB; a rel32 pattern is 5 bytes, so a 4-byte overlap suffices


def rel32_sites(image: KernelImage, opcodes: Tuple[int, ...] = (0xE8, 0xE9)):
    """Yield ``(site, target)`` for every direct ``call``/``jmp rel32``.

    Chunked: an executable range is routinely larger than a comfortable single
    read, and a truncated read silently *undercounts* references -- which is
    exactly the kind of number this module exists to get right.
    """
    for lo, hi in image.executable_ranges():
        span = hi - lo
        pos = 0
        while pos < span:
            length = min(CHUNK, span - pos)
            blob = image.read(lo + pos, length)
            for opcode in opcodes:
                needle = bytes([opcode])
                at = blob.find(needle)
                while at != -1 and at + 5 <= length:
                    rel = struct.unpack_from("<i", blob, at + 1)[0]
                    site = lo + pos + at
                    tgt = site + 5 + rel
                    if lo <= tgt < hi:
                        yield site, tgt
                    at = blob.find(needle, at + 1)
            if length < CHUNK:
                break
            pos += CHUNK - 4


def reference_targets(image: KernelImage) -> Dict[int, int]:
    """rva -> number of direct ``call``/``jmp rel32`` sites pointing at it.

    Only relative branches whose target lands inside the *same* executable range
    count; anything else is either data or a cross-range artefact.
    """
    out: Dict[int, int] = {}
    for _site, tgt in rel32_sites(image):
        out[tgt] = out.get(tgt, 0) + 1
    return out


def prologue_starts(image: KernelImage) -> set:
    starts = set()
    for pat in PROLOGUES:
        starts.update(image.find_all(pat))
    return starts


def _nested_count(index: FunctionIndex, starts: set) -> int:
    """Records whose start lies strictly inside the previous record's span."""
    recs = index.records
    nested = 0
    for i in range(1, len(recs)):
        prev = recs[i - 1]
        if prev.size > 0 and recs[i].rva < prev.rva + prev.size:
            nested += 1
    return nested


def _percentile(values: List[int], q: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round(q * (len(ordered) - 1)))))
    return ordered[idx]


def _decode_failures(image: KernelImage, rvas: Iterable[int], span: int = 16) -> int:
    require_capstone()
    bad = 0
    for rva in rvas:
        try:
            ins, _md = image.disasm(rva, span)
        except Exception:
            bad += 1
            continue
        if not ins or ins[0].size <= 0:
            bad += 1
    return bad


def audit(name: str, image: KernelImage, index: FunctionIndex,
          provider: str, sample_for_decode: int = 4096) -> dict:
    """One firmware's index basis, all counts exact except the decode sample."""
    recs = index.records
    total = len(recs)
    exec_ranges = image.executable_ranges()
    exec_bytes = sum(hi - lo for lo, hi in exec_ranges)

    refs = reference_targets(image)
    prologues = prologue_starts(image)

    starts = {r.rva for r in recs}
    referenced = sum(1 for r in recs if refs.get(r.rva))
    prologue_only = sum(
        1 for r in recs if not refs.get(r.rva) and r.rva in prologues
    )
    unreferenced = total - referenced - prologue_only
    named = sum(1 for r in recs if r.named)

    spans = [(r.rva, r.rva + max(r.size, 0)) for r in recs if r.size > 0]
    covered = set()
    for lo, hi in spans:
        covered.update(range(lo, min(hi, lo + 0x4000)))
    covered_bytes = len(covered)

    sizes = [r.size for r in recs if r.size > 0]
    step = max(1, total // sample_for_decode)
    sample = [r.rva for r in recs[::step]][:sample_for_decode]

    return {
        "firmware": name,
        "provider": provider,
        "records": total,
        "named_records": named,
        "referenced_records": referenced,
        "prologue_only_records": prologue_only,
        "unreferenced_records": unreferenced,
        "starts_in_index_also_reference_targets": sum(1 for s in starts if refs.get(s)),
        "reference_targets_outside_index": sum(1 for t in refs if t not in starts),
        "nested_records": _nested_count(index, starts),
        "executable_ranges": [[hex(lo), hex(hi)] for lo, hi in exec_ranges],
        "executable_bytes": exec_bytes,
        "covered_bytes_first_0x4000": covered_bytes,
        "coverage_fraction": round(covered_bytes / exec_bytes, 6) if exec_bytes else 0.0,
        "size_bytes": {
            "min": min(sizes) if sizes else 0,
            "p10": _percentile(sizes, 0.10),
            "median": _percentile(sizes, 0.50),
            "p90": _percentile(sizes, 0.90),
            "max": max(sizes) if sizes else 0,
        },
        "decode_failure_rate_sampled": round(
            _decode_failures(image, sample) / len(sample), 6
        ) if sample else 0.0,
        "decode_sample": len(sample),
    }


def compare(rows: List[dict]) -> dict:
    """Normalised comparison: which numbers are comparable at all."""
    by_fw = {r["firmware"]: r for r in rows}
    notes = []
    for r in rows:
        if r["provider"] == "sweep":
            notes.append(
                f"{r['firmware']}: index comes from a byte sweep, so 'records' counts "
                f"starts (prologue bytes and branch targets), not functions; "
                f"{r['unreferenced_records']} records carry neither a reference nor a "
                f"prologue and {r['nested_records']} start inside another record."
            )
        else:
            notes.append(
                f"{r['firmware']}: index comes from a curated inventory with real "
                f"sizes ({r['named_records']} named records)."
            )
    comparable = {
        "records": False,
        "referenced_records": True,
        "covered_bytes_first_0x4000": True,
        "decode_failure_rate_sampled": True,
        "size_bytes": False,
    }
    ratios = {}
    fws = sorted(by_fw)
    if len(fws) == 2:
        a, b = by_fw[fws[0]], by_fw[fws[1]]
        for key in ("records", "referenced_records", "covered_bytes_first_0x4000"):
            if b[key]:
                ratios[f"{fws[0]}_per_{fws[1]}_{key}"] = round(a[key] / b[key], 4)
    return {"comparable_fields": comparable, "ratios": ratios, "notes": notes}


def run(env, firmwares: Optional[List[str]] = None) -> dict:
    names = firmwares or sorted(env.images)
    rows = []
    for name in names:
        facts = env.facts[name]
        provider = (facts.doc.get("inventory") or {}).get("kind", "sweep")
        rows.append(audit(name, env.images[name], env.indexes[name], provider))
    return {"firmwares": rows, "comparison": compare(rows), "verdict": _verdict(rows)}


def _verdict(rows: List[dict]) -> str:
    if any(r["provider"] == "sweep" for r in rows) and any(
        r["provider"] != "sweep" for r in rows
    ):
        return "NOT_COMPARABLE_RAW_COUNTS"
    return "COMPARABLE_SAME_PROVIDER"
