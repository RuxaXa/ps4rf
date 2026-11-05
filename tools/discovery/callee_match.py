"""Callee-level correspondence between two firmware versions of one function.

Whole-function skeleton binding is conservative (it refuses when a prologue
differs).  Inside an *already aligned* pair -- two syscall handlers with the same
syscall number, say -- a much sharper question can be asked: which callee is
which, and did the call sequence change?

Matching rule: a callee's own body gives a small structural signature (decoded
instruction count in a fixed window, number of lock-prefixed/atomic
instructions, number of string/repeat operations).  Two callees from different
firmwares pair up when their signatures are equal *and unique* in the pair;
anything ambiguous stays unmatched instead of being guessed.

Measured on the aio_multi_delete pair (9.00 vs 13.52): 17 unique callees on each
side, 17 pairs, no ambiguity -- and the two pairs that matter are recognisable
without symbols: ``free`` (8 calls, 76 instructions) and ``fdrop``-like (3 calls,
69 instructions, 2 repeat ops).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .image import KernelImage, require_capstone


def callee_features(image: KernelImage, rva: int, window: int = 0x100) -> Optional[dict]:
    require_capstone()
    try:
        ins, _md = image.disasm(rva, window, instructions=True)
    except Exception:
        return None
    if not ins:
        return None
    lockish = sum(
        1
        for i in ins
        if "LOCK" in str(i.prefix).upper() or i.mnemonic in ("xchg", "cmpxchg", "xadd")
    )
    rep = sum(1 for i in ins if i.mnemonic.startswith("rep") or "movs" in i.mnemonic)
    ind = sum(1 for i in ins if i.mnemonic in ("call", "jmp") and not i.op_str.startswith("0x"))
    return {
        "n": len(ins),
        "lockish": lockish,
        "rep": rep,
        "indirect": ind,
        "signature": (len(ins) // 4, lockish, rep, ind),
    }


@dataclass
class CallProfile:
    rva: int
    size: int
    sites: List[Tuple[int, int]]
    counts: Counter
    sequence: List[int]


def call_profile(image: KernelImage, rva: int, size: int) -> CallProfile:
    require_capstone()
    ins, _md = image.disasm(rva, size, instructions=False)
    sites, seq = [], []
    for i in ins:
        if i.mnemonic != "call":
            continue
        try:
            tgt = int(i.op_str, 16)
        except Exception:
            continue
        sites.append((i.address, tgt))
        seq.append(tgt)
    return CallProfile(rva=rva, size=size, sites=sites, counts=Counter(seq), sequence=seq)


def match_callees(a_image: KernelImage, a_profile: CallProfile,
                  b_image: KernelImage, b_profile: CallProfile) -> dict:
    """Pair callees of two aligned functions by structural signature."""
    a_feat = {c: callee_features(a_image, c) for c in a_profile.counts}
    b_feat = {c: callee_features(b_image, c) for c in b_profile.counts}
    a_groups: Dict[tuple, List[int]] = {}
    b_groups: Dict[tuple, List[int]] = {}
    for c, f in a_feat.items():
        if f:
            a_groups.setdefault(f["signature"], []).append(c)
    for c, f in b_feat.items():
        if f:
            b_groups.setdefault(f["signature"], []).append(c)
    mapping: Dict[int, int] = {}
    ambiguous_a, ambiguous_b = [], []
    for sig, a_list in a_groups.items():
        b_list = b_groups.get(sig, [])
        if len(a_list) == 1 and len(b_list) == 1:
            mapping[a_list[0]] = b_list[0]
        else:
            ambiguous_a.extend(a_list)
            ambiguous_b.extend(b_list)
    mapped_b = set(mapping.values())
    unmatched_a = [c for c in a_profile.counts if c not in mapping]
    unmatched_b = [c for c in b_profile.counts if c not in mapped_b]
    return {
        "a_rva": hex(a_profile.rva),
        "b_rva": hex(b_profile.rva),
        "a_unique_callees": len(a_profile.counts),
        "b_unique_callees": len(b_profile.counts),
        "pairs": len(mapping),
        "mapping": {hex(k): hex(v) for k, v in sorted(mapping.items())},
        "ambiguous_a": [hex(c) for c in sorted(ambiguous_a)],
        "ambiguous_b": [hex(c) for c in sorted(ambiguous_b)],
        "unmatched_a": [hex(c) for c in sorted(unmatched_a)],
        "unmatched_b": [hex(c) for c in sorted(unmatched_b)],
        "features_a": {
            hex(c): {k: v for k, v in a_feat[c].items() if k != "signature"}
            for c in a_feat
            if a_feat[c]
        },
        "features_b": {
            hex(c): {k: v for k, v in b_feat[c].items() if k != "signature"}
            for c in b_feat
            if b_feat[c]
        },
        "_mapping_raw": mapping,
    }


def sequence_diff(a_profile: CallProfile, b_profile: CallProfile,
                  mapping: Dict[int, int]) -> dict:
    """Compare the call *sequences* after translating callees through ``mapping``."""
    inv = {v: k for k, v in mapping.items()}
    b_seq = [inv.get(c) for c in b_profile.sequence]
    a_seq = a_profile.sequence
    diffs = []
    n = min(len(a_seq), len(b_seq))
    for i in range(n):
        if b_seq[i] != a_seq[i]:
            diffs.append(
                {
                    "index": i,
                    "a_callee": hex(a_seq[i]) if a_seq[i] is not None else None,
                    "b_callee_mapped": hex(b_seq[i]) if b_seq[i] is not None else None,
                }
            )
            if len(diffs) >= 16:
                break
    return {
        "a_calls": len(a_seq),
        "b_calls": len(b_seq),
        "length_delta": len(b_seq) - len(a_seq),
        "first_divergences": diffs,
        "identical_sequence": not diffs and len(a_seq) == len(b_seq),
    }


def identify_by_anchor(
    a_image: KernelImage, a_profile: CallProfile,
    b_image: KernelImage, b_profile: CallProfile,
    a_anchor: int,
    b_anchor_names: Optional[dict] = None,
) -> Optional[int]:
    """Translate a named anchor callee (e.g. ``free``) across the pair.

    The anchor is named on the primary side only; the reference side gets the
    same structure-matched callee.  Returns ``None`` when the anchor has no
    unique counterpart -- an unproven translation is worse than none.
    """
    result = match_callees(a_image, a_profile, b_image, b_profile)
    raw = result["_mapping_raw"]
    return raw.get(a_anchor)
