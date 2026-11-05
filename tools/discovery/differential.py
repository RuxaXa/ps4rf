"""Cross-firmware function binding.

Firmware differences are the strongest ground truth we have offline: a bug that
was fixed between two images must show a code difference *in the same function*.
Binding two images therefore needs a correspondence that does not depend on
addresses (they move) or names (only the primary image has any).

Method: an instruction *skeleton* per function (mnemonic sequence, operands
reduced to register/memory/immediate shape), used in two stages --

1. an index on the first N skeleton tokens + a size bucket proposes candidates;
2. a longest-common-subsequence ratio over the full skeleton decides.

The result is a classification per pair, and it is deliberately allowed to be
``UNBOUND``: a function that exists only in one image is a real firmware
difference and must not be forced into a pair.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from .image import FunctionIndex, KernelImage, require_capstone

IDENTICAL = "IDENTICAL_BYTES"
SAME_SKELETON = "SAME_SKELETON"
CHANGED = "CHANGED"
DIVERGENT = "DIVERGENT"
UNBOUND = "UNBOUND"

SHAPE_BY_MNEMONIC = {
    "mov": "M",
    "movzx": "M",
    "movsx": "M",
    "movsxd": "M",
    "lea": "L",
    "call": "C",
    "jmp": "J",
    "cmp": "K",
    "test": "T",
    "add": "A",
    "sub": "A",
    "and": "A",
    "or": "A",
    "xor": "A",
    "imul": "A",
    "shl": "A",
    "shr": "A",
    "sar": "A",
    "push": "P",
    "pop": "P",
    "ret": "R",
    "nop": "N",
    "inc": "I",
    "dec": "I",
    "xchg": "I",
    "cmpxchg": "I",
    "xadd": "I",
}


def _shape(mnemonic: str) -> str:
    if mnemonic.startswith("j"):
        return "J"
    return SHAPE_BY_MNEMONIC.get(mnemonic, "?")


def skeleton(image: KernelImage, rva: int, size: int, limit: int = 96,
             window: int = 0x600) -> Tuple[str, ...]:
    """Operand-shape skeleton over a bounded window.

    The window is deliberately *not* the function size: sweep-derived
    boundaries on the reference firmware are start-to-next-start, so a body
    that is not a call target gets a 32-byte record.  Matching on a fixed
    window makes both sides comparable; the 96-instruction cap keeps a pair
    from being dominated by one long tail.
    """
    require_capstone()
    span = window if size <= 0 else min(size, window)
    if span <= 0:
        return ()
    try:
        ins, _md = image.disasm(rva, span, instructions=False)
    except Exception:
        return ()
    return tuple(_shape(i.mnemonic) for i in ins[:limit])


def skeleton_strict(image: KernelImage, rva: int, size: int, limit: int = 96,
                    window: int = 0x600) -> Tuple[str, ...]:
    """Mnemonic-only skeleton (no operand shapes) -- used as tie-breaker."""
    require_capstone()
    span = window if size <= 0 else min(size, window)
    if span <= 0:
        return ()
    try:
        ins, _md = image.disasm(rva, span, instructions=False)
    except Exception:
        return ()
    return tuple(i.mnemonic for i in ins[:limit])


def _lcs_ratio(a: Sequence, b: Sequence) -> float:
    if not a or not b:
        return 0.0
    # classic DP; sequences are short (<= 96) so this is cheap
    prev = [0] * (len(b) + 1)
    for x in a:
        cur = [0]
        for j, y in enumerate(b, 1):
            cur.append(prev[j - 1] + 1 if x == y else max(prev[j], cur[j - 1]))
        prev = cur
    return prev[-1] / max(len(a), len(b))


@dataclass
class Pair:
    a_rva: int
    a_size: int
    a_name: str
    b_rva: int
    b_size: int
    verdict: str
    ratio: float
    identical_bytes: bool

    def as_dict(self) -> dict:
        return {
            "a": {"rva": hex(self.a_rva), "size": self.a_size, "name": self.a_name},
            "b": {"rva": hex(self.b_rva), "size": self.b_size},
            "verdict": self.verdict,
            "ratio": round(self.ratio, 4),
            "identical_bytes": self.identical_bytes,
        }


class Binder:
    def __init__(self, a_image: KernelImage, a_index: FunctionIndex,
                 b_image: KernelImage, b_index: FunctionIndex, key_len: int = 8):
        self.a_image = a_image
        self.b_image = b_image
        self.a_index = a_index
        self.b_index = b_index
        self.key_len = key_len
        self.last_refusal: Optional[str] = None
        self._b_keys: Dict[Tuple, List[int]] = {}
        self._b_prefix: Dict[Tuple, List[int]] = {}
        self._b_skeletons: Dict[int, Tuple[str, ...]] = {}
        self._b_strict: Dict[int, Tuple[str, ...]] = {}
        for rec in b_index:
            sk = skeleton(b_image, rec.rva, 0)
            if not sk:
                continue
            self._b_skeletons[rec.rva] = sk
            self._b_strict[rec.rva] = skeleton_strict(b_image, rec.rva, 0)
            key = (sk[:key_len], len(sk) // 8)
            self._b_keys.setdefault(key, []).append(rec.rva)
            self._b_prefix.setdefault(sk[:6], []).append(rec.rva)

    def _candidates(self, sk: Tuple[str, ...], a_size: int) -> Tuple[List[int], bool]:
        exact = list(self._b_keys.get((sk[: self.key_len], len(sk) // 8), []))
        if exact:
            return exact, False
        pool = list(self._b_prefix.get(sk[:6], []))
        return pool[:400], True

    def bind(self, a_rva: int, threshold: float = 0.70) -> Optional[Pair]:
        """Bind one function; refuse an ambiguous pair instead of guessing."""
        rec = self.a_index.get(a_rva)
        if rec is None:
            return None
        sk = skeleton(self.a_image, rec.rva, rec.size)
        if not sk:
            return None
        candidates, widened = self._candidates(sk, rec.size)
        scored = []
        for b_rva in candidates:
            b_rec = self.b_index.get(b_rva)
            if b_rec is None:
                continue
            # No size guard: reference-firmware boundaries are sweep-derived and
            # a body that is not a call target can carry a 32-byte record.  The
            # skeleton window plus the ambiguity rule do the filtering instead.
            scored.append((_lcs_ratio(sk, self._b_skeletons[b_rva]), b_rva))
        if not scored:
            return None
        scored.sort(reverse=True)
        best_ratio, best = scored[0]
        if best_ratio < threshold:
            return None
        if len(sk) < 12:
            # a short function needs an exact, unique skeleton
            ties = [b for r, b in scored if r >= 0.999]
            if len(ties) != 1:
                self.last_refusal = "short_ambiguous"
                return None
        else:
            close = [b for r, b in scored if r >= best_ratio - 0.01 and b != best]
            if close and best_ratio < 0.999:
                self.last_refusal = "ambiguous"
                return None
        self.last_refusal = None
        if widened:
            self.last_refusal = "widened_key"
        b_rec = self.b_index.get(best)
        assert b_rec is not None
        a_bytes = self.a_image.read(rec.rva, min(rec.size, 0x800))
        b_bytes = self.b_image.read(b_rec.rva, min(b_rec.size, 0x800))
        identical = a_bytes == b_bytes
        if identical:
            verdict = IDENTICAL
        elif self._b_strict[best] == skeleton_strict(self.a_image, rec.rva, rec.size):
            verdict = SAME_SKELETON
        elif best_ratio >= 0.90:
            verdict = CHANGED
        else:
            verdict = DIVERGENT
        return Pair(
            a_rva=rec.rva,
            a_size=rec.size,
            a_name=rec.name,
            b_rva=b_rec.rva,
            b_size=b_rec.size,
            verdict=verdict,
            ratio=best_ratio,
            identical_bytes=identical,
        )

    def bind_many(self, rvas: Sequence[int], threshold: float = 0.70) -> List[Optional[Pair]]:
        return [self.bind(r, threshold) for r in rvas]

    def bind_injective(self, rvas: Sequence[int], threshold: float = 0.70) -> List[Optional[Pair]]:
        """Greedy injective assignment: one target belongs to one source.

        Without this, two related functions can claim the same counterpart
        (observed: two AIO handlers both binding to one reference function),
        which is a silent false positive that no per-pair threshold catches.
        """
        scored = []
        for a_rva in rvas:
            pair = self.bind(a_rva, threshold)
            if pair is not None:
                scored.append((pair.ratio, a_rva, pair))
        scored.sort(reverse=True, key=lambda t: (t[0], -t[1]))
        used = set()
        out: Dict[int, Optional[Pair]] = {r: None for r in rvas}
        collisions = []
        for ratio, a_rva, pair in scored:
            if pair.b_rva in used:
                collisions.append({"a": hex(a_rva), "b": hex(pair.b_rva)})
                continue
            used.add(pair.b_rva)
            out[a_rva] = pair
        self.collisions = collisions
        return [out[r] for r in rvas]

    def stats(self) -> dict:
        return {
            "a_functions": len(self.a_index),
            "b_functions": len(self.b_index),
            "b_skeletons": len(self._b_skeletons),
            "keys": len(self._b_keys),
        }


def measure_against_sysent(
    a_image: KernelImage,
    a_index: FunctionIndex,
    a_sysent,
    b_image: KernelImage,
    b_index: FunctionIndex,
    b_sysent,
    sample: Sequence[int],
    binder: Optional[Binder] = None,
) -> dict:
    """Measure skeleton-binder accuracy against syscall-number ground truth.

    The syscall number is the one correspondence that cannot be wrong: both
    images declare their own sysent, so ``sysent[n].sy_call`` on each side names
    the same function.  That makes it a free labelled set, and the binder has to
    be scored against it before any of its verdicts are believed.
    """
    from .entries import entry_chain

    if binder is None:
        binder = Binder(a_image, a_index, b_image, b_index)
    correct = wrong = unbound = skipped = 0
    errors = []
    for n in sample:
        ea, eb = a_sysent.get(n), b_sysent.get(n)
        if not (ea and eb and ea.valid and eb.valid):
            skipped += 1
            continue
        chain_a = entry_chain(a_image, ea.handler_rva, index=a_index)
        chain_b = entry_chain(b_image, eb.handler_rva, index=b_index)
        truth = set(chain_b)
        pair = binder.bind(chain_a[0])
        if pair is None:
            unbound += 1
            continue
        if pair.b_rva in truth:
            correct += 1
        else:
            wrong += 1
            errors.append({"syscall": n, "a": hex(chain_a[0]), "bound": hex(pair.b_rva),
                           "truth": [hex(t) for t in chain_b], "ratio": round(pair.ratio, 3)})
    total = correct + wrong + unbound
    return {
        "sample": len(sample),
        "skipped": skipped,
        "evaluated": total,
        "correct": correct,
        "wrong": wrong,
        "unbound": unbound,
        "accuracy": round(correct / total, 4) if total else None,
        "error_rate": round(wrong / total, 4) if total else None,
        "errors": errors[:20],
    }
