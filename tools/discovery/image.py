"""Kernel-image adapter: the only place that knows how a dump is laid out.

Two facts about our dumps are load-bearing and are recorded here once:

1. **Flat RVA convention.**  ``kernel.bin`` is a *reconstructed* ELF
   (interpreter ``/DUMMY``, segment type ``LOOS+0x1000010``) whose program
   headers claim ``p_offset != p_vaddr`` for two segments.  Three independent
   chains prove the flat reading (file offset == RVA): sysent[11] holds the
   public patch triple at RVA ``sysent + 11*0x30``, the ``k_prison0`` slot
   holds the struct address the raw13 table names, and the zone-name buckets
   resolve in order.  :class:`KernelImage` therefore maps RVA 1:1 onto the file
   and derives VAs as ``base + rva`` only for reporting.

2. **Firmware identity, not filename, selects the facts.**  The image hash is
   compared against the pinned facts document; a mismatch is refused, so a
   wrong dump cannot silently produce plausible addresses.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field
from typing import Iterable, Iterator, Optional

try:  # capstone is an analysis dependency of this package only
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
except Exception:  # pragma: no cover - reported by :func:`require_capstone`
    Cs = None  # type: ignore
    CS_ARCH_X86 = CS_MODE_64 = None  # type: ignore
    X86_OP_IMM = X86_OP_MEM = X86_OP_REG = X86_REG_RIP = None  # type: ignore


class ImageError(RuntimeError):
    """The image cannot be used for the requested operation."""


def require_capstone() -> None:
    if Cs is None:
        raise ImageError(
            "capstone is required for disassembly; install it into the repo venv "
            "(`uv pip install capstone`)"
        )


# --------------------------------------------------------------------------- ELF


@dataclass(frozen=True)
class Segment:
    index: int
    p_type: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int
    flags: int
    align: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & 1)


@dataclass
class KernelImage:
    """A read-only view of a PS4 kernel image (flat RVA == file offset)."""

    path: str
    sha256: str
    size: int
    entry: int
    segments: tuple
    base: int
    _data: bytes = field(repr=False, default=b"")

    # -- construction -------------------------------------------------------

    @classmethod
    def load(cls, path: str) -> "KernelImage":
        with open(path, "rb") as fh:
            data = fh.read()
        if data[:4] != b"\x7fELF" or data[4] != 2:
            raise ImageError(f"not an ELF64 image: {path}")
        e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
        e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
        e_phnum = struct.unpack_from("<H", data, 0x38)[0]
        entry = struct.unpack_from("<Q", data, 0x18)[0]
        segs = []
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align = (
                struct.unpack_from("<IIQQQQQQ", data, off)
            )
            segs.append(
                Segment(i, p_type, p_offset, p_vaddr, p_filesz, p_memsz, p_flags, p_align)
            )
        loads = [s for s in segs if s.p_type == 1]
        if not loads:
            raise ImageError("no PT_LOAD segment")
        base = min(s.vaddr for s in loads)
        return cls(
            path=path,
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
            entry=entry,
            segments=tuple(segs),
            base=base,
            _data=data,
        )

    # -- address arithmetic -------------------------------------------------

    def rva(self, va: int) -> int:
        """Virtual address -> RVA (flat)."""
        return va - self.base

    def va(self, rva: int) -> int:
        return self.base + rva

    def executable_ranges(self) -> list:
        return [(s.offset, s.offset + s.filesz) for s in self.segments if s.executable]

    # -- reads --------------------------------------------------------------

    def read(self, rva: int, length: int) -> bytes:
        if rva < 0 or length < 0 or rva + length > self.size:
            raise ImageError(f"read out of image: rva={rva:#x} len={length:#x}")
        return self._data[rva : rva + length]

    def u16(self, rva: int) -> int:
        return struct.unpack("<H", self.read(rva, 2))[0]

    def u32(self, rva: int) -> int:
        return struct.unpack("<I", self.read(rva, 4))[0]

    def u64(self, rva: int) -> int:
        return struct.unpack("<Q", self.read(rva, 8))[0]

    def hexdump(self, rva: int, length: int) -> str:
        return self.read(rva, length).hex()

    def is_canonical_kernel_va(self, value: int) -> bool:
        return 0xFFFF800000000000 <= value <= 0xFFFFFFFFFFFFFFFF

    # -- byte search --------------------------------------------------------

    def find_all(self, needle: bytes, limit: Optional[int] = None) -> list:
        out = []
        start = 0
        while True:
            idx = self._data.find(needle, start)
            if idx < 0:
                return out
            out.append(idx)
            if limit is not None and len(out) >= limit:
                return out
            start = idx + 1

    def find_string(self, text: str, limit: Optional[int] = None) -> list:
        return self.find_all(text.encode() + b"\x00", limit)

    def strings(self, minlen: int = 6, ranges: Optional[Iterable] = None) -> Iterator:
        """Yield (rva, text) for NUL-terminated printable ASCII runs."""
        spans = list(ranges) if ranges is not None else [(0, self.size)]
        for lo, hi in spans:
            blob = self._data[lo:hi]
            cur = bytearray()
            start = 0
            for i, b in enumerate(blob):
                if 0x20 <= b < 0x7F:
                    if not cur:
                        start = lo + i
                    cur.append(b)
                else:
                    if len(cur) >= minlen:
                        yield start, cur.decode("ascii", "replace")
                    cur = bytearray()

    # -- disassembly --------------------------------------------------------

    def disasm(self, rva: int, length: int, instructions: bool = True):
        require_capstone()
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = bool(instructions)
        code = self.read(rva, length)
        return list(md.disasm(code, rva)), md

    def linear_sweep(self, ranges: Optional[Iterable] = None) -> list:
        """Linear-sweep disassembly of the executable ranges.

        Returns instruction records ``(rva, size, mnemonic, op_str, bytes)``.
        Structure recovery deliberately does *not* trust a decoder to find
        function starts; :meth:`function_starts` supplies the anchored set.
        """
        require_capstone()
        out = []
        for lo, hi in ranges if ranges is not None else self.executable_ranges():
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = False
            blob = self.read(lo, hi - lo)
            for ins in md.disasm(blob, lo):
                out.append((ins.address, ins.size, ins.mnemonic, ins.op_str, ins.bytes))
        return out


# ---------------------------------------------------------------- function index


@dataclass(frozen=True)
class FunctionRecord:
    rva: int
    size: int
    name: str = ""
    source: str = "inventory"

    @property
    def named(self) -> bool:
        return bool(self.name) and not self.name.startswith("FUN_")


class FunctionIndex:
    """Function boundaries for one image.

    Two providers, both deterministic:

    * ``from_inventory`` — an external function inventory (Ghidra export) that
      is hash-pinned by its caller; the engine never edits it.
    * ``from_sweep`` — derive starts from direct ``call rel32`` targets plus
      prologue signatures, bounded by the next start.  Used for the reference
      firmware, for which no Ghidra inventory exists.
    """

    PROLOGUES = (
        b"\x55\x48\x89\xe5",  # push rbp; mov rbp, rsp
        b"\x55\x48\x8b\xec",  # push rbp; mov rbp, rsp (alt encoding)
    )

    def __init__(self, records: Iterable):
        recs = sorted(records, key=lambda r: r.rva)
        self.records = tuple(recs)
        self._by_rva = {r.rva: r for r in recs}
        self._starts = [r.rva for r in recs]

    def __len__(self) -> int:
        return len(self.records)

    def __iter__(self):
        return iter(self.records)

    def get(self, rva: int) -> Optional[FunctionRecord]:
        return self._by_rva.get(rva)

    def containing(self, rva: int) -> Optional[FunctionRecord]:
        lo, hi = 0, len(self._starts) - 1
        found = None
        while lo <= hi:
            mid = (lo + hi) // 2
            if self._starts[mid] <= rva:
                found = self.records[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        if found is None:
            return None
        return found if rva < found.rva + max(found.size, 1) else None

    def named(self) -> list:
        return [r for r in self.records if r.named]

    def by_name(self, name: str) -> Optional[FunctionRecord]:
        for r in self.records:
            if r.name == name:
                return r
        return None

    @classmethod
    def from_inventory(cls, doc) -> "FunctionIndex":
        """Read a ``{"base": int, "functions": [{addr|va, size, name}]}`` document."""
        base = int(doc["base"])
        recs = []
        for item in doc["functions"]:
            if "rva" in item:
                rva = int(item["rva"])
            else:
                rva = int(item.get("va", int(str(item["addr"]), 16) if "addr" in item else 0)) - base
            recs.append(
                FunctionRecord(rva=rva, size=int(item["size"]), name=item.get("name", ""))
            )
        return cls(recs)

    @classmethod
    def from_sweep(cls, image: KernelImage, min_size: int = 4) -> "FunctionIndex":
        """Derive function starts from call targets + prologues (no inventory).

        Deliberately conservative: a start must be either the target of a
        direct ``call rel32``/``jmp rel32`` inside the executable ranges or a
        known prologue.  Boundaries are the next start; the last start runs to
        the end of its executable range.
        """
        require_capstone()
        starts = set()
        for lo, hi in image.executable_ranges():
            starts.update(image.find_all(b"\x55\x48\x89\xe5"))
            blob = image.read(lo, hi - lo)
            for i in range(len(blob) - 5):
                op = blob[i]
                if op not in (0xE8, 0xE9):
                    continue
                rel = struct.unpack_from("<i", blob, i + 1)[0]
                tgt = lo + i + 5 + rel
                if lo <= tgt < hi:
                    starts.add(tgt)
            starts.add(lo)
        ordered = sorted(starts)
        recs = []
        for idx, start in enumerate(ordered):
            nxt = ordered[idx + 1] if idx + 1 < len(ordered) else None
            if nxt is None:
                size = 0x40
            else:
                size = nxt - start
            if size < min_size:
                continue
            recs.append(FunctionRecord(rva=start, size=size, source="sweep"))
        return cls(recs)


# ---------------------------------------------------------------- facts binding


@dataclass
class FirmwareFacts:
    """Pinned per-firmware facts (identity + table locations)."""

    doc: dict

    @property
    def name(self) -> str:
        return self.doc["firmware"]

    @property
    def sha256(self) -> str:
        return self.doc["image"]["sha256"]

    @property
    def base(self) -> int:
        return int(self.doc["image"]["base"], 16)

    def rva(self, key: str) -> int:
        return int(self.doc["tables"][key]["rva"], 16)

    def table(self, key: str) -> dict:
        return self.doc["tables"][key]

    @classmethod
    def load(cls, path: str) -> "FirmwareFacts":
        with open(path, "rt", encoding="utf-8") as fh:
            return cls(json.load(fh))


def bind(image: KernelImage, facts: FirmwareFacts, strict: bool = True) -> KernelImage:
    """Refuse an image whose hash does not match the pinned facts."""
    if strict and image.sha256 != facts.sha256:
        raise ImageError(
            f"image identity mismatch: facts {facts.sha256[:16]} != image {image.sha256[:16]}"
        )
    return image
