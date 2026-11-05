"""Entry-point inventory and reachability.

An exploit needs an *entry*: a code path a non-privileged process can reach.
This module enumerates the two statically provable entry classes in our dumps:

* ``sysent``  -- the syscall table (index -> handler, narg, thrcnt).  The table
  is located through pinned facts, and every handler is validated as a pointer
  into the executable range before it is used, so a wrong table base cannot
  produce a plausible entry list.
* ``cdevsw``  -- the character-device switch table (name, open/close/read/ioctl).
  The device mode (e.g. ``0x1b6`` = 0666) is what decides whether a device node
  is a userland entry at all.

Reachability is a bounded BFS over *direct* calls; indirect dispatch is recorded
as a boundary, never guessed through.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .image import FunctionIndex, KernelImage


@dataclass(frozen=True)
class SyscallEntry:
    number: int
    narg: int
    handler_rva: int
    thrcnt: int
    valid: bool

    def as_dict(self) -> dict:
        return {
            "number": self.number,
            "narg": self.narg,
            "handler_rva": hex(self.handler_rva),
            "thrcnt": self.thrcnt,
            "valid": self.valid,
        }


class SysentTable:
    def __init__(self, image: KernelImage, base_rva: int, stride: int = 48,
                 narg_offset: int = 0, call_offset: int = 8, thrcnt_offset: int = 44,
                 count: int = 700):
        self.image = image
        self.base_rva = base_rva
        self.stride = stride
        self.count = count
        self.entries: List[SyscallEntry] = []
        exec_ranges = image.executable_ranges()
        for n in range(count):
            rva = base_rva + n * stride
            if rva + stride > image.size:
                break
            narg = image.u32(rva + narg_offset)
            handler = image.u64(rva + call_offset)
            thrcnt = image.u32(rva + thrcnt_offset)
            handler_rva = image.rva(handler)
            valid = (
                image.is_canonical_kernel_va(handler)
                and any(lo <= handler_rva < hi for lo, hi in exec_ranges)
            )
            self.entries.append(SyscallEntry(n, narg, handler_rva, thrcnt, valid))

    def valid_entries(self) -> List[SyscallEntry]:
        return [e for e in self.entries if e.valid]

    def get(self, number: int) -> Optional[SyscallEntry]:
        for e in self.entries:
            if e.number == number:
                return e
        return None

    def stats(self) -> dict:
        return {
            "base_rva": hex(self.base_rva),
            "entries": len(self.entries),
            "valid": len(self.valid_entries()),
            "max_valid": max((e.number for e in self.valid_entries()), default=-1),
        }


@dataclass(frozen=True)
class DeviceEntry:
    index: int
    record_rva: int
    name: str
    open_rva: int
    close_rva: int
    read_rva: int
    ioctl_rva: int

    def as_dict(self) -> dict:
        return {
            "index": self.index,
            "record_rva": hex(self.record_rva),
            "name": self.name,
            "open": hex(self.open_rva),
            "close": hex(self.close_rva),
            "read": hex(self.read_rva),
            "ioctl": hex(self.ioctl_rva),
        }


class CdevswTable:
    """Walk ``cdevsw`` records until the name pointer stops looking like a name."""

    def __init__(self, image: KernelImage, base_rva: int, record_size: int = 0x68,
                 max_records: int = 512, fields: Optional[dict] = None, limit_rva: int = 0):
        self.image = image
        self.base_rva = base_rva
        self.devices: List[DeviceEntry] = []
        fields = fields or {"name_ptr": 8, "open": 16, "close": 32, "read": 40, "ioctl": 56}
        for idx in range(max_records):
            rec = base_rva + idx * record_size
            if rec + record_size > image.size or (limit_rva and rec >= limit_rva):
                break
            name_va = image.u64(rec + fields["name_ptr"])
            if not image.is_canonical_kernel_va(name_va):
                break
            name_rva = image.rva(name_va)
            if not (0 <= name_rva < image.size - 32):
                break
            raw = image.read(name_rva, 32)
            name = raw.split(b"\x00")[0]
            if not name or not all(0x20 <= b < 0x7F for b in name):
                break
            self.devices.append(
                DeviceEntry(
                    index=idx,
                    record_rva=rec,
                    name=name.decode("ascii"),
                    open_rva=image.rva(image.u64(rec + fields["open"])),
                    close_rva=image.rva(image.u64(rec + fields["close"])),
                    read_rva=image.rva(image.u64(rec + fields["read"])),
                    ioctl_rva=image.rva(image.u64(rec + fields["ioctl"])),
                )
            )


class EntryIndex:
    """Bounded BFS from each entry handler through direct calls.

    Reachability has to survive three shapes that are common in these dumps and that a
    naive "only known function starts" walk silently drops:

    * **split records** -- the inventory start for a handler can sit *after* the real
      prologue, so the entry rva is not a record start (9.00's netcontrol dispatcher is
      the worked example in the S1.2d evidence pack).  Decoding must start at the entry
      rva and run to the end of the covering record.
    * **tail jumps** -- a thin wrapper forwards into the real implementation with ``jmp``;
      the forwarded-to body is part of the same logical entry.
    * **relative jump tables** -- ``switch (cmd)`` becomes
      ``lea reg,[rip+X]; movsxd r,[base+idx*4]; add; jmp rax``, so the case bodies are
      code the call graph never sees.  They are decoded from the table, not guessed.
    """

    MAX_TAIL_HOPS = 3
    MAX_CONTINUATIONS = 8
    MAX_DECODE = 0x4000

    def __init__(self, image: KernelImage, index: FunctionIndex):
        self.image = image
        self.index = index
        self._callees: Dict[int, Set[int]] = {}
        self._cases: Dict[int, Set[int]] = {}
        self._tail: Dict[int, Set[int]] = {}

    # -- helpers -----------------------------------------------------------------
    def _decode(self, rva: int) -> list:
        """Instructions from ``rva`` to the end of its covering record."""
        rec = self.index.get(rva) or self.index.containing(rva)
        if rec is None:
            return []
        start = rva if self.index.get(rva) is None else rec.rva
        end = rec.rva + max(rec.size, 1)
        span = min(max(end - start, 1), self.MAX_DECODE)
        try:
            ins, _md = self.image.disasm(start, span, instructions=False)
        except Exception:
            return []
        return ins

    @staticmethod
    def _direct_target(op_str: str) -> Optional[int]:
        try:
            return int(op_str, 16)
        except Exception:
            return None

    def tail_targets(self, rva: int) -> Set[int]:
        """``jmp`` targets that leave the covering record (wrapper forwarding)."""
        if rva in self._tail:
            return self._tail[rva]
        rec = self.index.get(rva) or self.index.containing(rva)
        out: Set[int] = set()
        if rec is not None:
            for i in self._decode(rva):
                if i.mnemonic != "jmp":
                    continue
                tgt = self._direct_target(i.op_str)
                if tgt is None:
                    continue
                if not (rec.rva <= tgt < rec.rva + max(rec.size, 1)):
                    out.add(tgt)
        self._tail[rva] = out
        return out

    def jump_table_cases(self, rva: int) -> Set[int]:
        """Case targets of *relative* jump tables inside one function.

        Strict idiom, all four steps required and register-consistent::

            lea   rcx, [rip + disp]        ; table base
            movsxd rax, dword ptr [rcx + rax*4]
            add   rax, rcx                 ; relative entry -> absolute
            jmp   rax

        The entry count comes from the bound check in front of the table load when one
        exists, and every decoded target has to stay inside a function record within the
        same code window.  Anything looser turns ordinary ``lea``/``jmp`` pairs into
        invented case targets.
        """
        if rva in self._cases:
            return self._cases[rva]
        out: Set[int] = set()
        ins = self._decode(rva)
        for n, i in enumerate(ins):
            if i.mnemonic != "lea" or "rip" not in i.op_str:
                continue
            parts = i.op_str.replace(" ", "").split(",")
            if len(parts) != 2:
                continue
            dst = parts[0]
            try:
                disp = int(parts[1].split("+")[1].rstrip("]"), 16)
            except Exception:
                continue
            table_rva = i.address + i.size + disp
            if not (0 <= table_rva < self.image.size):
                continue
            load_reg, add_ok, jmp_ok = None, False, False
            for j in ins[n + 1:n + 9]:
                if j.mnemonic == "movsxd" and f"[{dst}" in j.op_str and "*4" in j.op_str:
                    load_reg = j.op_str.split(",")[0].strip()
                if (j.mnemonic == "add" and load_reg
                        and j.op_str.replace(" ", "") == f"{load_reg},{dst}"):
                    add_ok = True
                if (j.mnemonic == "jmp" and load_reg
                        and j.op_str.strip() == load_reg):
                    jmp_ok = True
            if not (load_reg and add_ok and jmp_ok):
                continue
            count = None
            for j in ins[max(0, n - 12):n]:
                if j.mnemonic != "cmp" or "," not in j.op_str:
                    continue
                tail = j.op_str.split(",")[-1].strip()
                try:
                    count = int(tail, 16) + 1
                except Exception:
                    continue
            if count is None or not (1 <= count <= 512):
                continue
            for k in range(count):
                raw = self.image.u32(table_rva + 4 * k)
                off = raw - (1 << 32) if raw >= (1 << 31) else raw
                tgt = table_rva + off
                rec = self.index.containing(tgt)
                if rec is None or abs(tgt - rva) > 0x8000:
                    break
                out.add(tgt)
        self._cases[rva] = out
        return out

    def callees(self, rva: int) -> Set[int]:
        if rva in self._callees:
            return self._callees[rva]
        out: Set[int] = set()
        for i in self._decode(rva):
            if i.mnemonic != "call":
                continue
            tgt = self._direct_target(i.op_str)
            if tgt is None or tgt <= 0:
                continue
            rec = self.index.containing(tgt)
            if rec is not None:
                out.add(rec.rva)
        self._callees[rva] = out
        return out

    def expand_entry(self, handler_rva: int, cap: int = 4096,
                     barrier_roots: Optional[Set[int]] = None) -> Dict[int, int]:
        """Entry -> {rva: depth} including continuation, tail hops and jump-table cases.

        The inventory can split one logical function into several adjacent records (a
        prologue stub, then the body).  When a record does not end in a terminator, the
        next record *is* the same execution path, so it is followed at the same depth.
        Nothing here is target specific: the three rules are "falls through", "jumps to"
        and "indexed by a relative table".
        """
        out: Dict[int, int] = {}
        barriers = set(barrier_roots or ())
        barriers.discard(handler_rva)
        todo = [(handler_rva, 0, 0, 0)]
        seen_tail = set()
        while todo and len(out) < cap:
            rva, depth, hops, conts = todo.pop(0)
            if rva in out and out[rva] <= depth:
                continue
            out[rva] = depth
            rec = self.index.get(rva) or self.index.containing(rva)
            if rec is not None and conts < self.MAX_CONTINUATIONS:
                ins = self._decode(rva)
                last = ins[-1] if ins else None
                if last is None or last.mnemonic not in ("ret", "jmp", "hlt", "ud2"):
                    nxt = rec.rva + max(rec.size, 1)
                    # Adjacent inventory records are not necessarily fragments of the
                    # same function: syscall handlers are densely packed.  Crossing a
                    # different known entry root makes one syscall appear to own every
                    # later handler in the section.  Stop there; an explicit call/jump
                    # may still reach that entry through the rules below.
                    if nxt not in barriers and self.index.containing(nxt) is not None:
                        todo.append((nxt, depth, hops, conts + 1))
            if hops < self.MAX_TAIL_HOPS and rva not in seen_tail:
                seen_tail.add(rva)
                for t in sorted(self.tail_targets(rva)):
                    rec = self.index.containing(t)
                    if rec is not None:
                        todo.append((rec.rva, depth, hops + 1, 0))
            for case in sorted(self.jump_table_cases(rva)):
                rec = self.index.containing(case)
                if rec is not None:
                    todo.append((rec.rva, depth + 1, hops, 0))
        return out

    def reachable(self, roots: Iterable[int], depth: int = 2, budget: int = 20000) -> Dict[int, int]:
        """rva -> minimum call depth (0 = the entry handler itself)."""
        seen: Dict[int, int] = {}
        frontier = [(r, 0) for r in roots if r > 0]
        while frontier and len(seen) < budget:
            rva, d = frontier.pop(0)
            if rva in seen and seen[rva] <= d:
                continue
            seen[rva] = d
            if d >= depth:
                continue
            for c in sorted(self.callees(rva)):
                if c not in seen:
                    frontier.append((c, d + 1))
        return seen


def dispatch_tables(image: KernelImage, index: FunctionIndex, min_entries: int = 8,
                    max_tables: int = 400, max_entries: int = 96) -> List[dict]:
    """Runs of code pointers in the data segment: candidate indirect dispatch tables.

    A table is a stretch of at least ``min_entries`` consecutive 8-byte slots, every one
    of them a canonical kernel address inside the executable range.  Nothing is assumed
    about what the table dispatches -- the targets are simply extra entry roots, and a
    rule that keys on a table's purpose would be target specific by construction.
    """
    ranges = image.executable_ranges()
    text_lo = min(lo for lo, _hi in ranges)
    text_hi = max(hi for _lo, hi in ranges)
    out: List[dict] = []
    stride = 8
    rva = 0
    size = image.size
    while rva + stride * min_entries <= size and len(out) < max_tables:
        run: List[int] = []
        cur = rva
        while cur + stride <= size and len(run) < max_entries:
            value = image.u64(cur)
            if not image.is_canonical_kernel_va(value):
                break
            target = image.rva(value)
            if not (text_lo <= target < text_hi) or index.containing(target) is None:
                break
            run.append(target)
            cur += stride
        if len(run) >= min_entries:
            out.append({"table_rva": rva, "entries": len(run), "targets": run})
            rva = cur
            continue
        rva += stride
    return out


def load_groups(path: str) -> dict:
    import json

    with open(path, "rt", encoding="utf-8") as fh:
        return json.load(fh)


def entry_chain(image: KernelImage, rva: int, max_hops: int = 3,
                index: Optional[FunctionIndex] = None) -> List[int]:
    """Follow a syscall wrapper to its implementation.

    On 13.52 the sysent handler is usually a *thin* wrapper that loads the
    arguments and then tail-jumps into the real implementation (``sys_662`` =
    12 bytes of argument marshalling, then ``jmp``).  Comparing a wrapper
    against a firmware where the same syscall has no wrapper produces a false
    "UNBOUND", so the chain is resolved explicitly and every hop is reported.

    The window is bounded by the function's own size when an inventory is
    supplied -- disassembling past the end of a 12-byte wrapper walks into the
    neighbouring function and invents a hop.
    """
    chain = [rva]
    cur = rva
    for _ in range(max_hops):
        span = 0x60
        if index is not None:
            rec = index.get(cur)
            if rec is not None and rec.size > 0:
                span = min(rec.size, 0x60)
        try:
            ins, _md = image.disasm(cur, span, instructions=False)
        except Exception:
            return chain
        if not ins:
            return chain
        nxt = None
        for i in ins:
            if i.mnemonic in ("ret", "hlt", "int3"):
                break
            if i.mnemonic == "jmp":
                try:
                    nxt = int(i.op_str, 16)
                except Exception:
                    nxt = None
                break
            if i.mnemonic == "call":
                break
        if nxt is None:
            return chain
        chain.append(nxt)
        cur = nxt
    return chain


def subsystem_map(sysent: SysentTable, groups: dict) -> Dict[int, List[str]]:
    """syscall number -> subsystem tags (from the data-driven group document)."""
    out: Dict[int, List[str]] = {}
    for group, spec in groups.items():
        for n in spec.get("syscalls", []):
            out.setdefault(int(n), []).append(group)
    return out
