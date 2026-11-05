"""Ownership catalog: which calls release, which allocate.

D1 must never decide "this was freed" from a function *name*.  Names are not
available in the reference firmware at all (its index is a byte sweep), so a
name-based release set silently turns into a different rule per firmware -- the
same finding would mean two different things on two images.

This module therefore separates the two things a name was doing:

* **roots are data.**  A small, hash-pinned set of RVAs per firmware with a
  written provenance (inventory name, cross-firmware twin match, call-site
  shape).  Data may be wrong; it is reviewable and it is not a classifier.
* **everything else is structural.**  From those roots the catalog grows through
  call shape only: a thunk that jumps to a release, or a wrapper that forwards
  its *own* pointer argument unchanged into a release.  Each entry keeps the
  chain that produced it, so a reviewer can re-walk it.

The catalog is deliberately conservative in one direction: a call whose callee is
*not* in the catalog is an unknown side effect.  It is never treated as "does not
free" -- the lifecycle analysis turns it into an UNKNOWN object state instead of
a clean one.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .image import FunctionIndex, KernelImage, require_capstone

try:  # pragma: no cover - guarded
    from capstone.x86 import X86_OP_IMM
except Exception:  # pragma: no cover
    X86_OP_IMM = -1

# argument registers in System V order; only the first is followed
ARG0 = "rdi"

#: 32/16/8-bit aliases of the 64-bit registers we reason about
_SUBREG = {
    "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
    "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
    "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
    "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
    "esi": "rsi", "si": "rsi", "sil": "rsi",
    "edi": "rdi", "di": "rdi", "dil": "rdi",
    "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
    "esp": "rsp", "sp": "rsp", "spl": "rsp",
}
for _n in range(8, 16):
    for _suffix, _width in (("d", 32), ("w", 16), ("b", 8)):
        _SUBREG[f"r{_n}{_suffix}"] = f"r{_n}"


def canon_reg(name: str) -> str:
    """``edi`` and ``rdi`` are the same register; a write to either kills it."""
    return _SUBREG.get(name, name)

ROLE_FREE = "free"
ROLE_REFCOUNT_RELEASE = "refcount_release"
ROLE_ALLOC = "alloc"

ANCHOR_ROLES = {
    "free": ROLE_FREE,
    "fdrop_release": ROLE_REFCOUNT_RELEASE,
    "malloc": ROLE_ALLOC,
}

MAX_ROUNDS = 3
MAX_CHAIN = 3


@dataclass(frozen=True)
class OwnershipEntry:
    rva: int
    role: str
    source: str          # data_anchor | thunk | forward_call | forward_tail
    chain: Tuple[int, ...] = ()
    evidence: str = ""
    conditional: bool = False   # the release runs on some path, not all

    def as_dict(self) -> dict:
        return {
            "rva": hex(self.rva),
            "role": self.role,
            "source": self.source,
            "chain": [hex(c) for c in self.chain],
            "evidence": self.evidence,
            "conditional": self.conditional,
        }


def call_sites(image: KernelImage, wanted: Iterable[int]) -> Dict[int, List[int]]:
    """target rva -> sorted call/jmp sites (direct rel32 only, chunked scan)."""
    from .index_audit import rel32_sites

    target_set = set(wanted)
    out: Dict[int, List[int]] = {}
    for site, tgt in rel32_sites(image):
        if tgt in target_set:
            out.setdefault(tgt, []).append(site)
    for sites in out.values():
        sites.sort()
    return out


def _arg_setup_before(ins: Sequence, idx: int, reg: str = ARG0) -> Tuple[bool, int]:
    """Is ``reg`` written in the window before ``ins[idx]`` without reloading?

    Returns ``(written, site)`` for the *last* write to ``reg`` at or before the
    call.  ``written=False`` means the register still carries its incoming value.
    """
    for k in range(idx - 1, max(-1, idx - 12), -1):
        ins_k = ins[k]
        ops = ins_k.operands
        if not ops:
            continue
        if _is_reg(ins_k, ops[0], reg):
            return True, ins_k.address
        if ins_k.mnemonic == "call" and _is_caller_saved(ins_k, reg):
            return True, ins_k.address
    return False, -1


def _is_reg(ins, op, name: str) -> bool:
    try:
        from capstone.x86 import X86_OP_REG
    except Exception:  # pragma: no cover
        return False
    return op.type == X86_OP_REG and canon_reg(ins.reg_name(op.reg)) == canon_reg(name)


def _is_caller_saved(ins, name: str) -> bool:
    return name in ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11")


class OwnershipCatalog:
    """Per-image release/alloc set with propagation provenance."""

    def __init__(self, image: KernelImage, index: FunctionIndex,
                 facts_doc: dict, extra_roots: Optional[dict] = None):
        require_capstone()
        self.image = image
        self.index = index
        self.entries: Dict[int, OwnershipEntry] = {}
        self.rounds: List[dict] = []
        self._seed(facts_doc, extra_roots or {})
        self._propagate()
        self._name_agreement = self._measure_name_agreement()

    # -- construction -------------------------------------------------------
    def _seed(self, facts_doc: dict, extra: dict) -> None:
        anchors = facts_doc.get("anchors") or {}
        prov = facts_doc.get("anchor_provenance") or {}
        for key, role in ANCHOR_ROLES.items():
            raw = anchors.get(key)
            if not raw:
                continue
            self.entries[int(raw, 16)] = OwnershipEntry(
                rva=int(raw, 16), role=role, source="data_anchor",
                evidence=prov.get(key, "anchor without recorded provenance"),
            )
        for raw, spec in (extra or {}).items():
            rva = int(raw, 16) if isinstance(raw, str) else int(raw)
            self.entries[rva] = OwnershipEntry(
                rva=rva, role=spec["role"], source="data_anchor",
                evidence=spec.get("evidence", "extra root"),
            )

    def _propagate(self) -> None:
        """Grow the catalog through thunk and argument-forwarding shape only."""
        for rnd in range(MAX_ROUNDS):
            known = {rva: e for rva, e in self.entries.items()}
            added = self._add_thunks(known)
            sites = call_sites(self.image, known)
            if not sites:
                self.rounds.append({"round": rnd, "added": added, "total": len(self.entries)})
                if not added:
                    break
                continue
            for target, site_list in sorted(sites.items()):
                entry = known[target]
                for site in site_list:
                    owner = self.index.containing(site)
                    if owner is None or owner.rva in self.entries:
                        continue
                    if site - owner.rva > 0x4000:
                        continue
                    verdict = self._forward_shape(owner, site, entry)
                    if verdict is None:
                        continue
                    source, chain = verdict
                    conditional = entry.conditional or not self._unconditional(owner, site)
                    self.entries[owner.rva] = OwnershipEntry(
                        rva=owner.rva, role=entry.role, source=source,
                        chain=(site,) + entry.chain,
                        evidence=f"{source} of {entry.role} at {target:#x} via {site:#x}",
                        conditional=conditional,
                    )
                    added += 1
            self.rounds.append({"round": rnd, "added": added, "total": len(self.entries)})
            if not added:
                break

    def _add_thunks(self, known: Dict[int, "OwnershipEntry"]) -> int:
        """A jump to a release *is* a release: decode the small records' first insn.

        Short ``jmp rel8`` thunks are two bytes and invisible to a ``rel32`` scan,
        so they are found from the index side instead: only records small enough
        to *be* a thunk are decoded.
        """
        added = 0
        for rec in self.index:
            if rec.rva in self.entries or not (0 < rec.size <= 0x20):
                continue
            try:
                ins, _md = self.image.disasm(rec.rva, min(rec.size, 8))
            except Exception:
                continue
            if not ins or ins[0].mnemonic != "jmp":
                continue
            target = None
            for op in ins[0].operands:
                if op.type == X86_OP_IMM:
                    target = int(op.imm)
            if target is None or target == rec.rva:
                continue
            callee = self.entries.get(target)
            if callee is None:
                continue
            self.entries[rec.rva] = OwnershipEntry(
                rva=rec.rva, role=callee.role, source="thunk",
                chain=(rec.rva,) + callee.chain,
                evidence=f"thunk of {callee.role} at {target:#x}",
                conditional=callee.conditional,
            )
            added += 1
        return added

    def _unconditional(self, owner, site: int) -> bool:
        """Does the release run on every path through ``owner``?

        A wrapper that frees only inside an ``if`` is not a release: a caller
        that keeps using the object afterwards is not necessarily wrong.  The
        cheapest sound-ish check is the shape before the call -- a conditional
        branch or an earlier exit makes the wrapper conditional.
        """
        if site <= owner.rva:
            return False
        span = min(site - owner.rva + 6, 0x4000)
        try:
            ins, _md = self.image.disasm(owner.rva, span)
        except Exception:
            return False
        for i in ins:
            if i.address >= site:
                break
            if i.mnemonic in ("ret", "hlt", "ud2", "jmp"):
                return False
            if i.mnemonic.startswith("j"):
                return False
            if i.mnemonic in ("call",):
                # an earlier call may throw/return early; treat as conditional
                return False
        return True

    def _forward_shape(self, owner, site: int, entry: OwnershipEntry) -> Optional[Tuple[str, Tuple[int, ...]]]:
        """Decide whether ``owner`` forwards its own argument into ``entry``."""
        size = min(max(owner.size, 0), 0x4000)
        if size <= 0:
            return None
        try:
            ins, _md = self.image.disasm(site - min(site - owner.rva, 0x80), min(0x100, size))
        except Exception:
            return None
        # locate the call/jmp instruction inside the decoded window
        idx = None
        for k, i in enumerate(ins):
            if i.address == site:
                idx = k
                break
        if idx is None:
            return None
        # a thunk is the degenerate forward: the first instruction jumps to it
        first = ins[0]
        if first.mnemonic == "jmp" and first.address == site and owner.size <= 0x20:
            return "thunk", ()
        written, write_site = _arg_setup_before(ins, idx, ARG0)
        if written:
            # ``mov rdi, <reg>`` where <reg> was copied from rdi earlier is still
            # a forward, but only the direct copy-at-entry form is accepted here:
            # anything else is an unknown alias and must stay out of the catalog.
            return None
        source = "forward_tail" if ins[idx].mnemonic == "jmp" else "forward_call"
        if ins[idx].mnemonic not in ("call", "jmp"):
            return None
        return source, ()

    # -- queries ------------------------------------------------------------
    def role_at(self, rva: int) -> Optional[str]:
        entry = self.entries.get(rva)
        return entry.role if entry else None

    def is_release(self, rva: int) -> bool:
        return self.role_at(rva) in (ROLE_FREE, ROLE_REFCOUNT_RELEASE)

    def release_semantics(self, rva: int) -> str:
        """``free`` invalidates its argument, ``refcount_release`` may."""
        entry = self.entries.get(rva)
        if entry is None:
            return "none"
        if entry.conditional:
            return "conditional"
        role = entry.role
        if role == ROLE_FREE:
            return "definite"
        if role == ROLE_REFCOUNT_RELEASE:
            return "conditional"
        return "none"

    def is_alloc(self, rva: int) -> bool:
        return self.role_at(rva) == ROLE_ALLOC

    def by_role(self, role: str) -> List[int]:
        return sorted(e.rva for e in self.entries.values() if e.role == role)

    # -- validation only ----------------------------------------------------
    def _measure_name_agreement(self) -> dict:
        """Compare the structural set against names -- measurement, not input.

        The old detector classified releases by name hint.  This reports both
        directions so the difference is auditable instead of invisible.
        """
        from .patterns import RELEASE_NAME_HINTS

        structural = set(self.by_role(ROLE_FREE)) | set(self.by_role(ROLE_REFCOUNT_RELEASE))
        name_hinted: Set[int] = set()
        named_total = 0
        for rec in self.index.named():
            named_total += 1
            low = (rec.name or "").lower()
            if any(h in low for h in RELEASE_NAME_HINTS):
                name_hinted.add(rec.rva)
        agree = structural & name_hinted
        structural_only = structural - name_hinted
        name_only = name_hinted - structural

        def _name(rva: int) -> str:
            rec = self.index.get(rva)
            return rec.name if rec is not None else ""

        return {
            "named_records": named_total,
            "structural_release_sites": len(structural),
            "name_hinted_sites": len(name_hinted),
            "agreement": len(agree),
            "structural_only": len(structural_only),
            "name_only": len(name_only),
            "structural_only_examples": [
                {"rva": hex(r), "source": self.entries[r].source, "name": _name(r)}
                for r in sorted(structural_only)[:8]
            ],
            "name_only_examples": [
                f"{_name(r)}@{r:#x}" for r in sorted(name_only)[:8]
            ],
        }

    def stats(self) -> dict:
        roles: Dict[str, int] = {}
        sources: Dict[str, int] = {}
        for entry in self.entries.values():
            roles[entry.role] = roles.get(entry.role, 0) + 1
            sources[entry.source] = sources.get(entry.source, 0) + 1
        return {
            "entries": len(self.entries),
            "by_role": roles,
            "by_source": sources,
            "rounds": self.rounds,
            "name_agreement": self._name_agreement,
        }

    def as_dict(self) -> dict:
        return {
            "stats": self.stats(),
            "entries": [e.as_dict() for _, e in sorted(self.entries.items())],
        }
