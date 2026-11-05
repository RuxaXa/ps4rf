"""Versioned value/memory domain for ownership analysis.

The two defects this module exists for are both identity defects:

* a *stack slot* is reused, so "the pointer in ``[rbp-0x20]``" is not one object
  over the lifetime of a function;
* two *table slots* can be reached through different index expressions, so
  "``[rbx+rcx*8]``" and "``[rbx+rdx*8]``" are not one slot unless the indices are
  provably equal.

Both are handled by making identity explicit rather than address-shaped:

* a **cell** is a canonical address expression (``Addr``) plus a **version** that
  increments on every store to it.  A read yields what the cell holds *now*,
  never what an earlier version held.
* a **value** is one of ``Ptr(obj)`` (a pointer to a tracked object), ``Addr``
  (an address expression, e.g. a frame slot), ``Const`` or ``Unknown``.  A
  register holds a *set* of possible values (may-analysis); a single-element set
  is a must fact.
* an **object** is ``Obj(kind, key)`` where the key is a call site (``ret@``,
  ``alloc@``), an argument index, or a frame slot *at one version*.  Object
  identity is therefore independent of the register or slot that carries it, and
  independent of its address.

Affine arithmetic over *symbols* is what makes index equality decidable without
solving: ``rax*8``, ``lea rdx, [rax*8]`` and ``rax<<3`` all canonicalise to the
same expression, and a symbol is derived from a cell *and its version* so that a
store between two reads makes the two indices different (``MAY_ALIAS``), not
equal.

``Unknown`` is a first-class value, never a wildcard: it never makes two things
equal, and a use whose carrier is Unknown is reported as an unknown relation, not
as a safe one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

MAX_TERMS = 8

#: a cell that receives more writes than this is widened to ``CELL_TOP``.  The
#: cap is what makes the fixpoint converge: once a cell is top, further stores
#: keep it top instead of minting a new identity per loop iteration.
MAX_CELL_VERSION = 4

#: A cell whose value set grows past this is collapsed to ``CELL_TOP``.  Without the
#: cap the value sets -- which can themselves contain cell symbols of other cells --
#: grow without bound and the fixpoint never finishes.
MAX_CELL_VALUES = 6

#: How many objects a state tracks as "an unknown call may have freed this" before
#: the bookkeeping is summarised.  It is evidence, not a verdict, so summarising it
#: is safe -- and keeping every object would keep the fixpoint moving.
MAX_TAINT_OBJECTS = 24

#: cell states.  They must never collapse into each other:
#: ``NEVER_WRITTEN`` is "the function has not stored here" (a stable slot
#: identity -- the D4 relation), ``EXACT`` is "content written, at version v",
#: ``APPROX`` is "merged, the value may differ from either arm", ``TOP`` is
#: "content lost; a read carries no identity at all".
CELL_NEVER_WRITTEN = "never_written"
CELL_EXACT = "exact"
CELL_APPROX = "approx"
CELL_TOP = "top"


# --------------------------------------------------------------------- affine


@dataclass(frozen=True, order=True)
class Affine:
    """Integer affine expression over named symbols, canonical form."""

    terms: Tuple[Tuple[str, int], ...] = ()
    const: int = 0

    def __post_init__(self):
        # canonicalise: drop zero coefficients, merge, sort, fold the constant
        merged: Dict[str, int] = {}
        for name, coef in self.terms:
            if coef:
                merged[name] = merged.get(name, 0) + coef
        clean = tuple(sorted((n, c) for n, c in merged.items() if c))
        if len(clean) > MAX_TERMS:
            raise ValueError("affine expression too wide")
        object.__setattr__(self, "terms", clean)

    # -- constructors -------------------------------------------------------
    @classmethod
    def sym(cls, name: str, coef: int = 1) -> "Affine":
        return cls(((name, coef),), 0)

    @classmethod
    def of(cls, const: int) -> "Affine":
        return cls((), int(const))

    # -- arithmetic ---------------------------------------------------------
    def add(self, other: "Affine") -> "Affine":
        return Affine(self.terms + other.terms, self.const + other.const)

    def sub(self, other: "Affine") -> "Affine":
        return Affine(self.terms + tuple((n, -c) for n, c in other.terms), self.const - other.const)

    def scale(self, k: int) -> "Affine":
        return Affine(tuple((n, c * k) for n, c in self.terms), self.const * k)

    # -- questions ----------------------------------------------------------
    def is_const(self) -> bool:
        return not self.terms

    def symbols(self) -> Tuple[str, ...]:
        return tuple(n for n, _ in self.terms)

    def describe(self) -> str:
        if self.is_const():
            return f"{self.const:#x}" if self.const else "0"
        parts = []
        for name, coef in self.terms:
            parts.append(name if coef == 1 else f"{name}*{coef}")
        text = "+".join(parts)
        if self.const:
            text += f"{self.const:+#x}"
        return text


# ----------------------------------------------------------------------- addrs


@dataclass(frozen=True, order=True)
class Addr:
    """A canonical memory address expression.

    ``base`` names the containing object/space (``frame:rbp``, ``global``,
    ``obj:@ret0x1000``, ``arg:0`` ...).  ``aff`` carries the displacement and,
    for indexed forms, the index symbols times their scale.
    """

    base: str
    aff: Affine = Affine((), 0)

    def key(self) -> str:
        return f"{self.base}[{self.aff.describe()}]"

    def is_indexed(self) -> bool:
        return bool(self.aff.terms)

    def offset(self) -> Optional[int]:
        return self.aff.const if self.aff.is_const() else None

    def with_add(self, extra: Affine) -> "Addr":
        return Addr(self.base, self.aff.add(extra))


def _frame_base(name: str) -> str:
    return f"frame:{name}"


# ---------------------------------------------------------------------- values


@dataclass(frozen=True, order=True)
class Obj:
    """A tracked object: ``kind`` says how it came to exist, ``key`` identifies it."""

    kind: str  # ret | alloc | arg | frame | global | slot
    key: str

    def describe(self) -> str:
        return f"{self.kind}:{self.key}"


@dataclass(frozen=True, order=True)
class Ptr:
    obj: Obj

    def describe(self) -> str:
        return self.obj.describe()


@dataclass(frozen=True, order=True)
class Const:
    value: int

    def describe(self) -> str:
        return f"#{self.value:#x}"


@dataclass(frozen=True, order=True)
class Unknown:
    """A value with no provable provenance.  Never equal to anything else."""

    reason: str

    def describe(self) -> str:
        return f"unknown({self.reason})"


Value = object  # union of Ptr | Addr | Const | Unknown


def describe_values(values: Iterable[Value]) -> str:
    return "|".join(sorted(_vkey(v) for v in values))


def _vkey(value: Value) -> str:
    if isinstance(value, Ptr):
        return value.describe()
    if isinstance(value, Addr):
        return value.key()
    if isinstance(value, Const):
        return value.describe()
    if isinstance(value, Unknown):
        return value.describe()
    return repr(value)


# ----------------------------------------------------------------------- cells


@dataclass(frozen=True)
class Cell:
    """Content of one address expression, with an explicit lattice state."""

    version: int
    values: FrozenSet[Value]
    approx: bool = False          # kept for readers; derivable from ``state``
    state: str = CELL_EXACT

    def describe(self) -> str:
        mark = {CELL_EXACT: "", CELL_APPROX: "?", CELL_TOP: "!"}.get(self.state, "?")
        return f"v{self.version}{mark}:{describe_values(self.values)}"

    def carries_identity(self) -> bool:
        """May a read of this cell name an object at all?"""
        return self.state in (CELL_EXACT, CELL_APPROX, CELL_NEVER_WRITTEN)


class Memory:
    """Sparse versioned memory: address expression -> Cell.

    ``lost`` names the address *spaces* whose cells were dropped by widening.
    A read there yields no identity (``Unknown``); it must never fall back to the
    never-written identity, which would forge a slot relation that was lost.
    """

    __slots__ = ("cells", "lost")

    def __init__(self, cells: Optional[Dict[Addr, Cell]] = None,
                 lost: FrozenSet[str] = frozenset()):
        self.cells: Dict[Addr, Cell] = dict(cells or {})
        self.lost: FrozenSet[str] = lost

    # -- reads --------------------------------------------------------------
    def load(self, addr: Addr) -> FrozenSet[Value]:
        cell = self.cells.get(addr)
        if cell is not None:
            return cell.values
        if self.is_lost(addr):
            return frozenset({Unknown(f"lost:{addr.key()}")})
        return frozenset({Unknown(f"unwritten:{addr.key()}")})

    def is_lost(self, addr: Addr) -> bool:
        return addr.base in self.lost

    def state_of(self, addr: Addr) -> str:
        cell = self.cells.get(addr)
        return cell.state if cell is not None else CELL_NEVER_WRITTEN

    def version(self, addr: Addr) -> int:
        cell = self.cells.get(addr)
        return cell.version if cell is not None else -1

    # -- writes -------------------------------------------------------------
    def _top(self, addr: Addr, version: int) -> Cell:
        return Cell(version, frozenset({Unknown(f"top:{addr.key()}")}), True, CELL_TOP)

    def store(self, addr: Addr, values: FrozenSet[Value]) -> int:
        old = self.cells.get(addr)
        if old is None:
            if len(values) > MAX_CELL_VALUES:
                self.cells[addr] = self._top(addr, 0)
                return 0
            self.cells[addr] = Cell(0, values, len(values) > 1, CELL_EXACT)
            return 0
        if old.state == CELL_TOP:
            # top is absorbing *and* saturated: keeping a growing union of values
            # would keep the fixpoint moving for ever, and nothing reads those
            # values anyway (a read of a top cell is Unknown)
            self.cells[addr] = Cell(old.version, frozenset({Unknown(f"top:{addr.key()}")}),
                                    True, CELL_TOP)
            return old.version
        if len(values) > MAX_CELL_VALUES:
            self.cells[addr] = self._top(addr, old.version)
            return old.version
        version = old.version + 1
        if version > MAX_CELL_VERSION:
            # widening point: further writes cannot be told apart, so the cell
            # becomes top instead of minting a new identity for every iteration.
            # The value set is collapsed too: a growing union never converges.
            self.cells[addr] = Cell(old.version, frozenset({Unknown(f"top:{addr.key()}")}),
                                    True, CELL_TOP)
            return old.version
        self.cells[addr] = Cell(version, values, False, CELL_EXACT)
        return version

    # -- merge --------------------------------------------------------------
    def merge(self, other: "Memory") -> "Memory":
        out: Dict[Addr, Cell] = {}
        # sorted, not set order: the merged dict order feeds every later walk, and
        # a hash-seed-dependent order makes the event counters differ between runs
        for addr in sorted(set(self.cells) | set(other.cells), key=lambda a: a.key()):
            a = self.cells.get(addr)
            b = other.cells.get(addr)
            if a is None or b is None:
                got = a or b
                assert got is not None
                # written on one arm only: the other arm kept its previous value,
                # so the content is approximate -- but it is not lost
                state = CELL_TOP if got.state == CELL_TOP else CELL_APPROX
                out[addr] = Cell(got.version, got.values, True, state)
                continue
            if a.state == CELL_TOP or b.state == CELL_TOP:
                out[addr] = Cell(min(a.version, b.version), a.values | b.values,
                                 True, CELL_TOP)
                continue
            if a.version == b.version and a.values == b.values and not (a.approx or b.approx):
                out[addr] = a
                continue
            if a.values == b.values:
                # the value agrees on both arms, so it is a must fact; only the
                # write count differs, which makes the version useless as a kill
                # witness but must not throw the value away
                out[addr] = Cell(max(a.version, b.version), a.values, True, CELL_APPROX)
                continue
            values = a.values | b.values
            if len(values) > MAX_CELL_VALUES:
                out[addr] = Cell(max(a.version, b.version),
                                 frozenset({Unknown(f"top:{addr.key()}")}), True, CELL_TOP)
            else:
                out[addr] = Cell(max(a.version, b.version), values, True, CELL_APPROX)
        return Memory(out, self.lost | other.lost)

    def copy(self) -> "Memory":
        return Memory(self.cells, self.lost)

    def mark_lost(self, base: str) -> None:
        self.lost = self.lost | {base}


# ---------------------------------------------------------------- register file


class RegState:
    """Per-program-point abstract state: registers, memory, object states."""

    __slots__ = ("regs", "mem", "released_must", "released_may", "release_sites",
                 "unknown_effect", "timeline", "origins", "uncertain", "definite_sites",
                 "may_sites", "release_facts", "taint_sites", "alloc_gen", "ret_gen")

    def __init__(self, regs: Optional[Dict[str, FrozenSet[Value]]] = None,
                 mem: Optional[Memory] = None,
                 released_must: FrozenSet[Obj] = frozenset(),
                 released_may: FrozenSet[Obj] = frozenset(),
                 release_sites: Optional[Dict[Obj, Tuple[int, ...]]] = None,
                 unknown_effect: Tuple[int, ...] = (),
                 timeline: Tuple[Tuple[int, str, str], ...] = (),
                 origins: Optional[Dict[str, int]] = None,
                 uncertain: FrozenSet[Obj] = frozenset(),
                 definite_sites: Optional[Dict[Obj, Tuple[int, ...]]] = None,
                 may_sites: Optional[Dict[Obj, Tuple[int, ...]]] = None,
                 release_facts: Optional[Dict[Obj, Tuple[Tuple[int, str, str], ...]]] = None,
                 taint_sites: Optional[Dict[Obj, Tuple[int, ...]]] = None,
                 alloc_gen: Optional[Dict[int, int]] = None,
                 ret_gen: Optional[Dict[int, int]] = None):
        self.regs = dict(regs or {})
        self.mem = mem if mem is not None else Memory()
        self.released_must = released_must
        self.released_may = released_may
        self.release_sites = dict(release_sites or {})
        self.unknown_effect = unknown_effect  # call sites whose effect is unknown
        self.timeline = timeline              # (site, event, detail) in execution order
        self.origins = dict(origins or {})    # reg -> site that defined its value
        self.uncertain = uncertain            # objects an unknown call *may* have freed
        self.definite_sites = dict(definite_sites or {})  # obj -> proven free sites
        self.may_sites = dict(may_sites or {})            # obj -> may-release sites
        self.release_facts = dict(release_facts or {})    # obj -> ((site, kind, pre), ...)
        self.taint_sites = dict(taint_sites or {})        # obj -> unknown-call sites
        self.alloc_gen = dict(alloc_gen or {})   # alloc site -> generation (0 = too many)
        self.ret_gen = dict(ret_gen or {})       # call site -> return generation

    # -- registers ----------------------------------------------------------
    def get(self, reg: str) -> FrozenSet[Value]:
        return self.regs.get(reg, frozenset({Unknown(f"uninit:{reg}")}))

    def must_get(self, reg: str) -> Optional[Value]:
        vals = self.get(reg)
        return next(iter(vals)) if len(vals) == 1 else None

    def set(self, reg: str, values: FrozenSet[Value]) -> None:
        self.regs[reg] = values

    def clobber(self, regs: Iterable[str], reason: str) -> None:
        val = frozenset({Unknown(reason)})
        for reg in regs:
            self.regs[reg] = val

    # -- objects ------------------------------------------------------------
    def mark_released(self, obj: Obj, site: int, definite: bool,
                      semantics: str = "free", precondition: str = "") -> None:
        sites = tuple(sorted(set(self.release_sites.get(obj, ())) | {site}))
        self.release_sites[obj] = sites
        self._note_fact(obj, site, semantics if definite else semantics, precondition)
        if definite:
            self.released_must = self.released_must | {obj}
            self.definite_sites[obj] = tuple(
                sorted(set(self.definite_sites.get(obj, ())) | {site}))
        else:
            self.may_sites[obj] = tuple(sorted(set(self.may_sites.get(obj, ())) | {site}))
        self.released_may = self.released_may | {obj}

    def mark_may_released(self, obj: Obj, site: int, semantics: str,
                          precondition: str) -> None:
        """A release the analysis cannot prove: must never confirm a defect."""
        self.mark_released(obj, site, definite=False, semantics=semantics,
                           precondition=precondition)

    def mark_uncertain(self, obj: Obj, site: int) -> None:
        """An unknown call *may* have freed this object; not a proven release.

        Taint is kept apart from release sites: an unknown call is not a release,
        and naming it as one is what made evidence unauditable.
        """
        self.uncertain = self.uncertain | {obj}
        if len(self.taint_sites) >= MAX_TAINT_OBJECTS and obj not in self.taint_sites:
            self.taint_sites[Obj("taint", "overflow")] = (site,)
            return
        self.taint_sites[obj] = tuple(sorted(set(self.taint_sites.get(obj, ())) | {site}))

    def _note_fact(self, obj: Obj, site: int, kind: str, precondition: str) -> None:
        facts = tuple(sorted(set(self.release_facts.get(obj, ())) |
                             {(site, kind, precondition)}))
        self.release_facts[obj] = facts

    def release_kind(self, obj: Obj, site: Optional[int] = None) -> str:
        """The structured release kind for ``obj`` (optionally at ``site``)."""
        facts = self.release_facts.get(obj, ())
        if not facts:
            return "unknown"
        if site is not None:
            for fact_site, kind, _pre in facts:
                if fact_site == site:
                    return kind
        return facts[-1][1]

    def release_precondition(self, obj: Obj, site: Optional[int] = None) -> str:
        facts = self.release_facts.get(obj, ())
        if not facts:
            return ""
        if site is not None:
            for fact_site, _kind, pre in facts:
                if fact_site == site:
                    return pre
        return facts[-1][2]

    def object_state(self, obj: Obj) -> str:
        if obj in self.released_must:
            return "RELEASED"
        if obj in self.released_may:
            return "MAY_RELEASED"
        return "LIVE"

    # -- timeline -----------------------------------------------------------
    def note(self, site: int, event: str, detail: str) -> None:
        if len(self.timeline) < 4096:
            self.timeline = self.timeline + ((site, event, detail),)

    # -- merge --------------------------------------------------------------
    @staticmethod
    def _merge_sites(left: Dict[Obj, Tuple[int, ...]],
                     right: Dict[Obj, Tuple[int, ...]]) -> Dict[Obj, Tuple[int, ...]]:
        out: Dict[Obj, Tuple[int, ...]] = {}
        for obj in set(left) | set(right):
            out[obj] = tuple(sorted(set(left.get(obj, ())) | set(right.get(obj, ()))))
        return out

    @staticmethod
    def _merge_gen(left: Dict[int, int], right: Dict[int, int]) -> Dict[int, int]:
        """Generations grow monotonically across arms; 0 means "too many".

        Keeping the maximum is what distinguishes iteration 1 from iteration 2 of
        a loop; once a site has produced more objects than the cap, it stays at 0
        for good, so the identity is lost instead of being reused.
        """
        out: Dict[int, int] = {}
        for site in set(left) | set(right):
            a = left.get(site)
            b = right.get(site)
            if a is None:
                out[site] = b if b is not None else 0
            elif b is None:
                out[site] = a
            elif a == 0 or b == 0:
                out[site] = 0
            else:
                out[site] = max(a, b)
        return out

    def merge(self, other: "RegState") -> "RegState":
        regs: Dict[str, FrozenSet[Value]] = {}
        for reg in sorted(set(self.regs) | set(other.regs)):
            regs[reg] = self.get(reg) | other.get(reg)
        origins = {reg: site for reg, site in self.origins.items()
                   if other.origins.get(reg) == site}
        facts: Dict[Obj, Tuple[Tuple[int, str, str], ...]] = {}
        for obj in set(self.release_facts) | set(other.release_facts):
            facts[obj] = tuple(sorted(set(self.release_facts.get(obj, ())) |
                                      set(other.release_facts.get(obj, ()))))
        merged = RegState(
            regs=regs,
            mem=self.mem.merge(other.mem),
            released_must=self.released_must & other.released_must,
            released_may=self.released_may | other.released_may,
            release_sites=self._merge_sites(self.release_sites, other.release_sites),
            unknown_effect=tuple(sorted(set(self.unknown_effect) | set(other.unknown_effect))),
            timeline=self.timeline if self.timeline == other.timeline else self.timeline,
            origins=origins,
            uncertain=self.uncertain | other.uncertain,
            definite_sites=self._merge_sites(self.definite_sites, other.definite_sites),
            may_sites=self._merge_sites(self.may_sites, other.may_sites),
            release_facts=facts,
            taint_sites=self._merge_sites(self.taint_sites, other.taint_sites),
            alloc_gen=self._merge_gen(self.alloc_gen, other.alloc_gen),
            ret_gen=self._merge_gen(self.ret_gen, other.ret_gen),
        )
        return merged

    def copy(self) -> "RegState":
        return RegState(dict(self.regs), self.mem.copy(), self.released_must,
                        self.released_may, dict(self.release_sites),
                        self.unknown_effect, self.timeline,
                        dict(self.origins), self.uncertain, dict(self.definite_sites),
                        dict(self.may_sites), dict(self.release_facts),
                        dict(self.taint_sites), dict(self.alloc_gen), dict(self.ret_gen))

    def fingerprint(self) -> tuple:
        """Cheap change detector for the worklist fixpoint.

        Every *semantic* set is part of the key, so a state that differs in a
        released object, a may-site, a taint site or a generation is requeued.
        Evidence-only fields (``unknown_effect``, ``origins``, ``timeline``) are
        not: they never change a verdict, and chasing them is what made the old
        fixpoint burn its step budget.
        """
        regs = tuple(sorted((r, tuple(sorted(_vkey(v) for v in vals)))
                            for r, vals in self.regs.items()))
        # an approximate cell has no usable version, so it is keyed by state only:
        # that is what lets a merged state reach its fixpoint
        cells = tuple(sorted((a.key(), c.state,
                              c.version if c.state == CELL_EXACT else -1,
                              tuple(sorted(_vkey(v) for v in c.values)))
                             for a, c in self.mem.cells.items()))
        return (regs, cells, self.released_must, self.released_may,
                tuple(sorted((o.kind, o.key, s) for o, s in self.release_sites.items())),
                tuple(sorted((o.kind, o.key, s) for o, s in self.may_sites.items())),
                tuple(sorted((o.kind, o.key, f) for o, f in self.release_facts.items())),
                self.uncertain,
                tuple(sorted((o.kind, o.key, s) for o, s in self.definite_sites.items())),
                tuple(sorted((o.kind, o.key, s) for o, s in self.taint_sites.items())),
                # ``unknown_effect`` and ``origins`` are evidence, not semantics:
                # they go into the report, never into a verdict, so keeping them in
                # the key would only make the fixpoint chase its own bookkeeping.
                tuple(sorted(self.alloc_gen.items())),
                tuple(sorted(self.ret_gen.items())),
                tuple(sorted(self.mem.lost)))
