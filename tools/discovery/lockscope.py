"""Lock-scope dataflow (D3) on top of the sync catalog.

The question D3 answers is not "does this function touch a lock" but "is *this*
mutation covered by *this* lock on *every* path that reaches it".  That is a
must/may dataflow, not a scan:

* ``must[b]`` = locks claimed/acquired on every path into block ``b``
* ``may[b]``  = locks acquired on at least one path into ``b``

A mutation whose ``must`` set is empty while ``may`` is not is protected on one
arm of a branch and unprotected on the other.  That is the shape of the published
``aio_multi_delete`` defect (the exclusive entry claim runs only when
``ao_rem_ids == 1``), and it is invisible to any rule that counts lock calls
instead of propagating them.

Nothing in here knows a firmware address, a syscall number or a function name.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .image import KernelImage
from .locks import (ACQUIRE_EXCL, ACQUIRE_SHARED, CLAIM, HELD, NOT_HELD,
                    PATH_DEPENDENT, RELEASE, UNKNOWN_STATE, SyncCatalog,
                    UNKNOWN, _mem_expr, canonical_reg, is_atomic, mem_key, provenance)
from .patterns import FunctionView

try:  # pragma: no cover
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
except Exception:  # pragma: no cover
    X86_OP_IMM = X86_OP_MEM = X86_OP_REG = -1

STORE = "STORE"
RELEASE_CALL = "RELEASE_CALL"
REFCOUNT_DROP = "REFCOUNT_DROP"
DIFFERENT_LOCK = "DIFFERENT_LOCK"

GRADE_B = "B"
GRADE_A = "A"
GRADE_U = "UNKNOWN"


# ------------------------------------------------------------------- events


@dataclass
class LockEvent:
    site: int
    effect: str          # ACQUIRE_EXCL / ACQUIRE_SHARED / RELEASE / CLAIM
    lock_id: str
    callee: int
    mode: str
    kind: str
    confidence: str
    evidence: str
    block: int = 0
    text: str = ""

    def as_dict(self) -> dict:
        return {
            "site": hex(self.site),
            "effect": self.effect,
            "lock_id": self.lock_id,
            "callee": hex(self.callee),
            "kind": self.kind,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "instruction": self.text,
        }


@dataclass
class MutationSite:
    site: int
    kind: str
    obj_expr: str
    text: str
    block: int = 0

    def as_dict(self) -> dict:
        return {"site": hex(self.site), "kind": self.kind, "object": self.obj_expr,
                "instruction": self.text}


# -------------------------------------------------------------------- scope


class LockScope:
    """Per-function lock/claim scope analysis."""

    def __init__(self, image: KernelImage, rva: int, size: int, catalog: SyncCatalog,
                 release_targets: Optional[Iterable[int]] = None, name: str = "",
                 max_blocks: int = 400):
        self.image = image
        self.catalog = catalog
        self.release_targets = set(release_targets or ())
        self.name = name
        self.view = FunctionView(image, rva, size, name, strict_cfg=True)
        self.rva = rva
        self.events: List[LockEvent] = []
        self.mutations: List[MutationSite] = []
        self.unknown_calls: List[dict] = []
        self._alias_before: Dict[int, Tuple[Set[str], Set[str]]] = {}
        self.claim_modes: Dict[str, str] = {}
        self.must: Dict[int, frozenset] = {}
        self.may: Dict[int, frozenset] = {}
        self._collect()
        self._solve_object_aliases()
        if 0 < len(self.view.blocks) <= max_blocks:
            self._solve()

    # -- collection ---------------------------------------------------------

    def _arg_prov(self, ins_list, pos: int, reg: str):
        return provenance(ins_list, pos, reg)

    def _collect(self) -> None:
        ins = self.view.ins
        for pos, i in enumerate(ins):
            if i.mnemonic == "call":
                try:
                    tgt = int(i.op_str, 16)
                except ValueError:
                    self.unknown_calls.append({"site": hex(i.address),
                                               "reason": "indirect call: lock state of the callee is unknown"})
                    continue
                cls = self.catalog.classify(tgt)
                if cls is not None:
                    reg = "rcx" if (cls["effect"] == CLAIM and cls.get("stamp_field") is not None) else "rdi"
                    prov = self._arg_prov(ins, pos, reg)
                    lock_id = "%s:%s" % (cls["kind"], prov.expr)
                    if cls.get("stamp_field") is not None:
                        # The helper's return value is the claimed object.  A
                        # forward must/may alias analysis ties that returned
                        # object to later mutation operands; the call site is
                        # a unique, non-name-derived claim identity.
                        lock_id = "claim@%#x" % i.address
                        self.claim_modes[lock_id] = cls.get("mode") or ACQUIRE_EXCL
                    self.events.append(LockEvent(
                        site=i.address, effect=cls["effect"], lock_id=lock_id,
                        callee=tgt, mode=cls["mode"], kind=cls["kind"],
                        confidence=prov.confidence, evidence=cls["evidence"],
                        block=self.view.block_of(i.address) or 0,
                        text=f"{i.mnemonic} {i.op_str}"))
                    continue
                if tgt in self.release_targets:
                    prov = self._arg_prov(ins, pos, "rdi")
                    self.mutations.append(MutationSite(
                        site=i.address, kind=RELEASE_CALL, obj_expr=prov.expr,
                        text=f"{i.mnemonic} {i.op_str}",
                        block=self.view.block_of(i.address) or 0))
                continue
            # -- mutations in plain instructions
            if is_atomic(i):
                ops = i.operands
                if len(ops) > 1 and ops[1].type == X86_OP_IMM:
                    val = ops[1].imm
                    size = ops[0].size * 8 if ops[0].size else 64
                    signed = val - (1 << size) if val >= (1 << (size - 1)) else val
                    if signed < 0:
                        key = mem_key(i)
                        mop = i.operands[0]
                        base = (canonical_reg(i.reg_name(mop.mem.base))
                                if mop.type == X86_OP_MEM and mop.mem.base else "")
                        prov = self._arg_prov(ins, pos, base) if base else None
                        self.mutations.append(MutationSite(
                            site=i.address, kind=REFCOUNT_DROP,
                            obj_expr="%s%s" % (prov.expr if prov else "?", key or ""),
                            text=f"{i.mnemonic} {i.op_str}",
                            block=self.view.block_of(i.address) or 0))
                continue
            if i.mnemonic != "mov" or len(i.operands) < 2:
                continue
            if i.operands[0].type != X86_OP_MEM:
                continue
            key = mem_key(i)
            if not key or key.startswith("rip"):
                continue
            mop = i.operands[0]
            base = (canonical_reg(i.reg_name(mop.mem.base))
                    if mop.type == X86_OP_MEM and mop.mem.base else "")
            if base in ("rsp", "rbp", ""):
                continue
            prov = self._arg_prov(ins, pos, base)
            self.mutations.append(MutationSite(
                site=i.address, kind=STORE,
                obj_expr="%s%s" % (prov.expr, key[len(base):] if key.startswith(base) else key),
                text=f"{i.mnemonic} {i.op_str}",
                block=self.view.block_of(i.address) or 0))

    # -- return-object claim aliases ----------------------------------------

    @staticmethod
    def _copy_alias_map(value: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        return {key: set(items) for key, items in value.items() if items}

    @staticmethod
    def _stack_location(ins, op) -> Optional[str]:
        if op.type != X86_OP_MEM or not op.mem.base or op.mem.index:
            return None
        base = canonical_reg(ins.reg_name(op.mem.base))
        if base not in ("rbp", "rsp"):
            return None
        return _mem_expr(ins, op)

    @staticmethod
    def _operand_alias(ins, op, state: Dict[str, Set[str]]) -> Set[str]:
        if op.type == X86_OP_REG:
            return set(state.get(canonical_reg(ins.reg_name(op.reg)), ()))
        loc = LockScope._stack_location(ins, op)
        return set(state.get(loc, ())) if loc else set()

    def _alias_transfer(self, body: Sequence, must: Dict[str, Set[str]],
                        may: Dict[str, Set[str]], capture: bool = False):
        claim_events = {event.site: event.lock_id for event in self.events
                        if event.effect == CLAIM}
        volatile = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}
        mutation_sites = {mutation.site: mutation for mutation in self.mutations}
        for ins in body:
            if capture and ins.address in mutation_sites:
                mutation = mutation_sites[ins.address]
                base = ""
                if mutation.kind == RELEASE_CALL:
                    base = "rdi"
                elif ins.operands and ins.operands[0].type == X86_OP_MEM:
                    mop = ins.operands[0]
                    if mop.mem.base:
                        base = canonical_reg(ins.reg_name(mop.mem.base))
                self._alias_before[ins.address] = (
                    set(must.get(base, ())), set(may.get(base, ())))

            if ins.mnemonic == "call":
                for reg in volatile:
                    must.pop(reg, None)
                    may.pop(reg, None)
                claim_id = claim_events.get(ins.address)
                if claim_id:
                    must["rax"] = {claim_id}
                    may["rax"] = {claim_id}
                continue

            ops = ins.operands
            if ins.mnemonic.startswith("mov") and len(ops) >= 2:
                dst, src = ops[0], ops[1]
                if dst.type == X86_OP_REG:
                    loc = canonical_reg(ins.reg_name(dst.reg))
                else:
                    loc = self._stack_location(ins, dst)
                if loc:
                    src_must = self._operand_alias(ins, src, must)
                    src_may = self._operand_alias(ins, src, may)
                    if src_must:
                        must[loc] = src_must
                    else:
                        must.pop(loc, None)
                    if src_may:
                        may[loc] = src_may
                    else:
                        may.pop(loc, None)
                continue

            # Any unsupported explicit register write kills the alias.  This
            # is fail-closed for positive lock coverage.
            try:
                _read, written = ins.regs_access()
            except Exception:
                written = ()
            for reg_id in written:
                reg = canonical_reg(ins.reg_name(reg_id))
                if reg not in ("rflags", "eflags"):
                    must.pop(reg, None)
                    may.pop(reg, None)
        return must, may

    @staticmethod
    def _join_alias_maps(states: Sequence[Dict[str, Set[str]]],
                         must_join: bool) -> Dict[str, Set[str]]:
        if not states:
            return {}
        keys = set().union(*(state.keys() for state in states))
        out = {}
        for key in keys:
            values = [set(state.get(key, ())) for state in states]
            merged = set.intersection(*values) if must_join else set.union(*values)
            if merged:
                out[key] = merged
        return out

    def _solve_object_aliases(self) -> None:
        """Forward must/may aliases for return-object claims.

        The bounded lattice tracks canonical registers and rbp/rsp stack homes.
        Unsupported transformations kill aliases instead of inventing one.
        """
        if not self.view.blocks:
            return
        entry = next(iter(self.view.blocks))
        reachable = set(self.view.reachable_blocks(entry))
        in_must: Dict[int, Dict[str, Set[str]]] = {entry: {}}
        in_may: Dict[int, Dict[str, Set[str]]] = {entry: {}}
        out_must: Dict[int, Dict[str, Set[str]]] = {}
        out_may: Dict[int, Dict[str, Set[str]]] = {}
        pred_map: Dict[int, List[int]] = {block: [] for block in self.view.blocks}
        for source, targets in self.view.succ.items():
            for target in targets:
                pred_map.setdefault(target, []).append(source)
        changed = True
        rounds = 0
        limit = max(8, len(reachable) * 4)
        while changed and rounds < limit:
            changed = False
            rounds += 1
            for block in self.view.blocks:
                if block not in reachable:
                    continue
                if block != entry:
                    preds = [pred for pred in pred_map.get(block, ())
                             if pred in out_may]
                    if not preds:
                        continue
                    new_must = self._join_alias_maps([out_must[p] for p in preds], True)
                    new_may = self._join_alias_maps([out_may[p] for p in preds], False)
                    if new_must != in_must.get(block) or new_may != in_may.get(block):
                        in_must[block], in_may[block] = new_must, new_may
                        changed = True
                block_must = self._copy_alias_map(in_must.get(block, {}))
                block_may = self._copy_alias_map(in_may.get(block, {}))
                new_out_must, new_out_may = self._alias_transfer(
                    self.view.ins_by.get(block, ()), block_must, block_may)
                if (new_out_must != out_must.get(block) or
                        new_out_may != out_may.get(block)):
                    out_must[block], out_may[block] = new_out_must, new_out_may
                    changed = True
        for block in reachable:
            block_must = self._copy_alias_map(in_must.get(block, {}))
            block_may = self._copy_alias_map(in_may.get(block, {}))
            self._alias_transfer(self.view.ins_by.get(block, ()),
                                 block_must, block_may, capture=True)

    # -- dataflow -----------------------------------------------------------

    def _preds(self) -> Dict[int, List[int]]:
        preds: Dict[int, List[int]] = {b: [] for b in self.view.blocks}
        for b, succ in self.view.succ.items():
            for s in succ:
                preds.setdefault(s, []).append(b)
        return preds

    def _solve(self) -> None:
        blocks = list(self.view.blocks)
        preds = self._preds()
        entry = blocks[0]
        events_by_block: Dict[int, List[LockEvent]] = {b: [] for b in blocks}
        for e in self.events:
            events_by_block.setdefault(e.block, []).append(e)
        top = frozenset({"<entry>"})
        must_in = {b: (top if b == entry else None) for b in blocks}
        may_in = {b: (frozenset() if b == entry else None) for b in blocks}
        changed = True
        rounds = 0
        while changed and rounds < 100:
            changed = False
            rounds += 1
            for b in blocks:
                if b != entry:
                    live = [p for p in preds.get(b, []) if must_in.get(p) is not None]
                    if not live:
                        continue
                    new_must = None
                    new_may: Set[str] = set()
                    for p in live:
                        out_must, out_may = self._run_block(p, must_in[p], may_in[p] or frozenset(),
                                                            events_by_block)
                        new_must = out_must if new_must is None else (new_must & out_must)
                        new_may |= out_may
                    if new_must is None:
                        continue
                    if must_in[b] != frozenset(new_must):
                        must_in[b] = frozenset(new_must)
                        changed = True
                    if may_in[b] != frozenset(new_may):
                        may_in[b] = frozenset(new_may)
                        changed = True
                if must_in[b] is None:
                    continue
                out_must, out_may = self._run_block(b, must_in[b], may_in[b] or frozenset(),
                                                    events_by_block)
                self.must[b] = frozenset(out_must)
                self.may[b] = frozenset(out_may)
        for b in blocks:
            if must_in.get(b) is None:
                continue
            base_must = must_in[b]
            if base_must is None:
                continue
            m, y = self._run_block(b, base_must, may_in[b] or frozenset(), events_by_block)
            self.must[b] = frozenset(m)
            self.may[b] = frozenset(y)
        self._incoming = {b: (frozenset(must_in[b] or frozenset()),
                              frozenset(may_in[b] or frozenset()))
                          for b in blocks
                          if must_in.get(b) is not None}

    def _run_block(self, b: int, must_in, may_in, events_by_block) -> Tuple[Set[str], Set[str]]:
        must = set(must_in) - {"<entry>"}
        may = set(may_in) - {"<entry>"}
        for e in events_by_block.get(b, ()):  # events are appended in address order
            if e.effect in (ACQUIRE_EXCL, ACQUIRE_SHARED, CLAIM):
                must.add(e.lock_id)
                may.add(e.lock_id)
            elif e.effect == RELEASE:
                must.discard(e.lock_id)
                may.discard(e.lock_id)
        return must, may

    # -- per-site state -----------------------------------------------------

    def state_at(self, site: int) -> dict:
        blk = self.view.block_of(site)
        if blk is None or blk not in self.must:
            return {"verdict": UNKNOWN_STATE, "must": [], "may": [],
                    "reason": "site outside the analysed CFG window"}
        must = set(self.must[blk])
        may = set(self.may[blk])
        # replay this block up to the site so the state is exact, not block-level
        ins = self.view.ins_by.get(blk, [])
        start_must, start_may = self._incoming.get(blk, (frozenset(), frozenset()))
        must = set(start_must) - {"<entry>"}
        may = set(start_may) - {"<entry>"}
        for e in self.events:
            if e.block != blk or e.site >= site:
                continue
            if e.effect in (ACQUIRE_EXCL, ACQUIRE_SHARED, CLAIM):
                must.add(e.lock_id)
                may.add(e.lock_id)
            elif e.effect == RELEASE:
                must.discard(e.lock_id)
                may.discard(e.lock_id)
        if must:
            verdict = HELD
        elif may:
            verdict = PATH_DEPENDENT
        else:
            verdict = NOT_HELD
        return {"verdict": verdict, "must": sorted(must), "may": sorted(may),
                "block": hex(blk)}

    @staticmethod
    def _identity(lock_id: str) -> str:
        """Strip the primitive kind from a lock identity."""
        return lock_id.split(":", 1)[1] if ":" in lock_id else lock_id

    @classmethod
    def _covers(cls, lock_id: str, obj_expr: str) -> bool:
        """A lock covers its base object and fields derived from that base.

        This is deliberately one-way: a lock on ``obj(A)`` may cover
        ``obj(A)+field``; a lock on ``obj(B)`` never covers ``obj(A)`` merely
        because both are held at the site.
        """
        ident = cls._identity(lock_id)
        if ident == obj_expr:
            return True
        return bool(ident and obj_expr.startswith(ident + "+"))

    def _unknown_before(self, site: int) -> List[dict]:
        return [u for u in self.unknown_calls if int(u["site"], 16) < site]

    def _witness_path(self, target: int, forbidden: Set[str]) -> List[str]:
        """One entry->target block path that avoids the named acquires/claims."""
        if not self.view.blocks:
            return []
        entry = next(iter(self.view.blocks))
        blocked = {
            e.block for e in self.events
            if e.effect in (ACQUIRE_EXCL, ACQUIRE_SHARED, CLAIM)
            and e.lock_id in forbidden
        }
        queue = [(entry, [entry])]
        seen = set()
        while queue:
            block, path = queue.pop(0)
            if block in seen or (block in blocked and block != target):
                continue
            seen.add(block)
            if block == target:
                return [hex(b) for b in path]
            for nxt in self.view.succ.get(block, ()):
                queue.append((nxt, path + [nxt]))
        return []

    def _dominance_rows(self, lock_ids: Sequence[str], mutation_block: int) -> List[dict]:
        """Dominator evidence: does the acquiring block dominate the mutation?"""
        if not lock_ids:
            return []
        dom = self.view.dominators()
        dominating = dom.get(mutation_block, set())
        rows = []
        for lock_id in lock_ids:
            sites = [event for event in self.events if event.lock_id == lock_id]
            for event in sites:
                rows.append({
                    "lock_id": lock_id,
                    "acquire_site": hex(event.site),
                    "acquire_block": hex(event.block),
                    "mutation_block": hex(mutation_block),
                    "dominates_mutation": event.block in dominating,
                    "evidence": event.evidence,
                })
        return rows

    def mutation_assessments(self) -> List[dict]:
        """Object-aware verdict and proof for every mutation.

        ``state_at`` reports generic must/may lock sets.  This method performs
        the required alias/identity check and is the only interface consumers
        should use for a D3 verdict.
        """
        rows = []
        for mutation in self.mutations:
            generic = self.state_at(mutation.site)
            must = list(generic.get("must", ()))
            may = list(generic.get("may", ()))
            alias_must, alias_may = self._alias_before.get(mutation.site, (set(), set()))
            # A reader claim aliases the object but cannot protect a write.
            def exclusive(name: str) -> bool:
                return self.claim_modes.get(name, ACQUIRE_EXCL) in (ACQUIRE_EXCL, CLAIM)
            claim_must = sorted(x for x in set(must) & set(alias_must) if exclusive(x))
            claim_may = sorted(x for x in set(may) & set(alias_may) if exclusive(x))
            shared_must = sorted(x for x in set(must) & set(alias_must) if not exclusive(x))
            shared_may = sorted(x for x in set(may) & set(alias_must) if not exclusive(x))
            expr_must = [x for x in must
                         if not x.startswith("claim@") and self._covers(x, mutation.obj_expr)]
            expr_may = [x for x in may
                        if not x.startswith("claim@") and self._covers(x, mutation.obj_expr)]
            must_cover = sorted(set(expr_must) | set(claim_must))
            may_cover = sorted(set(expr_may) | set(claim_may))
            alternative = sorted(set(may) - set(may_cover))
            unknown = self._unknown_before(mutation.site)
            if must_cover:
                verdict = HELD
            elif may_cover:
                verdict = PATH_DEPENDENT
            elif unknown:
                verdict = UNKNOWN_STATE
            elif must or may:
                verdict = DIFFERENT_LOCK
            else:
                verdict = NOT_HELD
            path = []
            if verdict == PATH_DEPENDENT:
                path = self._witness_path(mutation.block, set(may_cover))
            state = dict(generic,
                         verdict=verdict,
                         covering_locks=sorted(must_cover),
                         possibly_covering_locks=sorted(may_cover),
                         object_claim_must=claim_must,
                         object_claim_may=claim_may,
                         object_claim_shared_must=shared_must,
                         object_claim_shared_may=shared_may,
                         alternative_locks=alternative,
                         unknown_causes=unknown)
            rows.append({
                "site": mutation.as_dict(),
                "lock_state": state,
                "evidence": {
                    "object_identity": mutation.obj_expr,
                    "control_flow_path": path,
                    "relevant_instructions": list(self.view.window(mutation.site, 4, 2)),
                    "dominators": {
                        "covering": self._dominance_rows(must_cover, mutation.block),
                        "possibly_covering": self._dominance_rows(may_cover, mutation.block),
                    },
                },
            })
        return rows

    def exit_states(self) -> List[dict]:
        """Held-state at every reachable return (early exits included)."""
        out = []
        for block, body in self.view.ins_by.items():
            if not body or body[-1].mnemonic != "ret":
                continue
            state = self.state_at(body[-1].address)
            out.append({"site": hex(body[-1].address),
                        "must": state.get("must", []),
                        "may": state.get("may", []),
                        "verdict": state.get("verdict", UNKNOWN_STATE)})
        return out

    # -- findings -----------------------------------------------------------

    def findings(self) -> List[dict]:
        out = []
        acquires = [e for e in self.events if e.effect in (ACQUIRE_EXCL, ACQUIRE_SHARED, CLAIM)]
        has_exclusive = [e for e in acquires if e.effect in (ACQUIRE_EXCL, CLAIM)]
        assessments = {int(r["site"]["site"], 16): r for r in self.mutation_assessments()}
        for m in self.mutations:
            row = assessments[m.site]
            st = row["lock_state"]
            verdict = st["verdict"]
            if verdict == HELD:
                continue
            if verdict == NOT_HELD and not acquires:
                continue  # no lock in this function at all: out of scope for D3
            grade, rank = GRADE_B, 3
            if verdict == PATH_DEPENDENT:
                releasing = m.kind in (RELEASE_CALL, REFCOUNT_DROP)
                rank = 1 if releasing else 2
                pattern = "LOCK_SCOPE_PATH_DEPENDENT"
            elif verdict == DIFFERENT_LOCK:
                pattern = "LOCK_IDENTITY_MISMATCH"
                rank = 2 if m.kind in (RELEASE_CALL, REFCOUNT_DROP) else 3
            elif verdict == NOT_HELD:
                pattern = "LOCK_SCOPE_MUTATION_UNLOCKED"
                rank = 2 if m.kind in (RELEASE_CALL, REFCOUNT_DROP) else 3
            else:
                pattern = "LOCK_STATE_UNKNOWN"
                rank, grade = 5, GRADE_U
            relevant = [e.as_dict() for e in acquires
                        if verdict != PATH_DEPENDENT or e.lock_id in st["may"]]
            out.append({
                "pattern": pattern,
                "rank": rank,
                "grade": grade,
                "function": {"rva": hex(self.rva), "name": self.name,
                             "size": hex(self.view.size)},
                "site": m.as_dict(),
                "lock_state": st,
                "acquire_sites": relevant[:8],
                "exclusive_acquires": [e.as_dict() for e in has_exclusive][:8],
                "unknown_calls": self.unknown_calls[:4],
                "evidence": dict(self._evidence(m, st), **row["evidence"]),
            })
        out.sort(key=lambda f: (f["rank"], f["site"]["site"]))
        return out

    def _evidence(self, m: MutationSite, st: dict) -> dict:
        return {
            "claim": ("the mutation executes on a path where no exclusive acquire/claim "
                      "reaches it, while another arm of the same branch does acquire"),
            "must": st["must"],
            "may": st["may"],
            "window": list(self.view.window(m.site, before=4, after=2)),
        }

    def summary(self) -> dict:
        counts: Dict[str, int] = {}
        for m in self.mutations:
            row = next(r for r in self.mutation_assessments()
                       if int(r["site"]["site"], 16) == m.site)
            v = row["lock_state"]["verdict"]
            counts[v] = counts.get(v, 0) + 1
        return {
            "function": {"rva": hex(self.rva), "name": self.name, "size": hex(self.view.size)},
            "blocks": len(self.view.blocks),
            "events": len(self.events),
            "acquires": sum(1 for e in self.events if e.effect in (ACQUIRE_EXCL, ACQUIRE_SHARED)),
            "claims": sum(1 for e in self.events if e.effect == CLAIM),
            "releases": sum(1 for e in self.events if e.effect == RELEASE),
            "mutations": len(self.mutations),
            "mutation_states": counts,
            "findings": len(self.findings()),
        }


# ------------------------------------------------------- pair comparison


def compare_scope(a: LockScope, b: LockScope) -> dict:
    """Compare two builds of the same function.

    Matches mutation sites by *object expression plus mutation kind*, because
    absolute addresses move between firmware builds.  Unmatched sites are
    reported as such instead of being silently aligned.
    """
    def key(m: MutationSite) -> str:
        return "%s|%s" % (m.kind, m.obj_expr)

    a_map: Dict[str, List[MutationSite]] = {}
    for m in a.mutations:
        a_map.setdefault(key(m), []).append(m)
    b_map: Dict[str, List[MutationSite]] = {}
    for m in b.mutations:
        b_map.setdefault(key(m), []).append(m)
    rows = []
    for k in sorted(set(a_map) | set(b_map)):
        left = a_map.get(k, [])
        right = b_map.get(k, [])
        n = max(len(left), len(right))
        for idx in range(n):
            la = left[idx] if idx < len(left) else None
            rb = right[idx] if idx < len(right) else None
            rows.append({
                "key": k,
                "a": (dict(la.as_dict(), state=la_state(a, la)) if la else None),
                "b": (dict(rb.as_dict(), state=la_state(b, rb)) if rb else None),
                "delta": _delta(la_state(a, la) if la else None,
                                la_state(b, rb) if rb else None),
            })
    changed = [r for r in rows if r["delta"]]
    return {"rows": len(rows), "changed": changed, "all": rows}


def la_state(scope: LockScope, m: Optional[MutationSite]) -> Optional[str]:
    if m is None:
        return None
    return scope.state_at(m.site)["verdict"]


def _delta(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if a is None or b is None:
        return None
    if a == b:
        return None
    return "%s -> %s" % (a, b)
