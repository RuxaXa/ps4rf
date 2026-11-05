"""Instruction-order-aware, intraprocedural lock-free path witnesses.

This is deliberately a *may* analysis.  A path is considered blocked at the first
observed acquisition call, without asserting lock identity, release pairing, or
interprocedural synchronization.  It must never yield a PROVEN race by itself.
"""
from __future__ import annotations

from typing import Iterable


def stores_before_any_lock(view, lock_sites: Iterable[int], store_sites: Iterable[int]) -> list[int]:
    """Find stores reachable from function entry before the first lock acquisition.

    Unlike treating an entire block containing a lock call as protected, inspect
    each instruction in order.  This catches a store *before* the lock in the
    same basic block, without falsely reporting stores after that acquisition.

    The view supplies ``ins``, ``ins_by``, ``succ`` and ``block_of``.  Unknown
    CFG successors must be represented by the caller's uncertainty handling;
    this helper does not infer missing edges or cross-function lock state.
    """
    if not view.ins:
        return []
    start = view.block_of(view.ins[0].address)
    if start is None:
        return []

    acquisitions = set(lock_sites)
    candidates = set(store_sites)
    found: set[int] = set()
    seen: set[int] = set()
    stack = [start]
    while stack:
        block = stack.pop()
        if block in seen:
            continue
        seen.add(block)
        if block not in view.ins_by:
            continue
        for ins in view.ins_by[block]:
            if ins.address in acquisitions:
                # From here onward this path no longer witnesses a store before
                # an acquisition.  The previous instructions have been inspected.
                break
            if ins.address in candidates:
                found.add(ins.address)
        else:
            stack.extend(view.succ.get(block, ()))
    return sorted(found)
