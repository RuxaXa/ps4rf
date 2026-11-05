"""Dependency-free tests for intra-block lock ordering.

These intentionally run without Capstone to provide a lightweight regression
against the path helper before full disassembly integration is available.
"""
from dataclasses import dataclass

from tools.discovery.lock_paths import stores_before_any_lock


@dataclass(frozen=True)
class Ins:
    address: int


class View:
    def __init__(self, blocks, succ):
        self.ins_by = {start: [Ins(a) for a in addrs] for start, addrs in blocks.items()}
        self.ins = [ins for il in self.ins_by.values() for ins in il]
        self.succ = succ
        self.by_addr = {ins.address: start for start, il in self.ins_by.items() for ins in il}

    def block_of(self, addr):
        return self.by_addr.get(addr)


def test_store_preceding_lock_in_same_basic_block_is_exposed():
    view = View({100: [100, 101, 102]}, {100: []})
    assert stores_before_any_lock(view, {101}, {100}) == [100]


def test_store_following_lock_in_same_basic_block_is_not_exposed():
    view = View({100: [100, 101, 102]}, {100: []})
    assert stores_before_any_lock(view, {100}, {102}) == []


def test_alternative_arms_acquire_lock_before_join():
    view = View({100: [100], 200: [200], 300: [300], 400: [400]},
                {100: [200, 300], 200: [400], 300: [400], 400: []})
    assert stores_before_any_lock(view, {200, 300}, {400}) == []


def test_one_arm_skips_lock():
    view = View({100: [100], 200: [200], 300: [300], 400: [400]},
                {100: [200, 300], 200: [400], 300: [400], 400: []})
    assert stores_before_any_lock(view, {200}, {400}) == [400]


def test_back_edge_terminates():
    view = View({100: [100], 200: [200, 201]}, {100: [200], 200: [100]})
    assert stores_before_any_lock(view, {201}, {200}) == [200]


def test_unreachable_store_is_not_exposed():
    view = View({100: [100], 200: [200]}, {100: [], 200: []})
    assert stores_before_any_lock(view, {100}, {200}) == []


def test_empty_view():
    view = View({}, {})
    assert stores_before_any_lock(view, set(), set()) == []
