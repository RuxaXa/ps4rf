"""D3_lock_coverage: is the store covered by a lock on *every* path?

S1.9 proved with a path witness that 6 of the stores reported after the CFG correction had
no lock-free path at all: every path took a lock, in *different* blocks, so no single lock
block dominated the store and the dominance test called it uncovered.  Coverage is now
read as a path property, and both directions are pinned on a binutils fixture.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from tools.discovery import patterns
from tools.discovery.image import FunctionIndex, FunctionRecord

FIXDIR = ROOT / "tests" / "fixtures" / "discovery"
FIXTURE = FIXDIR / "lock-coverage-fixtures.json"
GENERATOR = FIXDIR / "gen_lock_coverage.py"


class FixtureImage:
    def __init__(self, doc: dict):
        self.base = int(doc["base_rva"], 16)
        self.data = bytes.fromhex(doc["image_hex"])
        self.size = self.base + len(self.data)
        self.sha256 = hashlib.sha256(self.data).hexdigest()

    def read(self, rva: int, length: int) -> bytes:
        off = rva - self.base
        if off < 0 or off + length > len(self.data):
            raise ValueError("fixture read out of range")
        return self.data[off: off + length]

    def disasm(self, rva: int, length: int, instructions: bool = True):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = bool(instructions)
        available = max(0, len(self.data) - (rva - self.base))
        return list(md.disasm(self.read(rva, min(length, available)), rva)), md

    def executable_ranges(self):
        return [(self.base, self.base + len(self.data))]


@pytest.fixture(scope="module")
def doc():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def env(doc):
    image = FixtureImage(doc)
    index = FunctionIndex([
        FunctionRecord(int(meta["rva"], 16), int(meta["size"], 16), name)
        for name, meta in doc["symbols"].items()
    ])
    return doc, image, index, int(doc["roots"]["lock"], 16)


def findings(env, name: str):
    doc, image, index, lock_rva = env
    record = index.by_name(name)
    assert record is not None, name
    view = patterns.FunctionView(image, record.rva, record.size, record.name)
    ctx = patterns.ScanContext(lock_calls=frozenset({lock_rva}))
    return view, patterns.detect_lock_coverage(view, ctx)


def test_fixture_matches_generator():
    before = FIXTURE.read_text(encoding="utf-8")
    result = subprocess.run([sys.executable, str(GENERATOR), "--check"],
                            cwd=str(ROOT), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert FIXTURE.read_text(encoding="utf-8") == before


@pytest.mark.parametrize("name", sorted(json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]))
def test_each_shape_is_decided_as_the_fixture_data_says(env, name):
    doc, _image, _index, _lock = env
    view, got = findings(env, name)
    if doc["cases"][name] == "NO_CLAIM":
        assert got == [], doc["case_notes"][name]
        # the reason is structural: every path enters a lock block
        lock_blocks = {view.block_of(int(site, 16)) for site in
                       [hex(a) for a, t in view.calls.items()
                        if t == int(doc["roots"]["lock"], 16)]}
        exposed = patterns._blocks_without_lock(view, lock_blocks)
        store_blocks = {view.block_of(i.address) for i in view.ins
                        if patterns._store_key(i) and patterns._store_key(i).startswith("rbx")}
        assert not (store_blocks & exposed), "a store must not sit on a lock-free path"
    else:
        assert got, doc["case_notes"][name]
        finding = got[0]
        assert finding.rank == 2
        assert finding.claims["uncovered_count"] == 1
        assert "path-based" in finding.counter_evidence["coverage"]


def test_the_dominance_reading_would_call_the_fixture_a_bug(env):
    """The old test -- one lock block dominating the store -- fails on this shape.

    Two arms lock in two different blocks; no single lock block dominates the join, yet
    every path holds a lock.  This is the defect the path reading removes.
    """
    doc, _image, _index, _lock = env
    view, got = findings(env, "fixture_d3_lock_on_every_path")
    assert got == []
    dom = view.dominators()
    lock_blocks = {view.block_of(a) for a, t in view.calls.items()
                   if t == int(doc["roots"]["lock"], 16)}
    store_block = view.block_of(max(i.address for i in view.ins
                                    if i.mnemonic == "mov" and "0x110" in i.op_str))
    assert not any(block in dom.get(store_block, set()) for block in lock_blocks), \
        "the fixture must not have a dominating lock block, or it proves nothing"


def test_pre_lock_store_same_block_is_a_regression_for_block_granularity(env):
    """Prove this positive control was invisible to the old block-only reading."""
    doc, _image, _index, lock_rva = env
    view, got = findings(env, "fixture_d3_store_before_lock_same_block")
    assert len(got) == 1
    store_rva = int(got[0].claims["uncovered_stores"][0], 16)
    lock_sites = {a for a, target in view.calls.items() if target == lock_rva}
    assert len(lock_sites) == 1
    assert view.block_of(store_rva) == view.block_of(next(iter(lock_sites)))
    lock_blocks = {view.block_of(a) for a in lock_sites}
    assert view.block_of(store_rva) not in patterns._blocks_without_lock(view, lock_blocks), (
        "old block-only D3 would have incorrectly hidden the pre-lock write"
    )
