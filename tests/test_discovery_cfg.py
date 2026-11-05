"""The default CFG, edge by edge.

S1.8 had to withhold the conditional-branch edges: `_direct_target` returns a target only
for `call`/`jmp`, so every `je`/`jne` lost its taken edge, alternative paths never joined,
and a value looked definite across a branch.  S1.9 restores them.

Both directions are fixed as data, before the engine runs (``cfg-fixtures.json``):

* nine positive edges -- taken and fall-through, per branch shape;
* negative edges -- a `jmp` has no fall-through, an indirect `jmp` has no successor at
  all, a `ret` has none, a `jmp` out of the function is not an internal edge;
* one shape where taken target == fall-through, which must yield exactly one edge.
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

from tools.discovery import patterns, validate
from tools.discovery.image import FunctionIndex, FunctionRecord

FIXDIR = ROOT / "tests" / "fixtures" / "discovery"
FIXTURE = FIXDIR / "cfg-fixtures.json"
GENERATOR = FIXDIR / "gen_cfg.py"


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
def cfg_doc():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def cfg_image(cfg_doc):
    return FixtureImage(cfg_doc)


def label_address(doc: dict, name: str) -> int:
    return int((doc["labels"].get(name) or doc["functions"].get(name))["rva"], 16)


def view_of(doc, image, name: str, strict: bool = False):
    meta = doc["functions"][name]
    return patterns.FunctionView(image, int(meta["rva"], 16), int(meta["size"], 16),
                                 name, strict_cfg=strict)


def successors_by_label(doc, view, source: str):
    by_address = {int(meta["rva"], 16): label for label, meta in doc["labels"].items()}
    block = view.block_of(label_address(doc, source))
    assert block is not None, source
    out = []
    for succ_block in view.succ.get(block, ()):
        out.append(by_address.get(succ_block, hex(succ_block)))
    return out


def test_fixture_matches_generator():
    before = FIXTURE.read_text(encoding="utf-8")
    result = subprocess.run([sys.executable, str(GENERATOR), "--check"],
                            cwd=str(ROOT), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert FIXTURE.read_text(encoding="utf-8") == before


@pytest.mark.parametrize("name", sorted(json.loads(FIXTURE.read_text(encoding="utf-8"))["cfg"]))
def test_successor_sets_are_exactly_the_declared_ones(cfg_doc, cfg_image, name):
    """Every declared edge is present and no other edge exists from that block."""
    expected = cfg_doc["cfg"][name]["successors"]
    view = view_of(cfg_doc, cfg_image, name)
    for source, targets in expected.items():
        got = successors_by_label(cfg_doc, view, source)
        assert sorted(got) == sorted(targets), \
            f"{name} {source}: expected {sorted(targets)}, got {sorted(got)}"
    for source in cfg_doc["cfg"][name].get("empty", []):
        assert successors_by_label(cfg_doc, view, source) == [], \
            f"{name} {source}: declared as a block without successors"


def test_a_branch_to_the_next_instruction_yields_one_edge(cfg_doc, cfg_image):
    """`je` to the following label: taken == fall-through, so exactly one successor."""
    view = view_of(cfg_doc, cfg_image, "fixture_cfg_same_target")
    block = view.block_of(label_address(cfg_doc, "cfg_same_branch"))
    succ = view.succ[block]
    assert len(succ) == 1, f"duplicate edge: {[hex(s) for s in succ]}"
    assert len(set(succ)) == len(succ), "successor list must not repeat a block"
    for name in cfg_doc["cfg"]:
        other = view_of(cfg_doc, cfg_image, name)
        for source_block, targets in other.succ.items():
            assert len(set(targets)) == len(targets), \
                f"{name} {hex(source_block)}: duplicate successor"


def test_unreachable_blocks_stay_unreachable(cfg_doc, cfg_image):
    for name, spec in cfg_doc["cfg"].items():
        view = view_of(cfg_doc, cfg_image, name)
        reached = set(view.reachable_blocks(view.block_of(view.ins[0].address)))
        for label in spec.get("unreachable", []):
            assert view.block_of(label_address(cfg_doc, label)) not in reached, \
                f"{name}: {label} must not be reachable"


def test_a_jump_out_of_the_function_is_a_tail_call_not_an_edge(cfg_doc, cfg_image):
    view = view_of(cfg_doc, cfg_image, "fixture_cfg_tail")
    site = None
    for ins in view.ins:
        if ins.mnemonic == "jmp":
            site = ins.address
    assert site is not None
    assert view.jumps.get(site) == label_address(cfg_doc, "d2_free")
    assert view.block_of(site) in view.succ
    assert view.succ[view.block_of(site)] == []


def test_the_encoded_target_is_the_edge_target(cfg_doc, cfg_image):
    """The engine's target comes from the instruction's own immediate, not a guess."""
    cases = {
        "fixture_cfg_cond_two_ways": ("cfg_two_branch", "cfg_two_else"),
        "fixture_cfg_jmp_only": ("cfg_jmp_branch", "cfg_jmp_target"),
        "fixture_cfg_same_target": ("cfg_same_branch", "cfg_same_next"),
        "fixture_cfg_loop": ("cfg_loop_body", "cfg_loop_body"),
    }
    for name, (source, target) in cases.items():
        view = view_of(cfg_doc, cfg_image, name)
        block = view.block_of(label_address(cfg_doc, source))
        branch = [i for i in view.ins_by[block] if i.mnemonic.startswith("j")]
        assert branch, f"{name}: no jump in the declared block"
        ins = branch[-1]
        assert patterns._branch_target(ins) == label_address(cfg_doc, target), \
            f"{name}: {ins.mnemonic} {ins.op_str} does not target {target}"
        assert view.block_of(label_address(cfg_doc, target)) in view.succ[block]


def test_both_modes_carry_the_same_branch_edges(cfg_doc, cfg_image):
    """`strict_cfg` may differ in what ends a block, never in whether a branch has edges."""
    for name in cfg_doc["cfg"]:
        loose = view_of(cfg_doc, cfg_image, name, strict=False)
        strict = view_of(cfg_doc, cfg_image, name, strict=True)
        assert loose.succ == strict.succ, f"{name}: modes disagree on the edge set"


# ------------------------------------------------------------- real firmware


@pytest.fixture(scope="module")
def env():
    pytest.importorskip("capstone")
    return validate.Environment.load(str(ROOT / "tools" / "discovery" / "data"),
                                     only=["13.52", "9.00"])


@pytest.mark.parametrize("fw,rva,size", [("13.52", 0x11F710, 0x7F0),
                                        ("9.00", 0x410870, 0x8F0),
                                        ("13.52", 0x3BA7B0, 0x6B1)])
def test_every_direct_conditional_branch_in_a_real_body_has_its_taken_edge(env, fw, rva, size):
    """The correction holds on firmware, not only on the fixture."""
    view = patterns.FunctionView(env.images[fw], rva, size, f"{fw}@{rva:#x}")
    conditional = [i for i in view.ins if i.mnemonic.startswith("j") and i.mnemonic != "jmp"]
    assert conditional, "the body has conditional branches"
    missing = []
    for ins in conditional:
        target = patterns._branch_target(ins)
        if target is None:
            continue
        block = view.block_of(ins.address)
        target_block = view.block_of(target)
        if target_block is None:
            continue  # a branch out of the analysed range: not an internal edge
        if target_block not in view.succ.get(block, ()):
            missing.append((hex(ins.address), ins.mnemonic, hex(target)))
    assert not missing, f"{fw}@{rva:#x}: taken edges missing: {missing}"
