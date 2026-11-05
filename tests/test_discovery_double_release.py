"""D2_double_release: the same object twice, or only the same label?

S1.8 measured that restoring the conditional-branch edges in the CFG raises the newly
attributed release sites from 17 to 55 of 259 -- and that D2 then claimed a kill-free
path on the *fixed* 13.52 ``aio_multi_delete`` body, a rank-1 false positive on the
labelled negative.  The rule grouped release sites by their slot label alone; two sites
reading ``rbx`` are not the same object when ``rbx`` is reloaded in between.

S1.9 lands both halves in one step: the CFG carries every branch target in both modes,
and D2 requires the object identity to survive between the two sites (no store to the
slot, no rebinding of a base register of the slot, no caller-saved base across a call).

Evidence lines:
* a synthetic image assembled by real binutils, seven shapes (see the fixture's
  ``case_notes``) -- no kernel claim, statements about the analysis engine only;
* the labelled firmware pair: 13.52 fixed must stay unactionable while 9.00 vulnerable
  stays actionable.
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
FIXTURE = FIXDIR / "double-release-fixtures.json"
GENERATOR = FIXDIR / "gen_double_release.py"


class FixtureImage:
    """Minimal image view over a flat RVA==offset blob."""

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
def fixture_doc():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def fixture_env(fixture_doc):
    image = FixtureImage(fixture_doc)
    index = FunctionIndex([
        FunctionRecord(int(meta["rva"], 16), int(meta["size"], 16), name)
        for name, meta in fixture_doc["symbols"].items()
    ])
    return fixture_doc, image, index, int(fixture_doc["roots"]["free"], 16)


def fixture_findings(fixture_env, name: str, strict: bool = False):
    doc, image, index, free_rva = fixture_env
    rec = index.by_name(name)
    assert rec is not None, name
    view = patterns.FunctionView(image, rec.rva, rec.size, rec.name, strict_cfg=strict)
    ctx = patterns.ScanContext(release_calls=frozenset({free_rva}))
    return view, patterns.detect_double_release(view, ctx)


def test_fixture_matches_generator():
    """The committed image is exactly what the generator produces (no drift)."""
    before = FIXTURE.read_text(encoding="utf-8")
    result = subprocess.run([sys.executable, str(GENERATOR), "--check"],
                            cwd=str(ROOT), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert FIXTURE.read_text(encoding="utf-8") == before


@pytest.mark.parametrize("name", sorted(json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]))
def test_each_shape_is_decided_as_the_fixture_data_says(fixture_env, name):
    doc, _image, _index, _free = fixture_env
    expected = doc["cases"][name]
    _view, findings = fixture_findings(fixture_env, name)
    assert findings, f"{name}: two release sites on one slot must at least be reported"
    actionable = [f for f in findings if f.rank <= 2]
    if expected == "DOUBLE_RELEASE":
        assert actionable, f"{name}: {doc['case_notes'][name]} must be a double release"
    else:
        assert not actionable, f"{name}: {doc['case_notes'][name]}"
        for finding in findings:
            refused_for_a_reason = (finding.claims["path_between_without_kill"] is False
                                    or finding.counter_evidence["refcount_guarded"] is True)
            assert refused_for_a_reason, \
                f"{name}: rank 3 without a named reason: {finding.claims}"


def store_only_walk(view, first: int, second: int, slot: str) -> bool:
    """The S1.8 rule, kept as the defect's own counterexample.

    It asks only whether some path avoids a *store* to the slot.  On both fixtures
    below that walk finds a path, so the old rule fired at rank 1 on code where the
    second site provably consumes a different object.
    """
    start = view.block_of(first)
    target = view.block_of(second)
    visited, stack = set(), [start]
    while stack:
        b = stack.pop()
        if b in visited:
            continue
        visited.add(b)
        lo = first if b == start else -1
        hi = second if b == target else 1 << 62
        hit = [i for i in view.ins_by.get(b, ())
               if lo < i.address < hi and patterns._store_key(i) == slot]
        if hit:
            continue
        if b == target:
            return True
        stack.extend(view.succ.get(b, ()))
    return False


@pytest.mark.parametrize("name", ["fixture_d2_base_rebound", "fixture_d2_loop_carried",
                                  "fixture_d2_caller_saved_base"])
def test_identity_is_what_refuses_these_shapes_not_a_slot_store(fixture_env, name):
    """These are refused because the *object* changes, not because a NULL reset exists.

    The store-only walk (the S1.8 rule) accepts them; the detector must not.
    """
    view, findings = fixture_findings(fixture_env, name)
    claimed = {f.slot: (int(f.claims["release_sites"][0], 16),
                        int(f.claims["release_sites"][-1], 16))
               for f in findings if f.slot}
    assert claimed, name
    refused_on_identity = 0
    for slot, (first, second) in claimed.items():
        if store_only_walk(view, first, second, slot):
            refused_on_identity += 1
    assert refused_on_identity, f"{name}: expected an identity refusal, not a kill"
    for finding in findings:
        assert finding.claims["path_between_without_kill"] is False
        assert finding.claims["same_object"]["identity_registers"]
        assert "rebinding of a base register of the slot" in \
               finding.counter_evidence["identity_forms_checked"]


def test_the_refcount_guard_is_read_from_the_instructions(fixture_env):
    """A guarded pair names the decrement and the branch that skips the release."""
    _view, findings = fixture_findings(fixture_env, "fixture_d2_refcount_guarded")
    assert findings
    for finding in findings:
        assert finding.rank == 3
        assert finding.counter_evidence["refcount_guarded"] is True
        kinds = {kind["kind"] for kind in finding.claims["release_kinds"]}
        assert kinds == {"REFCOUNT_GUARDED"}, kinds
        for kind in finding.claims["release_kinds"]:
            assert "xadd" in kind["drop_text"] and "jne" in kind["guard_text"]
            assert kind["field"] == "0x28"


def test_a_conditional_pair_still_claims_and_says_it_is_conditional(fixture_env):
    """Conditional sites are recorded, not treated as a refusal."""
    _view, findings = fixture_findings(fixture_env, "fixture_d2_conditional_pair")
    assert findings
    best = min(findings, key=lambda f: f.rank)
    assert best.rank == 1
    kinds = {kind["kind"] for kind in best.claims["release_kinds"]}
    assert kinds == {"CONDITIONAL"}, kinds
    assert best.counter_evidence["refcount_guarded"] is False


def test_a_slot_label_is_read_back_as_an_identity():
    """A register slot carries its own identity, a memory slot its base registers."""
    register_slot, bases = patterns._slot_identity("rbx")
    assert register_slot is True and bases == ("rbx",)
    register_slot, bases = patterns._slot_identity("rbx+0x40")
    assert register_slot is False and bases == ("rbx",)
    register_slot, bases = patterns._slot_identity("rcx+r14*8+0x0")
    assert register_slot is False and bases == ("rcx", "r14")
    # a rip-relative label is a global: no register in the function can rebind it
    assert patterns._slot_identity("rip+0x191d927") == (False, ())


# ------------------------------------------------------- the labelled firmware pair


@pytest.fixture(scope="module")
def env():
    pytest.importorskip("capstone")
    return validate.Environment.load(str(ROOT / "tools" / "discovery" / "data"),
                                     only=["13.52", "9.00"])


def firmware_findings(env, fw: str, rva: int, size: int, name: str):
    image, index = env.images[fw], env.indexes[fw]
    named = {record.rva: record.name for record in index.named()}
    for anchor, value in (env.facts[fw].doc.get("anchors") or {}).items():
        named.setdefault(int(value, 16), anchor)
    ctx = patterns.ScanContext.from_names(named)
    return patterns.scan_function(image, rva, size, name, ctx)


def test_the_cfg_carries_conditional_branch_targets(env):
    """The default CFG must contain the taken edge of a conditional branch.

    Without it alternative paths never join, so a value looks definite across a
    branch and every must-strength claim rests on a CFG the program does not have.
    """
    image = env.images["13.52"]
    index = env.indexes["13.52"]
    record = index.get(0x11F710) or index.containing(0x11F710)
    view = patterns.FunctionView(image, record.rva, max(int(record.size or 1), 1))
    conditional = [i for i in view.ins if i.mnemonic.startswith("j")
                   and i.mnemonic != "jmp"]
    assert conditional, "the aio_multi_delete body has conditional branches"
    missing = []
    for ins in conditional:
        target = patterns._branch_target(ins)
        if target is None:
            continue
        block = view.block_of(ins.address)
        succ = view.succ.get(block, ())
        target_block = view.block_of(target)
        if target_block is not None and target_block not in succ:
            missing.append(hex(ins.address))
    assert not missing, f"conditional branch targets missing from the CFG: {missing}"


def test_the_fixed_body_stays_unactionable_while_the_vulnerable_one_stays_actionable(env):
    """The S1.9 gate, both directions, on the labelled pair.

    13.52 0x11f710 is the fixed aio_multi_delete body, 9.00 0x410870 the vulnerable
    one.  The CFG correction may not turn the labelled negative into a rank<=2
    finding, and the vulnerable body must keep one.
    """
    fixed = firmware_findings(env, "13.52", 0x11F710, 0x7F0, "sys_662")
    vulnerable = firmware_findings(env, "9.00", 0x410870, 0x8F0, "sys_662")
    assert all(f.rank > 2 for f in fixed), \
        [(f.detector, f.rank) for f in fixed if f.rank <= 2]
    assert any(f.rank <= 2 for f in vulnerable), \
        [(f.detector, f.rank) for f in vulnerable]


def test_d2_does_not_claim_a_kill_free_path_across_a_loop_on_the_fixed_body(env):
    """The exact S1.8 false positive: two `rbx` sites, `rbx` reloaded between them."""
    fixed = [f for f in firmware_findings(env, "13.52", 0x11F710, 0x7F0, "sys_662")
             if f.detector == "D2_double_release"]
    assert fixed, "the two release sites are still published"
    for finding in fixed:
        assert finding.rank == 3
        assert finding.claims["path_between_without_kill"] is False
        assert finding.claims["same_object"]["identity_registers"] == ["rbx"]
