"""D1/D4 ownership and table-slot lifecycle: fixtures and detector acceptance.

The x86-64 fixture image is produced by real binutils and analysed through the
same capstone/CFG path as the firmware.  A fixture *name* selects a function; it
is never an input to the analysis: the release/alloc roots are handed in as data
(`roots` in the generated fixture document), exactly like the firmware anchors.
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

from tools.discovery.image import FunctionIndex, FunctionRecord
from tools.discovery.lifecycle import (ALIAS_MAY, CONFIRMED, MAY, PATH_DEPENDENT,
                                       Lifecycle)
from tools.discovery.memory import (CELL_APPROX, CELL_EXACT, CELL_NEVER_WRITTEN, CELL_TOP,
                                    MAX_CELL_VERSION, Addr, Affine, Memory, Obj, Ptr, Unknown)
from tools.discovery.ownership import (OwnershipCatalog, ROLE_ALLOC, ROLE_FREE)
from tools.discovery.patterns import Finding, FunctionView

FIXDIR = ROOT / "tests" / "fixtures" / "discovery"
FIXTURE = FIXDIR / "lifecycle-fixtures.json"


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
        code = self.read(rva, min(length, available))
        return list(md.disasm(code, rva)), md

    def executable_ranges(self):
        return [(self.base, self.base + len(self.data))]


@pytest.fixture(scope="module")
def env():
    doc = json.loads(FIXTURE.read_text(encoding="utf-8"))
    image = FixtureImage(doc)
    records = [
        FunctionRecord(int(meta["rva"], 16), int(meta["size"], 16), name)
        for name, meta in doc["symbols"].items()
    ]
    index = FunctionIndex(records)
    facts = {
        "anchors": {"free": doc["roots"]["free"], "malloc": doc["roots"]["alloc"]},
        "anchor_provenance": {"free": "fixture data root",
                              "malloc": "fixture data root"},
    }
    catalog = OwnershipCatalog(image, index, facts)
    return doc, image, index, catalog


def analyse(env, name: str) -> Lifecycle:
    _doc, image, index, catalog = env
    rec = index.by_name(name)
    assert rec is not None, name
    view = FunctionView(image, rec.rva, rec.size, name=rec.name, strict_cfg=True)
    run = Lifecycle(view, catalog)
    run.run()
    return run


def verdicts(run: Lifecycle):
    return [d.kind for d in run.defects]


# ------------------------------------------------------------------ fixture


def test_fixture_is_reproducible_and_pinned(env):
    doc, image, _index, _catalog = env
    assert image.sha256 == doc["image_sha256"]
    source = FIXDIR / doc["source"]
    assert hashlib.sha256(source.read_bytes()).hexdigest() == doc["source_sha256"]
    subprocess.run([sys.executable, str(FIXDIR / "gen_lifecycle.py"), "--check"], check=True)


# --------------------------------------------------------- catalog growth


def test_release_catalog_grows_only_through_call_shape(env):
    doc, _image, index, catalog = env
    free = index.by_name("own_free")
    alloc = index.by_name("own_alloc")
    assert catalog.entries[int(doc["roots"]["free"], 16)].source == "data_anchor"
    assert catalog.role_at(free.rva) == ROLE_FREE
    assert catalog.role_at(alloc.rva) == ROLE_ALLOC
    thunk = index.by_name("own_thunk")
    forward = index.by_name("own_forward")
    assert catalog.entries[thunk.rva].source == "thunk"
    assert catalog.entries[forward.rva].source in ("forward_call", "forward_tail")
    assert catalog.entries[forward.rva].chain, "a derived entry must keep its call site"
    bad = index.by_name("own_wrapper_bad")
    assert catalog.role_at(bad.rva) is None, "a replaced argument is not a forward"
    unknown = index.by_name("own_unknown")
    assert catalog.role_at(unknown.rva) is None


def test_catalog_reports_name_agreement_as_measurement_only(env):
    _doc, _image, _index, catalog = env
    stats = catalog.stats()
    agreement = stats["name_agreement"]
    assert agreement["structural_release_sites"] >= 1
    assert agreement["named_records"] == agreement["name_hinted_sites"] + (
        agreement["named_records"] - agreement["name_hinted_sites"])
    # the classifier consumes RVAs only: an entry's role never comes from a name
    source = (ROOT / "tools" / "discovery" / "lifecycle.py").read_text(encoding="utf-8")
    for token in ("RELEASE_NAME_HINTS", "rec.name", ".by_name("):
        assert token not in source, f"name-derived input {token!r} leaked into the detector"


# -------------------------------------------------------------------- D1


def test_release_then_use_is_confirmed(env):
    run = analyse(env, "fixture_d1_direct")
    assert verdicts(run) == [CONFIRMED]
    defect = run.defects[0]
    assert defect.confirmed
    assert defect.release_site < defect.use_site
    assert defect.obj.kind == "arg"
    assert defect.use_kind == "read"
    assert defect.carrier in ("rax", "rdx")
    assert defect.identity_class in ("DIRECT", "SAME_SLOT")


def test_invalidated_reference_is_safe(env):
    run = analyse(env, "fixture_d1_invalidated")
    assert run.defects == []
    assert run.releases, "the release itself must still be seen"


def test_stack_slot_reuse_is_not_a_use_after_release(env):
    run = analyse(env, "fixture_d1_slot_reuse")
    assert run.defects == [], "a reused slot holds a different object"
    versions = [cell.version for state in run.out_states.values()
                for cell in state.mem.cells.values()]
    assert max(versions) >= 1, "the slot must have been written twice"


def test_two_aliases_of_one_object_are_the_same_object(env):
    run = analyse(env, "fixture_d1_alias")
    assert verdicts(run) == [CONFIRMED]
    assert run.defects[0].carrier == "r12"


def test_release_on_one_path_only_is_not_confirmed(env):
    run = analyse(env, "fixture_d1_path")
    assert verdicts(run) == [PATH_DEPENDENT]
    assert run.defects[0].confirmed is False
    assert run.defects[0].detail["object_state"] == "MAY_RELEASED"


def test_unknown_call_effect_never_becomes_a_finding(env):
    """An unknown call may free its argument -- that is not evidence that it did.

    The run must produce no confirmed and no may finding, and the escape must be
    visible as evidence rather than as a claim.
    """
    run = analyse(env, "fixture_d1_unknown_effect")
    assert run.defects == []
    assert run.defect_stats()["releases"] == 0
    assert any(note[1] == "CALL_UNKNOWN" for st in run.out_states.values()
               for note in st.timeline), "the unknown effect must still be recorded"


def test_indirect_call_through_a_field_is_analysed(env):
    """An indirect call target comes from memory; the analysis must not raise."""
    run = analyse(env, "fixture_indirect_call")
    assert verdicts(run) == [CONFIRMED]
    assert any(note[1] == "CALL" for st in run.out_states.values() for note in st.timeline)


# -------------------------------------------------------------------- D4


@pytest.mark.parametrize("name", ["fixture_d4_same_index", "fixture_d4_lea_equal",
                                  "fixture_d4_shift_equal"])
def test_same_slot_through_different_index_expressions_is_confirmed(env, name):
    run = analyse(env, name)
    assert verdicts(run) == [CONFIRMED]
    assert run.defects[0].identity_class == "SAME_SLOT"


def test_different_index_is_only_a_may_alias(env):
    run = analyse(env, "fixture_d4_other_index")
    assert [d.confirmed for d in run.defects] == [False]
    assert verdicts(run) == [ALIAS_MAY]
    assert run.defects[0].identity_class == "MAY_ALIAS"
    assert run.defects[0].detail["released_slot"] != run.defects[0].detail["compared_slot"]
    assert run.defects[0].detail["index"]


def test_cleared_slot_is_safe(env):
    run = analyse(env, "fixture_d4_cleared")
    assert [d for d in run.defects if d.confirmed] == []
    assert not run.alias_defects()


def test_index_expressions_canonicalise_before_identity(env):
    shift = analyse(env, "fixture_d4_shift_equal")
    lea = analyse(env, "fixture_d4_lea_equal")
    plain = analyse(env, "fixture_d4_same_index")
    keys = {
        run.__class__.__name__: sorted(a.cell for a in run.accesses if a.indexed)
        for run in (shift, lea, plain)
    }
    assert keys["Lifecycle"]
    assert len({tuple(v) for v in keys.values()}) == 1, keys


def test_affine_equality_is_structural():
    index = Affine.sym("s:s1", 1)
    assert index.scale(8) == Affine.of(0).add(Affine.sym("s:s1", 4)).scale(2)
    assert index.scale(8) != Affine.sym("s:s2", 8)
    assert index.scale(8) != index.scale(4)


# ------------------------------------------------------------- integration


def test_defect_carries_the_required_evidence_fields(env):
    _doc, image, index, catalog = env
    rec = index.by_name("fixture_d1_direct")
    view = FunctionView(image, rec.rva, rec.size, name=rec.name, strict_cfg=True)
    run = Lifecycle(view, catalog)
    run.run()
    findings = run.findings()
    assert findings
    finding = findings[0]
    payload = finding.as_dict()
    assert payload["detector"] == "D1_use_after_release"
    assert payload["claims"]["object"]
    assert payload["claims"]["verdict"] == CONFIRMED
    assert payload["claims"]["identity_class"]
    assert payload["sites"] and len(payload["sites"]) == 2
    assert payload["window"]
    assert payload["counter_evidence"]["confirmed"] is True
    assert payload["falsification"]
    claims = payload["claims"]
    assert isinstance(claims["lifecycle_timeline"], list)
    assert claims["lifecycle_timeline"], "the object's own timeline must be attached"
    path = claims["path_conditions"]
    assert "blocks" in path and "branches" in path


def test_analysis_is_deterministic(env):
    first = analyse(env, "fixture_d4_other_index")
    second = analyse(env, "fixture_d4_other_index")
    assert [d.as_dict() for d in first.defects] == [d.as_dict() for d in second.defects]
    assert first.defect_stats() == second.defect_stats()


def test_release_events_record_the_source_slot(env):
    run = analyse(env, "fixture_d4_same_index")
    assert run.releases
    assert run.releases[0]["source_cell"], "the released object must name its slot"
    assert run.releases[0]["semantics"] == "definite"


# ------------------------------------------------- S1.2b counterexamples
#
# Every test below is a shape the baseline gets wrong.  The counterexamples were
# first run against the pinned baseline commit (an export of ``aeec7f4``, see the
# S1.2b evidence pack): the assertion in ``test_baseline_*`` documents what the
# old code did, the assertion in the fixture test documents what it must do.


def test_cell_states_never_collapse_into_each_other():
    """NEVER_WRITTEN, EXACT, APPROX and TOP must stay distinguishable."""
    slot = Addr("frame:rbp", Affine.of(-0x8))
    empty = Memory()
    assert empty.state_of(slot) == CELL_NEVER_WRITTEN
    empty.store(slot, frozenset({Ptr(Obj("arg", "0"))}))
    assert empty.state_of(slot) == CELL_EXACT
    assert empty.version(slot) == 0
    empty.store(slot, frozenset({Ptr(Obj("arg", "0"))}))
    assert empty.version(slot) == 1, "a second store is a new version, not the same one"
    for _ in range(MAX_CELL_VERSION + 2):
        empty.store(slot, frozenset({Unknown("x")}))
    assert empty.state_of(slot) == CELL_TOP, "a cell that keeps changing must widen"
    version_at_top = empty.version(slot)
    empty.store(slot, frozenset({Ptr(Obj("arg", "0"))}))
    assert empty.version(slot) == version_at_top, "top cells must stop versioning"


def test_merge_keeps_a_known_singleton_value():
    """P15: a merge that agrees on the value must not throw the value away."""
    slot = Addr("frame:rbp", Affine.of(-0x10))
    left, right = Memory(), Memory()
    left.store(slot, frozenset({Ptr(Obj("arg", "1"))}))
    right.store(slot, frozenset({Ptr(Obj("arg", "1"))}))
    right.store(slot, frozenset({Ptr(Obj("arg", "1"))}))
    merged = left.merge(right)
    assert merged.state_of(slot) == CELL_APPROX
    assert merged.load(slot) == frozenset({Ptr(Obj("arg", "1"))}), (
        "both arms agree, so the value is a must fact even though the versions differ"
    )


def test_widening_loses_identity_instead_of_forging_one():
    """A dropped cell must not look like a never-written slot."""
    slot = Addr("obj:arg:0", Affine.of(0x20))
    lost = Memory()
    lost.mark_lost("obj:arg:0")
    assert lost.is_lost(slot)
    assert isinstance(next(iter(lost.load(slot))), Unknown)


def test_p0_2_may_set_release_is_never_definite(env):
    """Baseline: both may-set members were marked *definite* and the use confirmed."""
    run = analyse(env, "fixture_p0_2_may_release")
    assert [d.kind for d in run.defects] == [PATH_DEPENDENT]
    assert [d.confirmed for d in run.defects] == [False]
    assert not any(r["treats_as_defect"] for r in run.releases)
    assert run.defects[0].detail["release_precondition"]
    assert run.defects[0].detail["object_state"] == "MAY_RELEASED"


def test_p0_1_merged_slot_is_a_may_set(env):
    """Baseline: the merged slot was one symbol, so the release looked definite."""
    run = analyse(env, "fixture_p0_1_approx_may_set")
    assert [d.confirmed for d in run.defects] == [False]
    assert run.defects[0].kind in (MAY, PATH_DEPENDENT)
    assert "2 objects" in run.defects[0].detail["release_precondition"]


def test_p0_1_never_written_and_merged_slots_stay_distinct(env):
    """A store kills the never-written identity: the reload is a different object."""
    run = analyse(env, "fixture_p0_1_never_vs_merged")
    assert run.defects == []
    assert run.releases and run.releases[0]["treats_as_defect"]
    assert f"{CELL_NEVER_WRITTEN}" in run.releases[0]["object"]


def test_p0_3_tail_jump_to_conditional_wrapper_is_not_definite(env):
    """Baseline: ``semantics: definite`` with no ``treats_as_defect`` at all."""
    run = analyse(env, "fixture_p0_3_tail_cond")
    assert run.defects == []
    assert len(run.releases) == 1
    record = run.releases[0]
    assert record["via"] == "tail_jump"
    assert record["semantics"] == "conditional"
    assert record["release_kind"] == "conditional_free"
    assert record["treats_as_defect"] is False
    assert record["precondition"], "an unproven release must state its precondition"


def test_p0_3_conditional_wrapper_call_is_an_observation(env):
    """Baseline: the computed flag was dead code, so this produced *nothing*."""
    run = analyse(env, "fixture_p0_3_cond_caller")
    assert len(run.defects) == 1
    defect = run.defects[0]
    assert defect.confirmed is False
    assert defect.kind == PATH_DEPENDENT
    assert hex(int(run.releases[0]["callee"])) in defect.detail["release_precondition"]
    assert run.observations(), "an unproven release is an observation, not silence"


def test_p0_4_loop_carried_release_is_reported(env):
    """Baseline: the ordering guard dropped it (release address > use address)."""
    run = analyse(env, "fixture_p0_4_loop_carried")
    assert len(run.defects) == 1
    defect = run.defects[0]
    assert defect.confirmed is False
    assert defect.kind == MAY
    assert defect.release_site > defect.use_site, "the witness must come from the cycle"
    assert defect.detail["ordering"] in ("loop_carried", "cfg_path")


def test_p0_4_recycled_call_site_keeps_distinct_identities(env):
    """Baseline: 3077 release records from one call site and a *confirmed* defect."""
    run = analyse(env, "fixture_p0_4_loop_recycle")
    assert not [d for d in run.defects if d.confirmed]
    assert len(run.releases) <= 10, "records must be deduplicated, not multiplied"
    assert run.defect_stats()["release_events"] > len(run.releases)
    identities = {r["object"] for r in run.releases if r["object"].startswith("alloc:")}
    assert len(identities) > 1, "two iterations must not share one allocation identity"


def test_p1_store_kill_clears_the_released_identity(env):
    """The store after the release is a kill: the reload is a different object."""
    run = analyse(env, "fixture_p1_store_kill")
    assert run.defects == []
    assert run.observations() == []
    assert run.releases and run.releases[0]["treats_as_defect"]


def test_p1_outparam_keeps_the_stored_object_as_a_candidate(env):
    """Baseline: the out-parameter write destroyed the stored pointer's identity."""
    run = analyse(env, "fixture_p1_outparam")
    assert [d.confirmed for d in run.defects] == [False]
    assert run.defects[0].kind in (MAY, PATH_DEPENDENT)
    assert run.observations(), "losing an identity must not be silent"


def test_disagreeing_merge_arms_are_not_a_must_value():
    slot = Addr("frame:rbp", Affine.of(-0x8))
    left, right = Memory(), Memory()
    left.store(slot, frozenset({Ptr(Obj("arg", "0"))}))
    right.store(slot, frozenset({Ptr(Obj("arg", "1"))}))
    merged = left.merge(right)
    assert merged.state_of(slot) == CELL_APPROX
    assert merged.load(slot) != frozenset({Ptr(Obj("arg", "0"))}), (
        "disagreeing arms must not keep one arm's value as a must fact"
    )


def test_d1_d4_confirmations_are_untrusted_until_acceptance():
    """Until the repair is accepted D1/D4 must not reach a report as confirmed."""
    from tools.discovery import patterns

    assert patterns.D1_D4_TRUSTED is False
    finding = Finding(detector="D1_use_after_release", bug_class="OWNERSHIP_UAF",
                      function_rva=0x1000, function_size=0x40, function_name="f",
                      site_rvas=(0x1010, 0x1020), slot=None, rank=1)
    stamped = patterns._stamp_trust([finding])
    assert stamped[0].counter_evidence["trust"] == patterns.UNTRUSTED_MARK
    assert stamped[0].rank == 3, "demoted below the queue admission rank"
