"""S1.6 interprocedural summaries: object-keyed effects, refusals and two-hop composition.

The fixture image is produced by real binutils and decoded through the same capstone path as the
firmware. The only thing handed in as data is the release anchor, exactly like a firmware anchor;
no fixture *name* reaches the analysis.

Each test is named after the defect it forbids.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from tools.discovery import summaries
from tools.discovery.image import FunctionIndex, FunctionRecord

FIXDIR = ROOT / "tests" / "fixtures" / "discovery"
FIXTURE = FIXDIR / "summary-fixtures.json"
GENERATOR = FIXDIR / "gen_summaries.py"


class FixtureImage:
    def __init__(self, doc: dict):
        self.base = int(doc["base_rva"], 16)
        self.data = bytes.fromhex(doc["image_hex"])
        self.size = self.base + len(self.data)
        self.sha256 = hashlib.sha256(self.data).hexdigest()

    def read(self, rva: int, length: int) -> bytes:
        return self.data[rva - self.base: rva - self.base + length]

    def disasm(self, rva: int, length: int, instructions: bool = True):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = bool(instructions)
        available = max(0, len(self.data) - (rva - self.base))
        return list(md.disasm(self.read(rva, min(length, available)), rva)), md

    def executable_ranges(self):
        return [(self.base, self.base + len(self.data))]


@pytest.fixture(scope="module")
def env():
    doc = json.loads(FIXTURE.read_text(encoding="utf-8"))
    image = FixtureImage(doc)
    index = FunctionIndex(
        [FunctionRecord(int(meta["rva"], 16), int(meta["size"], 16), name)
         for name, meta in doc["symbols"].items()]
    )
    release_rvas = {int(doc["symbols"][name]["rva"], 16) for name in doc["release_roots"]}

    def is_release(target) -> bool:
        return int(target) in release_rvas

    store = summaries.SummaryStore(image, index, is_release)
    return doc, image, index, store


def summarize(env, name: str):
    doc, _image, index, store = env
    record = index.by_name(name)
    assert record is not None, f"fixture symbol missing: {name}"
    return store.get(record.rva)


def call_site_in(env, name: str, callee: str) -> int:
    """Address of the first direct call to ``callee`` inside ``name``."""
    from tools.discovery.patterns import FunctionView

    doc, image, index, _store = env
    own = index.by_name(name)
    target = index.by_name(callee)
    view = FunctionView(image, own.rva, own.size)
    for site, rva in sorted(view.calls.items()):
        if rva == target.rva:
            return site
    raise AssertionError(f"{name} does not call {callee}")


def test_fixture_matches_generator():
    """The committed image is exactly what the generator produces (no drift)."""
    before = FIXTURE.read_text(encoding="utf-8")
    result = subprocess.run([sys.executable, str(GENERATOR), "--check"],
                            cwd=str(ROOT), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert FIXTURE.read_text(encoding="utf-8") == before


def test_a_summary_names_every_argument_it_reads_with_field_and_width(env):
    summary = summarize(env, "callee_deref")
    effect = summary.param(0)
    assert effect.role in ("READ", "DEREF")
    assert [(read.offset, read.width) for read in effect.reads] == [(0x10, 4)]
    assert effect.postcondition == summaries.LIVE


def test_two_parameters_at_the_same_offset_are_different_effects(env):
    summary = summarize(env, "callee_two_args_same_field")
    first, second = summary.param(0), summary.param(1)
    assert {read.offset for read in first.reads} == {0x10}
    assert {read.offset for read in second.reads} == {0x10}
    assert (first.register, second.register) == ("rdi", "rsi")


def test_a_lock_xadd_drop_with_a_count_test_is_guarded(env):
    effect = summarize(env, "callee_drop_guarded").param(0)
    assert effect.drops_must == 1
    assert effect.refcount_field == 0x28
    assert effect.guard == "proven", effect.guard_reason
    assert effect.ownership in (summaries.OWN_DROP_REF, summaries.OWN_FREE)


def test_an_unguarded_drop_is_not_reported_as_protected(env):
    effect = summarize(env, "callee_drop_unguarded").param(0)
    assert effect.drops_must == 1
    assert effect.guard == "unknown"
    assert "no comparison" in effect.guard_reason


def test_a_positive_xadd_is_a_take_not_a_drop(env):
    effect = summarize(env, "callee_take").param(0)
    assert effect.takes == 1
    assert effect.drops_must == 0 and effect.drops_may == 0


def test_a_release_on_one_arm_is_conditional(env):
    effect = summarize(env, "callee_conditional_free").param(0)
    assert effect.drops_may == 1
    assert effect.drops_must == 0
    assert effect.release_conditional is True
    assert effect.postcondition == summaries.MAY_RELEASED


def test_a_global_store_is_an_escape_not_a_release(env):
    effect = summarize(env, "callee_escape_global").param(0)
    assert effect.escape == summaries.ESCAPE_GLOBAL
    assert effect.ownership == summaries.OWN_NONE
    assert effect.postcondition == summaries.LIVE
    assert "global" in effect.escape_detail


def test_a_returned_argument_is_an_alias_not_a_new_object(env):
    summary = summarize(env, "callee_return_arg")
    assert summary.returns.kind == summaries.RET_ARG_ALIAS
    assert summary.returns.arg_index == 0
    assert summary.returns.owned is False


def test_a_returned_field_is_not_an_alias(env):
    summary = summarize(env, "callee_return_field")
    assert summary.returns.kind == summaries.RET_FIELD_LOAD
    assert summary.returns.field_offset == 0x8
    assert summary.returns.owned is None, "a field load is a different object, not an alias"


def test_a_returned_callee_result_does_not_claim_ownership(env):
    summary = summarize(env, "callee_return_alloc")
    assert summary.returns.kind == summaries.RET_NEW_OBJECT
    assert summary.returns.owned is None, (
        "a callee result carries an owned reference only if the callee says so")


def test_an_interior_pointer_keeps_the_base_object(env):
    effect = summarize(env, "callee_lea_interior").param(0)
    assert {read.offset for read in effect.reads} == {0x10}, (
        "a read through lea rdi+0x10 belongs to argument 0, not to a synthetic object")


def test_an_indirect_call_refuses_every_postcondition(env):
    summary = summarize(env, "callee_indirect")
    assert summary.status == summaries.PARTIAL
    assert summary.refusal["code"] == "indirect_only"
    assert summary.indirect_calls == 1
    assert all(effect.postcondition == summaries.UNKNOWN for effect in summary.params)


def test_the_nearest_write_to_an_argument_register_decides_the_placement(env):
    from tools.discovery.patterns import FunctionView

    doc, image, index, store = env
    record = index.by_name("caller_redefined_arg")
    view = FunctionView(image, record.rva, record.size)
    site = call_site_in(env, "caller_redefined_arg", "callee_deref")
    callee_summary = store.get(index.by_name("callee_deref").rva)
    stale = summaries.hop_at(view, site, "rax", callee_summary)
    fresh = summaries.hop_at(view, site, "rcx", callee_summary)
    assert stale.placement == summaries.REFUTED
    assert fresh.placement == summaries.PROVEN
    assert fresh.argument == "rdi"


def test_a_subregister_write_cannot_prove_full_pointer_identity(env):
    from tools.discovery.patterns import FunctionView

    doc, image, index, store = env
    record = index.by_name("caller_subregister")
    view = FunctionView(image, record.rva, record.size)
    site = call_site_in(env, "caller_subregister", "callee_deref")
    hop = summaries.hop_at(view, site, "rax", store.get(index.by_name("callee_deref").rva))
    assert hop.placement == summaries.UNKNOWN
    assert hop.status == summaries.UNKNOWN


def test_an_interior_pointer_requires_separate_object_identity_proof(env):
    from tools.discovery.patterns import FunctionView

    doc, image, index, store = env
    record = index.by_name("caller_lea_arg")
    view = FunctionView(image, record.rva, record.size)
    site = call_site_in(env, "caller_lea_arg", "callee_deref")
    hop = summaries.hop_at(view, site, "rax", store.get(index.by_name("callee_deref").rva))
    assert hop.placement == summaries.UNKNOWN
    assert hop.status == summaries.UNKNOWN


def test_a_call_without_argument_setup_proves_nothing(env):
    from tools.discovery.patterns import FunctionView

    doc, image, index, store = env
    record = index.by_name("caller_no_setup")
    view = FunctionView(image, record.rva, record.size)
    site = call_site_in(env, "caller_no_setup", "callee_deref")
    hop = summaries.hop_at(view, site, "rax", store.get(index.by_name("callee_deref").rva))
    assert hop.placement == summaries.UNKNOWN
    assert hop.status == summaries.UNKNOWN
    assert hop.status != "possible", "a summary hop must never publish a synthetic 'possible'"


def test_a_complete_callee_that_only_reads_the_argument_refutes_a_transfer(env):
    from tools.discovery.patterns import FunctionView

    doc, image, index, store = env
    record = index.by_name("caller_hop_negative")
    view = FunctionView(image, record.rva, record.size)
    site = call_site_in(env, "caller_hop_negative", "callee_deref")
    hop = summaries.hop_at(view, site, "rax", store.get(index.by_name("callee_deref").rva))
    assert hop.placement == summaries.PROVEN
    assert hop.status == summaries.REFUTED
    assert "not a transfer" in hop.why


def test_a_returned_alias_composes_into_a_two_hop_ownership_proof(env):
    effect = summarize(env, "caller_return_alias_chain").param(0)
    assert effect.drops_must == 1, (
        "the callee returns its own argument, so the forwarded drop belongs to parameter 0")
    assert effect.ownership in (summaries.OWN_DROP_REF, summaries.OWN_FREE)


def test_a_returned_field_does_not_compose_into_ownership(env):
    effect = summarize(env, "caller_return_field_chain").param(0)
    assert effect.drops_must == 0 and effect.drops_may == 0, (
        "the forwarded object came from a field load: it is not parameter 0")


def test_an_escaping_argument_keeps_the_object_live(env):
    effect = summarize(env, "caller_escape").param(0)
    assert effect.escape != summaries.ESCAPE_NONE
    assert effect.postcondition == summaries.LIVE


def test_a_release_on_a_field_pointer_belongs_to_the_field_object(env):
    summary = summarize(env, "callee_drop_field_pointer")
    field_object = summary.object(("arg", 0, (0x30,)))
    assert field_object.ownership == summaries.OWN_FREE
    assert field_object.ownership_strength == "must"
    assert field_object.label == "arg0+0x30"
    assert len(field_object.release_sites) == 1
    container = summary.param(0)
    assert container.postcondition == summaries.LIVE, (
        "the container argument is not the object that was released")
    assert container.ownership == summaries.OWN_NONE


def test_two_drops_on_one_field_object_are_a_double_release_shape(env):
    from tools.discovery.patterns import FunctionView

    doc, image, index, store = env
    record = index.by_name("callee_double_drop_field")
    view = FunctionView(image, record.rva, record.size)
    summary = store.get(record.rva)
    defects = summaries.sequential_double_releases(view, summary)
    assert defects, "two releases on arg0+0x30 must be reported"
    assert defects[0]["param"] == 0
    assert "arg0+0x30" in defects[0]["why"]


def test_two_different_field_objects_are_not_a_double_release(env):
    from tools.discovery.patterns import FunctionView

    doc, image, index, store = env
    record = index.by_name("callee_two_fields_one_drop_each")
    view = FunctionView(image, record.rva, record.size)
    summary = store.get(record.rva)
    assert summaries.sequential_double_releases(view, summary) == [], (
        "arg0+0x30 and arg0+0x38 are different objects; merging them is a false positive")
    assert summary.object(("arg", 0, (0x30,))).ownership == summaries.OWN_FREE
    assert summary.object(("arg", 0, (0x38,))).ownership == summaries.OWN_FREE


def test_a_release_through_a_global_pointer_belongs_to_the_global_object(env):
    summary = summarize(env, "callee_drop_global_pointer")
    globals_ = [effect for effect in summary.field_objects if effect.key[:1] == ("glob",)]
    assert globals_, "a drop on a pointer stored in a global must be attributed to that global"
    released = globals_[0]
    assert released.ownership == summaries.OWN_FREE
    assert released.ownership_strength == "must"
    assert released.label.startswith("glob")
    assert summary.param(0).ownership == summaries.OWN_NONE, (
        "argument 0 is not the released object; inheriting the global's life cycle would be a "
        "false attribution")


def test_two_drops_of_one_global_object_are_a_double_release_shape(env):
    from tools.discovery.patterns import FunctionView

    doc, image, index, store = env
    record = index.by_name("callee_double_drop_global")
    view = FunctionView(image, record.rva, record.size)
    summary = store.get(record.rva)
    defects = summaries.sequential_double_releases(view, summary)
    assert defects, "two releases of the same global pointer must be reported"
    assert defects[0]["why"].startswith("two reference-consuming sites on object glob")


def test_a_hop_into_a_consuming_callee_is_proved_with_two_witnesses(env):
    from tools.discovery.patterns import FunctionView

    doc, image, index, store = env
    record = index.by_name("caller_hop_positive")
    view = FunctionView(image, record.rva, record.size)
    site = call_site_in(env, "caller_hop_positive", "callee_drop_unguarded")
    hop = summaries.hop_at(view, site, "rax",
                           store.get(index.by_name("callee_drop_unguarded").rva))
    assert hop.status == summaries.PROVEN
    kinds = {witness_kind for witness in hop.witnesses for witness_kind in witness}
    assert kinds == {"caller", "callee"}, (
        "a proved hop needs a caller-side placement and a callee-side release, not one of them")
    assert hop.ownership in (summaries.OWN_DROP_REF, summaries.OWN_FREE)


def test_the_control_hop_into_a_reading_callee_is_refuted(env):
    from tools.discovery.patterns import FunctionView

    doc, image, index, store = env
    record = index.by_name("caller_hop_negative")
    view = FunctionView(image, record.rva, record.size)
    site = call_site_in(env, "caller_hop_negative", "callee_deref")
    hop = summaries.hop_at(view, site, "rax", store.get(index.by_name("callee_deref").rva))
    assert hop.status == summaries.REFUTED
    assert hop.placement == summaries.PROVEN


def test_a_path_conditional_consumption_is_conditional_not_unknown(env):
    from tools.discovery.patterns import FunctionView

    doc, image, index, store = env
    record = index.by_name("caller_hop_conditional")
    view = FunctionView(image, record.rva, record.size)
    site = call_site_in(env, "caller_hop_conditional", "callee_conditional_free")
    hop = summaries.hop_at(view, site, "rax",
                           store.get(index.by_name("callee_conditional_free").rva))
    assert hop.status == summaries.CONDITIONAL, (
        "a release that runs on one path is a witnessed transfer, not an unknown")
    assert hop.placement == summaries.PROVEN
    kinds = {witness_kind for witness in hop.witnesses for witness_kind in witness}
    assert kinds == {"caller", "callee"}
    assert "path only" in hop.why


# --------------------------------------------------------- S1.7 indexed object identity


def test_an_indexed_slot_is_its_own_object_with_a_table_and_index_identity(env):
    summary = summarize(env, "callee_index_drop")
    slots = [effect for effect in summary.field_objects if effect.key[:1] == ("tab",)]
    assert slots, "the released slot must be an object of its own"
    slot = slots[0]
    assert slot.ownership == summaries.OWN_FREE
    assert "arg1" in slot.label and "*8" in slot.label, (
        f"the identity has to name the index provenance and the scale, got {slot.label}")


def test_the_same_slot_indexed_twice_is_the_same_object(env):
    from tools.discovery.patterns import FunctionView

    doc, image, index, store = env
    record = index.by_name("callee_index_double_drop")
    view = FunctionView(image, record.rva, record.size)
    summary = store.get(record.rva)
    defects = summaries.sequential_double_releases(view, summary)
    assert defects, "the same slot released twice is a double-release shape"
    assert "tab" in defects[0]["why"]


def test_two_different_indices_are_not_a_double_release(env):
    from tools.discovery.patterns import FunctionView

    doc, image, index, store = env
    record = index.by_name("callee_index_two_indices")
    view = FunctionView(image, record.rva, record.size)
    summary = store.get(record.rva)
    assert summaries.sequential_double_releases(view, summary) == [], (
        "index rcx and index rdx select different slots; merging them is a fabricated double free")


def test_a_store_into_the_slot_creates_a_new_generation(env):
    from tools.discovery.patterns import FunctionView

    doc, image, index, store = env
    record = index.by_name("callee_index_reallocated")
    view = FunctionView(image, record.rva, record.size)
    summary = store.get(record.rva)
    assert summaries.sequential_double_releases(view, summary) == [], (
        "after the slot is overwritten the object is a different generation")


def test_an_index_reloaded_from_memory_claims_no_identity(env):
    from tools.discovery.patterns import FunctionView

    doc, image, index, store = env
    record = index.by_name("callee_index_unknown_index")
    view = FunctionView(image, record.rva, record.size)
    summary = store.get(record.rva)
    assert summaries.sequential_double_releases(view, summary) == [], (
        "an index without provenance cannot establish identity")
    assert not [e for e in summary.field_objects if e.key[:1] == ("tab",)], (
        "no table key may be produced from an unresolvable index")


def test_a_body_with_unresolved_object_accesses_cannot_refute_ownership(env):
    """A complete walk that refused an object access may hide a consumption."""
    summary = summarize(env, "callee_index_unknown_index")
    record = {"status": summary.status, "refusal": summary.refusal,
              "flows": [], "unresolved_accesses": summary.analysis.get("unresolved_accesses", 0)}
    dimension = __import__("tools.discovery.chains", fromlist=["chains"]) \
        .ownership_summary_dimension({"summary": record})
    assert summary.status == "complete"
    assert record["unresolved_accesses"] > 0, (
        "the fixture must exercise an unresolved object access")
    assert dimension["verdict"] == "UNKNOWN", (
        "without a counter-argument an unresolved access cannot support REFUTED")


def _double_releases(env, name):
    from tools.discovery.patterns import FunctionView

    doc, image, index, store = env
    record = index.by_name(name)
    view = FunctionView(image, record.rva, record.size)
    return summaries.sequential_double_releases(view, store.get(record.rva))


def test_a_masked_index_is_a_provenance(env):
    assert _double_releases(env, "callee_index_masked"), (
        "i & 0xff twice is the same expression and therefore the same slot")


def test_a_mask_over_another_input_is_a_different_slot(env):
    assert _double_releases(env, "callee_index_masked_other_input") == [], (
        "esi & 0xff and edx & 0xff are different expressions")


def test_a_sign_extended_shifted_index_is_a_provenance(env):
    assert _double_releases(env, "callee_index_struct_scaled"), (
        "sign-extension and a shift are part of the index expression")


def test_a_different_stride_is_a_different_slot(env):
    assert _double_releases(env, "callee_index_struct_other_stride") == [], (
        "shift 4 and shift 5 address different records")


# ------------------------------------------------- S1.8 base provenance across joins


def _release_effects(env, name):
    summary = summarize(env, name)
    return [effect for effect in summary.params
            if effect.ownership in (summaries.OWN_DROP_REF, summaries.OWN_FREE)]


def test_an_object_known_on_one_path_is_attributed_as_may(env):
    effects = _release_effects(env, "callee_may_release_in_loop")
    assert effects, "the object is known on the path that loads it; refusing it hides a real flow"
    effect = effects[0]
    assert effect.ownership_strength == "may", (
        "a value that survives only one predecessor may not be claimed as must")
    assert effect.ownership_site or effect.release_sites


def test_two_possible_objects_claim_no_identity(env):
    effects = _release_effects(env, "callee_may_two_objects")
    assert effects == [], (
        "the register may hold either field; claiming one of them is a fabricated identity")


def test_a_clobbered_register_claims_no_identity(env):
    assert _release_effects(env, "callee_clobbered_by_call") == [], (
        "an indirect call clobbers the argument register; nothing may be attributed afterwards")


def test_summaries_are_memoised_and_the_digest_is_stable(env):
    _doc, _image, index, store = env
    record = index.by_name("callee_drop_guarded")
    first = store.get(record.rva)
    digest = store.digest()
    second = store.get(record.rva)
    assert first is second or first.as_dict() == second.as_dict()
    assert store.stats()["cache_hits"] >= 1
    assert store.digest() == digest


def test_a_refused_callee_never_promotes_a_hop(env):
    from tools.discovery.patterns import FunctionView

    doc, image, index, store = env
    record = index.by_name("caller_lea_arg")
    view = FunctionView(image, record.rva, record.size)
    site = call_site_in(env, "caller_lea_arg", "callee_deref")
    hop = summaries.hop_at(view, site, "rax", store.get(index.by_name("callee_indirect").rva))
    assert hop.status == summaries.UNKNOWN
    assert hop.summary_status in (summaries.PARTIAL, summaries.REFUSED)


def test_no_address_literals_or_target_constants_in_the_summary_module():
    """The layer must not carry firmware-specific constants; a literal is a hidden oracle."""
    source = (ROOT / "tools" / "discovery" / "summaries.py").read_text(encoding="utf-8")
    offenders = [match.group(0) for match in
                 re.finditer(r"0x[0-9a-fA-F]{3,}", source)]
    offenders = [value for value in offenders if value not in ("0x10",)]
    assert not offenders, f"address-like literals in summaries.py: {offenders}"
