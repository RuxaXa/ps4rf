"""A1 review regressions: reproducible counterexamples for the audited defects.

The independent audit A1 (`1328aa5`) reproduced five logic defects and named two
further design risks.  Each test below is the audit's own counterexample, kept as a
permanent regression: the defect, not the desired output, is what used to pass.

Nothing here is a claim about a PlayStation kernel.  These are statements about the
analysis engine, proven on a fixture image assembled by real binutils.
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

from tools.discovery import chains as chains_mod
from tools.discovery import handles, queue, semgraph

FIXDIR = ROOT / "tests" / "fixtures" / "discovery"
FIXTURE = FIXDIR / "a1-regressions.json"
GENERATOR = FIXDIR / "gen_a1_regressions.py"


class FixtureImage:
    """Minimal image view over a flat RVA==offset blob."""

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
def fixture_doc():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def fixture_image(fixture_doc):
    return FixtureImage(fixture_doc)


def instructions_of(doc, image, name):
    rva = int(doc["symbols"][name]["rva"], 16)
    size = int(doc["symbols"][name]["size"], 16)
    ins, _md = image.disasm(rva, size)
    return ins


def test_fixture_matches_generator():
    """The committed image is exactly what the generator produces (no drift)."""
    before = FIXTURE.read_text(encoding="utf-8")
    result = subprocess.run([sys.executable, str(GENERATOR), "--check"],
                            cwd=str(ROOT), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert FIXTURE.read_text(encoding="utf-8") == before


# ---------------------------------------------------------------- A1-04: the guard


def test_unrelated_compare_never_proves_a_refcount_guard(fixture_doc, fixture_image):
    """A1-04: `cmp eax, 0x10` is not a reference-count guard.

    The old code set `guarded=True` whenever the character "1" appeared in the
    operands of any `cmp` in the next eight instructions, so this exact shape --
    decrement, unrelated compare, release call -- was reported as protected.
    """
    ins = instructions_of(fixture_doc, fixture_image, "guard_unrelated_cmp")
    dec_idx = next(i for i, x in enumerate(ins) if "dec" in x.mnemonic)
    release_idx = next(i for i, x in enumerate(ins) if x.mnemonic == "call")
    state, reason, site = handles.guard_proof(
        ins, dec_idx, release_idx, ins[release_idx].address, 0x28, "rdi")
    assert state == "unknown", f"an unrelated compare must not prove a guard: {reason}"
    assert site == 0
    assert "unrelated" in reason


def test_count_compare_with_a_consuming_branch_is_a_proven_guard(fixture_doc, fixture_image):
    """The positive control: the same detector must still find a real guard."""
    ins = instructions_of(fixture_doc, fixture_image, "guard_equal_one")
    dec_idx = next(i for i, x in enumerate(ins) if "dec" in x.mnemonic)
    release_idx = next(i for i, x in enumerate(ins) if x.mnemonic == "call")
    state, reason, site = handles.guard_proof(
        ins, dec_idx, release_idx, ins[release_idx].address, 0x28, "rdi")
    assert state == "proven", reason
    assert site == ins[next(i for i, x in enumerate(ins) if x.mnemonic == "jne")].address


def test_count_compare_without_a_branch_is_not_a_guard(fixture_doc, fixture_image):
    """A compare whose flags nobody consumes gates nothing."""
    ins = instructions_of(fixture_doc, fixture_image, "guard_no_branch")
    dec_idx = next(i for i, x in enumerate(ins) if "dec" in x.mnemonic)
    release_idx = next(i for i, x in enumerate(ins) if x.mnemonic == "call")
    state, reason, _site = handles.guard_proof(
        ins, dec_idx, release_idx, ins[release_idx].address, 0x28, "rdi")
    assert state == "unknown", reason


class _View:
    """Release-shape view over one decoded function, with an explicit call map."""

    def __init__(self, ins, calls):
        self.ins = ins
        self.calls = calls


def test_release_shape_reports_unknown_guard_instead_of_protected(
        fixture_doc, fixture_image):
    """A1-04 through the producer: `Drop.guarded` may not be invented."""
    ins = instructions_of(fixture_doc, fixture_image, "guard_unrelated_cmp")
    call = next(x for x in ins if x.mnemonic == "call")
    release_rva = int(call.op_str, 16)
    view = _View(ins, {call.address: release_rva})
    shape = handles.release_shape(view, lambda target: target == release_rva)
    assert len(shape.drops) == 1
    drop = shape.drops[0]
    assert drop.guarded is False, drop.guard_reason
    assert drop.guard_state == "unknown"
    assert drop.guard_reason


def test_release_shape_still_recognises_a_real_guard(fixture_doc, fixture_image):
    ins = instructions_of(fixture_doc, fixture_image, "guard_equal_one")
    call = next(x for x in ins if x.mnemonic == "call")
    release_rva = int(call.op_str, 16)
    view = _View(ins, {call.address: release_rva})
    shape = handles.release_shape(view, lambda target: target == release_rva)
    assert [d.guard_state for d in shape.drops] == ["proven"]


# ------------------------------------------------------------- A1-05: store summary


def test_plain_mov_store_is_summarised_and_a_load_is_not(fixture_doc, fixture_image):
    """A1-05: every `mov` hit `continue` before the store branch was reached.

    The counterexample is `mov dword ptr [rdi+0x10], eax`: the old summary stayed
    empty.  The companion load must not be booked as a write at its offset.
    """
    rva = int(fixture_doc["symbols"]["store_vs_load"]["rva"], 16)
    size = int(fixture_doc["symbols"]["store_vs_load"]["size"], 16)
    summary = handles.summarize(fixture_image, rva, size)
    assert summary.stores == {0x10: {4}}, summary.stores
    assert 0x20 not in summary.stores, "a load is not a store"


# ------------------------------------------------------- helper: synthetic graph


def _function_node(rva: int, subsystem: str = "") -> str:
    return f"function:{rva}"


def _witness(site: str, kind: str, text: str) -> dict:
    return {"site": site, "kind": kind, "text": text}


def _primitive(rva: str = "0x200", rank: int = 1) -> dict:
    return {"detector": "D2_double_release", "rank": rank,
            "bug_class": "OWNERSHIP_DOUBLE_FREE", "function": {"rva": rva}}


# --------------------------------------------------- A1-01: strongest entry path


def test_a_possible_summary_hop_does_not_eclipse_a_proved_concrete_path():
    """A1-01: one-hop `possible` beats two-hop `proved` when only length is ranked.

    Shape: an entry that summarises reachability of the primitive with a synthetic
    `reaches` hop whose status is `possible`, plus a concrete entry -> helper ->
    primitive route where every hop is proved.  The old walk stopped at the first
    entry it met, i.e. the shortest hop count, and reported "possible" while the
    proved route existed in the same graph.
    """
    g = semgraph.Graph()
    g.node("entry:sysent[7]", "entry")
    g.node("function:0x40", "function")
    g.node("function:0x20", "function")
    g.edge("entry:sysent[7]", "function:0x20", "reaches",
           {"site": "0x20", "kind": "entry-attribution", "text": "entry may reach 0x20"},
           status=semgraph.POSSIBLE)
    g.edge("entry:sysent[7]", "function:0x40", "reaches",
           {"site": "0x40", "kind": "entry-attribution", "text": "entry reaches 0x40"})
    g.edge("function:0x40", "function:0x20", "calls",
           {"site": "0x44", "kind": "call", "text": "call 0x20"}, status=semgraph.PROVED)
    scan = {"findings": [_primitive("0x20")]}
    out = semgraph.chains(g.export(), scan, facts={})
    chain = out["chains"][0]
    assert chain["hop_status"] == "proved", chain["hops"]
    assert chain["hop_count"] == 2
    assert [h["kind"] for h in chain["hops"]] == ["reaches", "calls"]
    # the weaker route is reported, not silently dropped
    alternatives = chain["path_selection"]["alternatives"]
    assert [a["hop_status"] for a in alternatives] == ["possible"]
    assert alternatives[0]["hop_count"] == 1
    assert chain["path_selection"]["paths_considered"] >= 2


def test_chain_path_selection_is_stable_under_edge_order():
    g = semgraph.Graph()
    g.node("entry:sysent[7]", "entry")
    g.node("entry:cdevsw[3]", "entry")
    g.node("function:0x20", "function")
    g.edge("entry:sysent[7]", "function:0x20", "reaches",
           {"site": "0x20", "kind": "entry-attribution", "text": "entry reaches 0x20"},
           status=semgraph.POSSIBLE)
    g.edge("entry:cdevsw[3]", "function:0x20", "reaches",
           {"site": "0x22", "kind": "entry-attribution", "text": "entry reaches 0x20"},
           status=semgraph.PROVED)
    scan = {"findings": [_primitive("0x20")]}
    forward = semgraph.chains(g.export(), scan, facts={})["chains"][0]
    shuffled = dict(g.export())
    shuffled["edges"] = list(reversed(shuffled["edges"]))
    backward = semgraph.chains(shuffled, scan, facts={})["chains"][0]
    assert forward["entry"] == backward["entry"] == "entry:cdevsw[3]"
    assert forward["path_selection"]["alternatives"] == \
        backward["path_selection"]["alternatives"]


# ------------------------------------------- A1-06: transfer-reference provenance


def test_argument_register_hand_off_proves_a_transfer(fixture_doc, fixture_image):
    ins = instructions_of(fixture_doc, fixture_image, "pass_in_arg")
    call = next(x for x in ins if x.mnemonic == "call")
    assert semgraph._argument_carries(ins, call.address, "rax") is True


def test_a_register_the_call_never_receives_proves_nothing(fixture_doc, fixture_image):
    """A1-06: "the callee drops a reference" is not "the callee drops *this* object".

    `mov rbx, rax` puts the object where the call cannot see it, so the transfer
    edge must stay unknown instead of becoming a possible hop in a chain.
    """
    ins = instructions_of(fixture_doc, fixture_image, "pass_in_nonarg")
    call = next(x for x in ins if x.mnemonic == "call")
    assert semgraph._argument_carries(ins, call.address, "rax") is False


def test_a_different_object_in_the_argument_register_is_not_a_transfer(
        fixture_doc, fixture_image):
    """A1-06, second counterexample the audit asked for.

    `pass_other_object` acquires into rax and then hands the callee **rcx**.  The callee
    drops something, but nothing witnesses that it is the object this function acquired,
    so no transfers-reference edge may be drawn from it.
    """
    ins = instructions_of(fixture_doc, fixture_image, "pass_other_object")
    call = next(x for x in ins if x.mnemonic == "call")
    assert semgraph._argument_carries(ins, call.address, "rax") is False


def test_an_interior_pointer_lea_does_not_prove_object_identity(fixture_doc,
                                                                 fixture_image):
    """An interior address (rax+0x10) need not be the refcounted object pointer.

    The old A1-06 test treated a derived address as the identical acquired
    object; that was an overclaim, so it stays UNKNOWN rather than PROVED.
    """
    ins = instructions_of(fixture_doc, fixture_image, "pass_by_lea")
    call = next(x for x in ins if x.mnemonic == "call")
    assert semgraph._argument_carries(ins, call.address, "rax") is False


def test_an_unproven_transfer_hop_stays_unknown_in_a_chain():
    """The unproven edge must not default to `possible`, the grade a chain trusts."""
    g = semgraph.Graph()
    g.node("entry:sysent[9]", "entry")
    g.node("function:0x30", "function")
    g.node("function:0x20", "function")
    g.node("function:0x10", "function")
    g.edge("entry:sysent[9]", "function:0x30", "reaches",
           {"site": "0x30", "kind": "entry-attribution", "text": "entry reaches 0x30"})
    g.edge("function:0x30", "function:0x20", "transfers-reference",
           {"site": "0x34", "kind": "argument-passing-unproven",
            "text": "no argument register receives the object"},
           status=semgraph.UNKNOWN)
    g.edge("function:0x20", "function:0x10", "calls",
           {"site": "0x24", "kind": "call", "text": "call 0x10"}, status=semgraph.PROVED)
    scan = {"findings": [_primitive("0x10")]}
    chain = semgraph.chains(g.export(), scan, facts={})["chains"][0]
    assert chain["hop_status"] == "unknown"
    assert [h["status"] for h in chain["hops"]] == ["proved", "unknown", "proved"]


def test_missing_transfer_status_fails_closed_in_export_and_chain():
    """Missing transfer status must not silently become POSSIBLE."""
    g = semgraph.Graph()
    g.node("entry:sysent[9]", "entry")
    g.node("function:0x30", "function")
    g.node("function:0x20", "function")
    g.node("function:0x10", "function")
    g.edge("entry:sysent[9]", "function:0x30", "reaches",
           {"site": "0x30", "text": "entry reaches 0x30"})
    g.edge("function:0x30", "function:0x20", "transfers-reference",
           {"site": "0x34", "text": "unknown argument placement"})
    g.edge("function:0x20", "function:0x10", "calls",
           {"site": "0x24", "text": "call 0x10"}, status=semgraph.PROVED)
    exported = g.export()
    transfer = next(e for e in exported["edges"] if e["kind"] == "transfers-reference")
    assert transfer["status"] == semgraph.UNKNOWN
    chain = semgraph.chains(exported, {"findings": [_primitive("0x10")]}, facts={})["chains"][0]
    assert chain["hop_status"] == semgraph.UNKNOWN
    assert [h["status"] for h in chain["hops"]] == [
        semgraph.PROVED, semgraph.UNKNOWN, semgraph.PROVED]


def test_missing_transfer_status_aggregates_as_unknown_independent_of_order():
    """An absent grade cannot silently promote another transfer observation."""
    for missing_first in (True, False):
        g = semgraph.Graph()
        witness = {"site": "0x44", "text": "call 0x20"}
        records = ({}, {"status": semgraph.UNKNOWN})
        if not missing_first:
            records = tuple(reversed(records))
        for attrs in records:
            g.edge("function:0x30", "function:0x20",
                   "transfers-reference", witness, **attrs)
        edge = g.export()["edges"][0]
        assert edge["status"] == semgraph.UNKNOWN
        assert len(edge["evidence"]) == 2 or len(edge["evidence"]) == 0


# ------------------------------------------------------- A1-02: candidate evidence


def _finding(rank: int, slot: str, claims: dict) -> dict:
    return {
        "detector": "D2_double_release",
        "rank": rank,
        "bug_class": "OWNERSHIP_DOUBLE_FREE",
        "function": {"rva": "0x20", "name": "f"},
        "slot": slot,
        "sites": [slot],
        "claims": claims,
        "window": {"start": slot, "end": slot},
        "counter_evidence": {"error_paths_checked": True},
        "falsification": {"id": f"FALS_{slot}", "action": "re-read the slot"},
    }


def test_merged_evidence_never_mixes_ranks_and_is_permutation_invariant():
    """A1-02: the merged candidate took the minimum rank but kept another record's proof.

    The rank-1 record and the rank-3 record describe different slots.  Whichever
    order the scan emits them in, the candidate must keep one record's hypothesis,
    rank and window together, must stay byte-identical across permutations, and must
    still show the other record beside it.
    """
    first = _finding(1, "0x200", {"released_twice": True})
    second = _finding(3, "0x300", {"released_twice": True, "note": "weaker observation"})
    scan_forward = {"findings": [first, second]}
    scan_backward = {"findings": [second, first]}
    out_forward = queue.build(scan_forward["findings"], {}, {}, [], min_rank=3)
    out_backward = queue.build(scan_backward["findings"], {}, {}, [], min_rank=3)
    assert json.dumps(out_forward, sort_keys=True) == \
        json.dumps(out_backward, sort_keys=True)

    candidate = out_forward["queue"][0]
    assert candidate["evidence"]["rank"] == 1, "the representative is the rank-1 record"
    assert candidate["evidence"]["rank_of_hypothesis"] == 1
    per_site = candidate["evidence"]["sites"]
    assert [(s["rank"], s["slot"]) for s in per_site] == [(1, "0x200"), (3, "0x300")]
    # the merged hypothesis must not carry the stronger rank with the weaker proof
    assert "weaker observation" not in json.dumps(candidate["root_cause_hypothesis"])
    ranks = [s["rank"] for s in per_site]
    assert candidate["evidence"]["rank"] == min(ranks)


# ------------------------------------- A1-07: whole-program seeding is opt-in and visible


class _StubHandles:
    """`build` only needs a catalog constructor and a shape function."""

    class HandleCatalog:                     # noqa: D401 - stub
        def __init__(self, *args, **kwargs):
            pass

    @staticmethod
    def release_shape(*args, **kwargs):
        return None


class _StubIndex:
    def get(self, rva):
        return None

    def containing(self, rva):
        return None


def _scan(scanned, findings=None):
    return {"findings": findings or [], "scanned_rvas": scanned}


def test_whole_program_mode_seeds_from_every_scanned_function():
    doc = semgraph.build(_scan(["0x10", "0x20", "0x30"]), _StubHandles(),
                         image=None, index=_StubIndex(), whole_program=True)
    assert doc["expansion"]["mode"] == "whole-program"
    assert doc["expansion"]["root_source"] == "scanned_rvas"
    assert doc["expansion"]["roots"] == 3


def test_finding_centred_mode_is_still_the_default_and_says_so():
    g = semgraph.Graph()
    g.node("function:0x20", "function")
    doc = semgraph.build(_scan([], [{"detector": "D2_double_release", "rank": 1,
                                     "bug_class": "OWNERSHIP_DOUBLE_FREE",
                                     "function": {"rva": "0x20"}}]),
                         _StubHandles(), image=None, index=_StubIndex())
    assert doc["expansion"]["mode"] == "finding-centred"
    assert doc["expansion"]["root_source"] == "finding-functions"


def test_whole_program_without_a_scanned_list_is_truncated_not_silently_reduced():
    """Falling back to the findings would make a finding-centred graph look whole-program."""
    doc = semgraph.build(_scan([]), _StubHandles(), image=None, index=_StubIndex(),
                         whole_program=True)
    assert doc["expansion"]["truncated"] is True
    assert "scanned_rvas" in doc["expansion"]["truncated_reason"]


def test_the_function_budget_is_published_when_it_bites(monkeypatch):
    monkeypatch.setattr(semgraph, "MAX_WHOLE_PROGRAM_FUNCTIONS", 1)
    doc = semgraph.build(_scan(["0x10", "0x20", "0x30"]), _StubHandles(),
                         image=None, index=_StubIndex(), whole_program=True)
    assert doc["expansion"]["function_budget"] == 1
    assert doc["expansion"]["truncated"] is True
    assert "function budget 1" in doc["expansion"]["truncated_reason"]


def test_the_roots_a_budget_left_out_are_published(monkeypatch):
    """"Truncated" says a limit bit; it does not say what fell off. Which entrypoints the
    budget dropped decides whether the graph is still fit for the question."""
    monkeypatch.setattr(semgraph, "MAX_WHOLE_PROGRAM_FUNCTIONS", 2)
    doc = semgraph.build(_scan(["0x10", "0x20", "0x30", "0x40"]), _StubHandles(),
                         image=None, index=_StubIndex(), whole_program=True)
    expansion = doc["expansion"]
    assert expansion["roots_requested"] == 4
    assert expansion["roots_seeded"] == 2
    assert expansion["roots_dropped_count"] == 2
    assert expansion["roots_dropped"] == ["0x30", "0x40"]


def test_a_budget_that_bites_drops_the_least_relevant_roots(monkeypatch):
    """BW 13.52: truncating by ascending address dropped two syscall handlers because they sit
    at the top of the text section. Entry handlers must be seeded first."""
    monkeypatch.setattr(semgraph, "MAX_WHOLE_PROGRAM_FUNCTIONS", 2)
    entry_meta = {"sysent[1]": {"handler_rva": "0x40"}, "sysent[2]": {"handler_rva": "0x30"}}
    doc = semgraph.build(_scan(["0x10", "0x20", "0x30", "0x40"]), _StubHandles(),
                         image=None, index=_StubIndex(), entry_meta=entry_meta,
                         whole_program=True)
    expansion = doc["expansion"]
    assert expansion["roots_seeded"] == 2
    assert expansion["roots_dropped"] == ["0x10", "0x20"], expansion["roots_dropped"]
    assert expansion["root_priority"].startswith("entry-handlers")
