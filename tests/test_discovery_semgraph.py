import pytest
from types import SimpleNamespace

from tools.discovery import chains as chains_mod
from tools.discovery import semgraph
from tools.discovery.entries import EntryIndex


def test_graph_rejects_edge_without_binary_witness():
    g = semgraph.Graph()
    g.node("function:0x1", "function")
    g.node("function:0x2", "function")
    with pytest.raises(AssertionError, match="has no witness"):
        g.edge("function:0x1", "function:0x2", "calls", {})


def test_graph_export_is_deterministic_and_counts_edges():
    g = semgraph.Graph()
    g.node("function:0x2", "function", subsystem="socket")
    g.node("function:0x1", "function", subsystem="aio")
    g.edge("function:0x2", "function:0x1", "calls",
           {"site": "0x20", "kind": "call", "text": "call 0x1"})
    a = g.export()
    b = g.export()
    assert a == b
    assert a["counts"]["edges"] == {"calls": 1}
    assert [n["id"] for n in a["nodes"]] == ["function:0x1", "function:0x2"]


def test_identical_subsystem_never_creates_an_edge_by_itself():
    g = semgraph.Graph()
    g.node("function:0x1", "function", subsystem="kqueue")
    g.node("function:0x2", "function", subsystem="kqueue")
    exported = g.export()
    assert exported["edges"] == []


def test_chain_requires_an_entry_rooted_witness_path():
    g = semgraph.Graph()
    g.node("entry:sysent[1]", "entry")
    g.node("function:0x10", "function")
    g.node("function:0x20", "function")
    g.edge("entry:sysent[1]", "function:0x10", "reaches",
           {"site": "0x10", "kind": "entry-attribution", "text": "entry reaches 0x10"})
    g.edge("function:0x10", "function:0x20", "calls",
           {"site": "0x18", "kind": "call", "text": "call 0x20"})
    scan = {"findings": [{"detector": "D2_double_release", "rank": 1,
                           "bug_class": "OWNERSHIP_DOUBLE_FREE", "function": {"rva": "0x20"}}]}
    out = semgraph.chains(g.export(), scan, facts={}, chains_mod=chains_mod)
    counts = out["counts"]
    assert (counts["chains"], counts["shown"], counts["entry_rooted"]) == (1, 1, 1)
    # A proved control-flow path is CFG_REACHABLE and nothing more: the ladder must not
    # promote it because the hops happen to be witnessed.
    assert counts["proof_levels"] == {"CFG_REACHABLE": 1}
    chain = out["chains"][0]
    assert chain["entry"] == "entry:sysent[1]"
    assert chain["hop_status"] == "proved"
    assert [h["kind"] for h in chain["hops"]] == ["reaches", "calls"]
    assert all(h["witness"]["site"] for h in chain["hops"])
    # A1-03: a witnessed, proved path proves reachability of the CODE.  It says
    # nothing about whether an unprivileged caller is authorized to drive it, so the
    # privilege requirement stays open until authorization evidence exists.
    blockers = {b["id"]: b for b in chain["requirements"]["blockers"]}
    assert "BLOCK_REQ_ENTRY_REACHABLE" not in blockers
    assert "BLOCK_REQ_UNPRIV_ENTRY" in blockers
    assert "authorization" in blockers["BLOCK_REQ_UNPRIV_ENTRY"]["why"].lower()
    assert chain["requirements"]["entry_privilege"] == "UNKNOWN"


def test_recorded_authorization_evidence_is_what_clears_privilege():
    """The positive control for A1-03: evidence closes the requirement, a kind does not."""
    g = semgraph.Graph()
    g.node("entry:sysent[1]", "entry", entry_kind="syscall",
           authorization={"basis": "syscall-cred-gate-absent",
                          "evidence": "handler 0x10 has no cred or kauth call on any path",
                          "unprivileged": True})
    g.node("function:0x20", "function")
    g.edge("entry:sysent[1]", "function:0x20", "reaches",
           {"site": "0x10", "kind": "entry-attribution", "text": "entry reaches 0x20"})
    scan = {"findings": [{"detector": "D2_double_release", "rank": 1,
                          "bug_class": "OWNERSHIP_DOUBLE_FREE",
                          "function": {"rva": "0x20"}}]}
    out = semgraph.chains(g.export(), scan, facts={}, chains_mod=chains_mod)
    chain = out["chains"][0]
    blockers = {b["id"] for b in chain["requirements"]["blockers"]}
    assert "BLOCK_REQ_ENTRY_REACHABLE" not in blockers
    assert "BLOCK_REQ_UNPRIV_ENTRY" not in blockers
    assert chain["requirements"]["entry_privilege"] == "UNPRIVILEGED"


def test_an_authorization_claim_without_evidence_clears_nothing():
    g = semgraph.Graph()
    g.node("entry:sysent[1]", "entry", entry_kind="syscall",
           authorization={"basis": "syscall-cred-gate-absent", "unprivileged": True})
    g.node("function:0x20", "function")
    g.edge("entry:sysent[1]", "function:0x20", "reaches",
           {"site": "0x10", "kind": "entry-attribution", "text": "entry reaches 0x20"})
    scan = {"findings": [{"detector": "D2_double_release", "rank": 1,
                          "bug_class": "OWNERSHIP_DOUBLE_FREE",
                          "function": {"rva": "0x20"}}]}
    out = semgraph.chains(g.export(), scan, facts={}, chains_mod=chains_mod)
    blockers = {b["id"] for b in out["chains"][0]["requirements"]["blockers"]}
    assert "BLOCK_REQ_UNPRIV_ENTRY" in blockers


def test_unrooted_primitive_is_unknown_not_implicitly_reachable():
    g = semgraph.Graph()
    g.node("function:0x20", "function")
    scan = {"findings": [{"detector": "D2_double_release", "rank": 1,
                           "bug_class": "OWNERSHIP_DOUBLE_FREE", "function": {"rva": "0x20"}}]}
    out = semgraph.chains(g.export(), scan, facts={})
    chain = out["chains"][0]
    assert chain["entry"] is None
    assert chain["hop_status"] == "unknown"
    assert chain["hops"] == []


def test_known_entry_root_is_a_split_record_continuation_barrier():
    """Adjacent syscall records must not turn into one giant fall-through function."""
    records = {
        0x100: SimpleNamespace(rva=0x100, size=0x10),
        0x110: SimpleNamespace(rva=0x110, size=0x10),
    }

    class FakeIndex:
        def get(self, rva):
            return records.get(rva)

        def containing(self, rva):
            for rec in records.values():
                if rec.rva <= rva < rec.rva + rec.size:
                    return rec
            return None

    ei = EntryIndex.__new__(EntryIndex)
    ei.__dict__["index"] = FakeIndex()
    ei.__dict__["_decode"] = lambda rva: [SimpleNamespace(mnemonic="nop")]
    ei.__dict__["tail_targets"] = lambda rva: set()
    ei.__dict__["jump_table_cases"] = lambda rva: set()
    assert set(ei.expand_entry(0x100)) == {0x100, 0x110}
    assert set(ei.expand_entry(0x100, barrier_roots={0x100, 0x110})) == {0x100}


def test_attributed_but_unretained_entry_path_is_possible_not_proved():
    g = semgraph.Graph()
    g.node("entry:sysent[1]", "entry")
    g.node("function:0x20", "function")
    g.edge("entry:sysent[1]", "function:0x20", "reaches",
           {"site": "sysent[1].sy_call", "kind": "entry-table",
            "text": "handler is known; predecessor path not retained"},
           status="possible")
    scan = {"findings": [{"detector": "D2_double_release", "rank": 1,
                           "bug_class": "OWNERSHIP_DOUBLE_FREE", "function": {"rva": "0x20"}}]}
    chain = semgraph.chains(
        g.export(), scan, facts={}, chains_mod=chains_mod
    )["chains"][0]
    assert chain["entry"] == "entry:sysent[1]"
    assert chain["hop_status"] == "possible"
    assert "BLOCK_REQ_UNPRIV_ENTRY" in {
        b["id"] for b in chain["requirements"]["blockers"]
    }


def test_the_published_requirements_carry_the_open_obligation():
    """`dataclasses.asdict` drops the computed `next_obligation`; the artefact then looks as if
    no obligation were open at all, which is the opposite of what the ladder is for."""
    g = semgraph.Graph()
    g.node("entry:sysent[1]", "entry")
    g.node("function:0x20", "function")
    g.edge("entry:sysent[1]", "function:0x20", "reaches",
           {"site": "0x10", "kind": "entry-attribution", "text": "entry reaches 0x20"})
    scan = {"findings": [{"detector": "D2_double_release", "rank": 1,
                          "bug_class": "OWNERSHIP_DOUBLE_FREE", "function": {"rva": "0x20"}}]}
    out = semgraph.chains(g.export(), scan, facts={}, chains_mod=chains_mod)
    requirements = out["chains"][0]["requirements"]
    assert requirements["proof_level"] == "CFG_REACHABLE"
    assert requirements["next_obligation"]["level"] == "UNPRIV_REACHABLE"
    assert requirements["next_obligation"]["missing"][0]["requirement"] == "REQ_UNPRIV_ENTRY"
