"""Conservative A1-06 argument-placement counterexamples (synthetic operands).

These tests pin the semantics of Capstone operand types and register writes;
they do not claim firmware reachability or independently discovered exploits.
"""
from dataclasses import dataclass

import pytest
from types import SimpleNamespace

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from tools.discovery.semgraph import (_argument_carries, _transfer_status, POSSIBLE,
                                      UNKNOWN, REFUTED, Graph, chains, check_evidence)


@dataclass
class Ins:
    address: int
    mnemonic: str
    operands: list

    def reg_name(self, reg):
        return reg

    def regs_access(self):
        if self.mnemonic in ("cmp", "test", "je", "jne", "call"):
            return ([], [])
        writes = []
        if self.operands and self.operands[0].type == X86_OP_REG:
            writes.append(self.operands[0].reg)
        if self.mnemonic == "xchg" and len(self.operands) > 1 and self.operands[1].type == X86_OP_REG:
            writes.append(self.operands[1].reg)
        return ([], writes)


def reg(name):
    return SimpleNamespace(type=X86_OP_REG, reg=name)


def mem(base, disp=0, index=None):
    return SimpleNamespace(type=X86_OP_MEM,
                           mem=SimpleNamespace(base=base, index=index, disp=disp))


def imm(value):
    return SimpleNamespace(type=X86_OP_IMM, imm=value)


def move(address, dst, src, mnemonic="mov"):
    return Ins(address, mnemonic, [reg(dst), src])


def call(address):
    return Ins(address, "call", [imm(0xF00)])


def test_exact_register_handoff():
    assert _argument_carries([move(0x10, "rdi", reg("rax")), call(0x20)], 0x20, "rax")


def test_memory_load_does_not_transfer_original_pointer():
    assert not _argument_carries([move(0x10, "rdi", mem("rax", 0x20)), call(0x20)], 0x20, "rax")


def test_partial_register_is_not_a_pointer_witness():
    assert not _argument_carries([move(0x10, "rdi", reg("r8d")), call(0x20)], 0x20, "r8")


def test_later_argument_overwrite_invalidates_handoff():
    code = [move(0x10, "rdi", reg("rax")), move(0x12, "rdi", reg("rbx")), call(0x20)]
    assert not _argument_carries(code, 0x20, "rax")


def test_partial_argument_overwrite_invalidates_handoff():
    code = [move(0x10, "rdi", reg("rax")), Ins(0x12, "xor", [reg("edi"), reg("edi")]), call(0x20)]
    assert not _argument_carries(code, 0x20, "rax")


def test_intervening_call_invalidates_witness():
    code = [move(0x10, "rdi", reg("rax")), call(0x14), call(0x20)]
    assert not _argument_carries(code, 0x20, "rax")


def test_branch_can_bypass_handoff():
    code = [Ins(0x10, "je", [imm(0x20)]), move(0x14, "rdi", reg("rax")), call(0x20)]
    assert not _argument_carries(code, 0x20, "rax")


def test_object_load_precedes_argument_placement():
    code = [move(0x10, "rax", mem("rbx")), move(0x14, "rdi", reg("rax")), call(0x20)]
    assert _argument_carries(code, 0x20, "rax", obj_load_site=0x10)
    assert not _argument_carries(code, 0x20, "rax", obj_load_site=0x18)


def test_object_register_clobber_invalidates_identity():
    code = [move(0x10, "rax", mem("rbx")), move(0x12, "rax", reg("rcx")),
            move(0x14, "rdi", reg("rax")), call(0x20)]
    assert not _argument_carries(code, 0x20, "rax", obj_load_site=0x10)


def test_identity_lea_yes_interior_pointer_and_indexed_lea_no():
    assert _argument_carries([move(0x10, "rdi", mem("rax"), "lea"), call(0x20)], 0x20, "rax")
    assert not _argument_carries([move(0x10, "rdi", mem("rax", 0x10), "lea"),
                                  call(0x20)], 0x20, "rax")
    assert not _argument_carries([move(0x10, "rdi", mem("rax", index="rcx"), "lea"),
                                  call(0x20)], 0x20, "rax")


def test_xchg_second_operand_clobbers_argument():
    code = [move(0x10, "rdi", reg("rax")), Ins(0x12, "xchg", [reg("rbx"), reg("rdi")]), call(0x20)]
    assert not _argument_carries(code, 0x20, "rax")


def test_branch_can_skip_object_load():
    code = [Ins(0x0A, "jne", [imm(0x14)]), move(0x10, "rax", mem("rbx")),
            move(0x14, "rdi", reg("rax")), call(0x20)]
    assert not _argument_carries(code, 0x20, "rax", obj_load_site=0x10)


def test_caller_only_witness_does_not_prove_callee_drop_identity():
    """Caller passes A, but callee may drop unrelated B.

    A proven call-site placement alone cannot be PROVED as ownership transfer;
    it needs separate callee-side object-identity evidence.
    """
    assert _transfer_status(True) == POSSIBLE
    assert _transfer_status(False) == UNKNOWN
    assert _transfer_status(True) != "proved"


def test_graph_keeps_distinct_evidence_at_same_site():
    """Independent findings at one call site must not erase each other."""
    graph = Graph()
    witness = {"site": "0x10", "kind": "call", "text": "call 0x20"}
    assert graph.edge("function:0x10", "function:0x20", "calls", witness,
                      detector="D1", status=UNKNOWN)
    assert not graph.edge("function:0x10", "function:0x20", "calls", witness,
                          detector="D2", status="proved")
    assert not graph.edge("function:0x10", "function:0x20", "calls", witness,
                          detector="D1", status=UNKNOWN)
    exported = graph.export()
    assert len(exported["edges"]) == 1
    edge = exported["edges"][0]
    assert edge["status"] == "proved"
    assert {rec["attrs"]["status"] for rec in edge["evidence"]} == {UNKNOWN, "proved"}


def test_graph_export_is_stable_when_evidence_arrives_in_reverse_order():
    witness = {"site": "0x10", "kind": "call", "text": "call 0x20"}
    a, b = Graph(), Graph()
    records = [{"detector": "D1", "status": UNKNOWN},
               {"detector": "D2", "status": "proved"}]
    for graph, sequence in ((a, records), (b, list(reversed(records)))):
        for record in sequence:
            graph.edge("function:0x10", "function:0x20", "calls",
                       witness, **record)
    assert a.export() == b.export()


def test_proved_transfer_requires_both_witness_halves():
    import pytest
    witness = {"site": "0x20", "kind": "argument-passing", "text": "mov rdi, rax"}
    graph = Graph()
    with pytest.raises(AssertionError, match="callee object-identity witness"):
        graph.edge("function:0x10", "function:0x30", "transfers-reference", witness,
                   status="proved", argument_proven=True)
    with pytest.raises(AssertionError, match="callee object-identity witness"):
        graph.edge("function:0x10", "function:0x30", "transfers-reference", witness,
                   status="proved", argument_proven=False,
                   callee_identity_witness={"site": "0x31", "text": "drop arg0"})
    with pytest.raises(AssertionError, match="callee object-identity witness"):
        graph.edge("function:0x10", "function:0x30", "transfers-reference", witness,
                   status="proved", argument_proven=True,
                   callee_identity_witness={"site": "0x31", "text": "drop arg0"})
    assert graph.edge("function:0x10", "function:0x30", "transfers-reference", witness,
                      status="proved", argument_proven=True, callee_identity_proven=True,
                      callee_identity_witness={"site": "0x31", "text": "drop arg0"})


def test_chain_prefers_proved_over_unknown_witness_at_same_site():
    graph = Graph()
    graph.node("entry:sysent[4]", "entry")
    graph.node("function:0x20", "function")
    witness = {"site": "0x40", "kind": "entry-table", "text": "sysent[4] -> 0x20"}
    graph.edge("entry:sysent[4]", "function:0x20", "reaches", witness,
               status=UNKNOWN, detector="D1")
    graph.edge("entry:sysent[4]", "function:0x20", "reaches", witness,
               status="proved", detector="D2")
    finding = {"detector": "D2", "function": {"rva": "0x20"},
               "bug_class": "OWNERSHIP_DOUBLE_FREE", "rank": 1}
    selected = chains(graph.export(), {"findings": [finding]}, facts={})["chains"][0]
    assert selected["hop_status"] == "proved"
    assert selected["path_selection"]["paths_considered"] == 1
    assert len(graph.export()["edges"][0]["evidence"]) == 2
    assert len(selected["hops"][0]["evidence"]) == 2


def test_parallel_evidence_does_not_multiply_structural_chain_paths():
    graph = Graph()
    graph.node("entry:sysent[1]", "entry")
    for i in range(4):
        graph.node(f"function:0x{i+10:x}", "function")
    endpoints = [("entry:sysent[1]", "function:0xa", "reaches")]
    endpoints.extend((f"function:0x{i+10:x}", f"function:0x{i+11:x}", "calls")
                     for i in range(3))
    for j, (src, dst, kind) in enumerate(endpoints):
        for detector in ("D1", "D2", "D3"):
            graph.edge(src, dst, kind,
                       {"site": hex(j+0x100), "kind": kind, "text": f"{src}->{dst}"},
                       detector=detector, status="proved")
    exported = graph.export()
    assert len(exported["edges"]) == 4
    finding = {"detector": "D1", "function": {"rva": "0xd"},
               "bug_class": "OWNERSHIP_DOUBLE_FREE", "rank": 1}
    selected = chains(exported, {"findings": [finding]}, facts={})["chains"][0]
    assert selected["hop_status"] == "proved"
    assert selected["path_selection"]["paths_considered"] == 1


def test_conflicting_proof_and_refutation_degrades_to_unknown():
    graph = Graph()
    witness = {"site": "0x30", "kind": "call", "text": "call 0x10"}
    graph.edge("function:0x1", "function:0x2", "calls", witness, status="proved")
    graph.edge("function:0x1", "function:0x2", "calls", witness, status="refuted")
    edge = graph.export()["edges"][0]
    assert edge["status"] == UNKNOWN
    assert edge["evidence_conflict"] is True


@pytest.mark.parametrize("source,partial", [
    ("rbx", "ebx"), ("rbx", "bx"), ("rbx", "bl"), ("rbx", "bh"),
    ("rbp", "ebp"), ("rbp", "bp"), ("rbp", "bpl"),
    ("rsp", "esp"), ("rsp", "sp"), ("rsp", "spl"),
    ("r12", "r12d"), ("r12", "r12w"), ("r12", "r12b"),
])
def test_subregister_clobber_kills_source_pointer_identity(source, partial):
    """After acquiring a pointer, even 8/16/32-bit writes destroy identity.

    Previously rbx/rbp/rsp subregisters were absent from canonical(),
    and the scanner would incorrectly retain an older object.
    """
    intact = [move(0x10, source, mem("rcx")),
              move(0x14, "rdi", reg(source)), call(0x20)]
    assert _argument_carries(intact, 0x20, source, obj_load_site=0x10)

    overwritten = [move(0x10, source, mem("rcx")),
                   move(0x12, partial, reg("rax")),
                   move(0x14, "rdi", reg(source)), call(0x20)]
    assert not _argument_carries(overwritten, 0x20, source, obj_load_site=0x10)


# Independent firmware-audit findings N1-N4: mutations must make these red.

def test_n1_statusless_reference_transfer_is_explicitly_unknown():
    graph = Graph()
    w = {"site": "0x14", "kind": "call", "text": "call free_wrapper"}
    graph.edge("function:0x1", "function:0x2", "transfers-reference", w)
    edge = graph.export()["edges"][0]
    assert edge["status"] == UNKNOWN
    assert check_evidence(graph.export()) == []


def test_n1_legacy_statusless_transfer_is_rejected_by_evidence_validator():
    w = {"site": "0x14", "kind": "call", "text": "call free_wrapper"}
    graph = {"edges": [{"src": "entry:probe", "dst": "function:0x2",
                        "kind": "transfers-reference", "witness": w}],
             "nodes": [{"id": "entry:probe", "kind": "entry"},
                       {"id": "function:0x2", "kind": "function"}]}
    assert any("transfer-status-missing" in error
               for error in check_evidence(graph))
    finding = {"detector": "D1", "function": {"rva": "0x2"},
               "bug_class": "OWNERSHIP_DOUBLE_FREE", "rank": 1}
    result = chains(graph, {"findings": [finding]}, facts={})["chains"][0]
    assert result["hop_status"] == UNKNOWN


def test_n2_refuted_unknown_disagreement_is_visible_and_order_independent():
    w = {"site": "0x14", "kind": "call", "text": "call helper"}
    exports = []
    for statuses in ((UNKNOWN, REFUTED), (REFUTED, UNKNOWN)):
        graph = Graph()
        for status in statuses:
            graph.edge("function:0x1", "function:0x2", "calls", w,
                       status=status, detector=status)
        edge = graph.export()["edges"][0]
        assert edge["status"] == UNKNOWN
        assert edge["evidence_conflict"] is True
        assert {rec["attrs"]["status"] for rec in edge["evidence"]} == {
            UNKNOWN, REFUTED}
        exports.append(graph.export())
    assert exports[0] == exports[1]


def test_n3_conflicted_aggregate_does_not_advertise_proved_identity():
    graph = Graph()
    w = {"site": "0x14", "kind": "call", "text": "call helper"}
    proof = {"site": "0x44", "text": "free(arg0)", "kind": "release"}
    graph.edge("function:0x1", "function:0x2", "transfers-reference", w,
               status="proved", argument_proven=True,
               callee_identity_proven=True, callee_identity_witness=proof)
    graph.edge("function:0x1", "function:0x2", "transfers-reference", w,
               status=REFUTED, detector="negative")
    edge = graph.export()["edges"][0]
    assert edge["status"] == UNKNOWN
    assert edge["evidence_conflict"] is True
    for attribute in ("argument_proven", "callee_identity_proven",
                      "callee_identity_witness"):
        assert attribute not in edge
    assert any(rec["attrs"].get("callee_identity_witness") == proof
               for rec in edge["evidence"])


def test_n4_alternative_routes_preserve_aggregated_witnesses():
    graph = Graph()
    for name in ("entry:best", "entry:alternate"):
        graph.node(name, "entry")
    graph.node("function:0x20", "function")
    w1 = {"site": "0x40", "kind": "entry-table", "text": "best -> fn"}
    w2 = {"site": "0x50", "kind": "entry-table", "text": "alternate -> fn"}
    graph.edge("entry:best", "function:0x20", "reaches", w1,
               status="proved", detector="D1")
    graph.edge("entry:alternate", "function:0x20", "reaches", w2,
               status="possible", detector="D2")
    graph.edge("entry:alternate", "function:0x20", "reaches", w2,
               status=UNKNOWN, detector="D3")
    finding = {"detector": "D1", "function": {"rva": "0x20"},
               "bug_class": "OWNERSHIP_DOUBLE_FREE", "rank": 1}
    chain = chains(graph.export(), {"findings": [finding]}, facts={})["chains"][0]
    assert chain["entry"] == "entry:best"
    alt = chain["path_selection"]["alternatives"][0]
    assert alt["entry"] == "entry:alternate"
    assert len(alt["hops"][0]["evidence"]) == 2
    assert {obs["attrs"]["detector"] for obs in alt["hops"][0]["evidence"]} == {
        "D2", "D3"}


def test_mutation_partial_width_lea_guard_is_discriminating():
    # LEA into edi is a valid x86-64 instruction but loses high pointer bits.
    # Removing the explicit full-width destination guard makes it PROVED.
    code = [move(0x10, "edi", mem("rax"), mnemonic="lea"), call(0x20)]
    assert not _argument_carries(code, 0x20, "rax")


def test_mutation_branch_in_placement_window_must_refuse_linear_proof():
    # A conditional after placement is an unresolved control-flow window.
    # The old independent test used a branch *before* placement, which was
    # already caught by a different skip-path check.
    code = [move(0x10, "rdi", reg("rax")),
            Ins(0x14, "jne", [imm(0x1e)]), call(0x20)]
    assert not _argument_carries(code, 0x20, "rax")


def test_n1_null_transfer_grade_is_unknown_and_invalid_is_refused():
    w = {"site": "0x14", "kind": "call", "text": "call helper"}
    graph = Graph()
    assert graph.edge("function:0x1", "function:0x2", "transfers-reference",
                      w, status=None)
    assert graph.export()["edges"][0]["status"] == UNKNOWN
    with pytest.raises(AssertionError, match="invalid proof status"):
        graph.edge("function:0x1", "function:0x3", "transfers-reference",
                   w, status="pr0ved")


def test_n1_unvalidated_external_null_grade_cannot_break_chain_scoring():
    w = {"site": "0x14", "kind": "call", "text": "call helper"}
    graph = {"nodes": [{"id": "entry:probe", "kind": "entry"},
                       {"id": "function:0x2", "kind": "function"}],
             "edges": [{"src": "entry:probe", "dst": "function:0x2",
                        "kind": "transfers-reference", "witness": w,
                        "status": None}]}
    assert check_evidence(graph)
    finding = {"detector": "D1", "function": {"rva": "0x2"},
               "bug_class": "OWNERSHIP_DOUBLE_FREE", "rank": 1}
    result = chains(graph, {"findings": [finding]}, facts={})["chains"][0]
    assert result["hop_status"] == UNKNOWN
