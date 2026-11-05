"""Conservative A1-06 argument-placement counterexamples (synthetic operands).

These tests pin the semantics of Capstone operand types and register writes;
they do not claim firmware reachability or independently discovered exploits.
"""
from dataclasses import dataclass
from types import SimpleNamespace

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from tools.discovery.semgraph import _argument_carries, _transfer_status, POSSIBLE, UNKNOWN, Graph, chains


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
    assert graph.edge("function:0x10", "function:0x20", "calls", witness,
                      detector="D2", status="proved")
    assert not graph.edge("function:0x10", "function:0x20", "calls", witness,
                          detector="D1", status=UNKNOWN)
    exported = graph.export()
    assert len(exported["edges"]) == 2
    assert {edge["status"] for edge in exported["edges"]} == {UNKNOWN, "proved"}


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
    assert graph.edge("function:0x10", "function:0x30", "transfers-reference", witness,
                      status="proved", argument_proven=True,
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
    assert selected["path_selection"]["paths_considered"] >= 2
