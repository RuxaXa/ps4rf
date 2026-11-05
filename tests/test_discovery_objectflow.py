"""Object flow: alias tracking, identity, and why a call edge proves nothing."""
from __future__ import annotations

import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.discovery import objectflow


class Operand:
    def __init__(self, kind, reg=None, base=None, disp=0, index=0, size=8):
        self.type = kind
        self.reg = reg
        self.size = size
        if kind == 3:                                  # memory
            self.mem = type("Mem", (), {"base": base, "index": index, "disp": disp})()


REG_NAMES = {1: "rax", 2: "rbx", 3: "rcx", 4: "rdi", 5: "rsi", 6: "rdx", 7: "rbp", 8: "rsp",
             9: "r8", 10: "r9", 11: "r10"}


class Ins:
    def __init__(self, address, mnemonic, op_str, *operands):
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.operands = list(operands)
        self.size = 4

    def reg_name(self, reg):
        return REG_NAMES.get(reg)


REG, IMM, MEM = 1, 2, 3     # capstone: X86_OP_REG=1, X86_OP_IMM=2, X86_OP_MEM=3


def view(*insns):
    return type("View", (), {"ins": list(insns), "rva": 0x100})()


def test_an_alias_through_a_move_is_tracked():
    insns = [
        Ins(0x100, "mov", "rbx, rdi", Operand(REG, 2), Operand(REG, 4)),
        Ins(0x104, "mov", "eax, dword ptr [rbx + 0x28]", Operand(REG, 1),
            Operand(MEM, base=2, disp=0x28, size=4)),
    ]
    tracked = objectflow.track_register(insns, 0, "rdi")
    assert "rbx" in tracked["regs"]
    writes = objectflow.object_field_writes(insns, tracked["regs"])
    assert writes == []                                # a load is not a field write


def test_a_spill_and_reload_keeps_the_alias():
    insns = [
        Ins(0x100, "mov", "qword ptr [rbp - 8], rdi", Operand(MEM, base=7, disp=-8),
            Operand(REG, 4)),
        Ins(0x104, "mov", "rbx, qword ptr [rbp - 8]", Operand(REG, 2),
            Operand(MEM, base=7, disp=-8)),
    ]
    tracked = objectflow.track_register(insns, 0, "rdi")
    assert "rbx" in tracked["regs"]
    assert "[rbp-0x8]" in tracked["slots"]


def test_clearing_the_register_ends_the_alias():
    insns = [
        Ins(0x100, "mov", "rbx, rdi", Operand(REG, 2), Operand(REG, 4)),
        Ins(0x104, "xor", "rbx, rbx", Operand(REG, 2), Operand(REG, 2)),
    ]
    tracked = objectflow.track_register(insns, 0, "rdi")
    assert "rbx" not in tracked["regs"]


def test_a_transfer_needs_the_callee_to_use_the_object():
    caller = view(Ins(0x100, "mov", "rdi, rax", Operand(REG, 4), Operand(REG, 1)),
                  Ins(0x104, "call", "0x500", Operand(REG, 1)))
    callee_uses = view(Ins(0x500, "dec", "dword ptr [rdi + 0x28]",
                           Operand(MEM, base=4, disp=0x28, size=4)))
    verdict = objectflow.prove_transfer(caller, 0x104, callee_uses, ["rax"])
    assert verdict["proved"] is True
    assert verdict["argument_register"] == "rdi"
    assert "dereferences rdi" in verdict["evidence"]


def test_a_call_edge_alone_is_not_a_transfer():
    caller = view(Ins(0x100, "mov", "rdi, rax", Operand(REG, 4), Operand(REG, 1)),
                  Ins(0x104, "call", "0x500", Operand(REG, 1)))
    callee_ignores = view(Ins(0x500, "mov", "eax, 0", Operand(REG, 1)))
    verdict = objectflow.prove_transfer(caller, 0x104, callee_ignores, ["rax"])
    assert verdict["proved"] is False
    assert "does not use it as an object" in verdict["why"]


def test_a_different_object_in_the_argument_register_is_refused():
    caller = view(Ins(0x100, "mov", "rdi, rcx", Operand(REG, 4), Operand(REG, 3)),
                  Ins(0x104, "call", "0x500", Operand(REG, 1)))
    callee_uses = view(Ins(0x500, "dec", "dword ptr [rdi + 0x28]",
                           Operand(MEM, base=4, disp=0x28, size=4)))
    verdict = objectflow.prove_transfer(caller, 0x104, callee_uses, ["rax"])
    assert verdict["proved"] is False
    assert "no tracked alias" in verdict["why"]


def test_two_drop_sites_on_the_same_alias_are_one_object_and_the_field_is_named():
    insns = [
        Ins(0x100, "mov", "rbx, rdi", Operand(REG, 2), Operand(REG, 4)),
        Ins(0x104, "dec", "dword ptr [rbx + 0x28]", Operand(MEM, base=2, disp=0x28, size=4)),
    ]
    record = objectflow.object_flow_for_drops(
        view(*insns), [{"site": "0x104", "object_register": "rbx"}], "rdi",
        stores={0x28: {4: 1}})
    assert record["proved"] is True
    assert record["shared_field_offsets"] == [0x28]
    assert "same field offsets" in record["evidence"]


def test_a_site_that_does_not_use_the_alias_refuses_the_identity():
    insns = [Ins(0x100, "mov", "rbx, rdi", Operand(REG, 2), Operand(REG, 4))]
    record = objectflow.object_flow_for_drops(
        view(*insns), [{"site": "0x108", "object_register": "rcx"}], "rdi")
    assert record["proved"] is False
    assert "not every site acts on an alias" in record["why"]


def test_a_long_move_chain_does_not_make_every_register_an_alias():
    """A vacuous alias set makes "same object" trivially true, which is worse than no answer."""
    insns = [
        Ins(0x100, "mov", "rbx, rdi", Operand(REG, 2), Operand(REG, 4)),
        Ins(0x104, "mov", "rcx, rbx", Operand(REG, 3), Operand(REG, 2)),
        Ins(0x108, "mov", "rdx, rcx", Operand(REG, 6), Operand(REG, 3)),
        Ins(0x10c, "mov", "rsi, rdx", Operand(REG, 5), Operand(REG, 6)),
        Ins(0x110, "mov", "r8, rsi", Operand(REG, 9), Operand(REG, 5)),
    ]
    tracked = objectflow.track_register(insns, 0, "rdi")
    assert {"rbx", "rcx", "rdx"} <= set(tracked["regs"])
    assert "rsi" not in tracked["regs"] and "r8" not in tracked["regs"]
    assert tracked["depths"]["rdx"] == objectflow.MAX_ALIAS_HOPS


def test_overwriting_the_alias_register_ends_the_alias_but_an_offset_does_not():
    killed = [
        Ins(0x100, "mov", "rbx, rdi", Operand(REG, 2), Operand(REG, 4)),
        Ins(0x104, "mov", "rbx, 0", Operand(REG, 2), Operand(IMM, size=8)),
    ]
    assert "rbx" not in objectflow.track_register(killed, 0, "rdi")["regs"]
    interior = [
        Ins(0x100, "mov", "rbx, rdi", Operand(REG, 2), Operand(REG, 4)),
        Ins(0x104, "add", "rbx, 0x28", Operand(REG, 2), Operand(IMM, size=8)),
    ]
    assert "rbx" in objectflow.track_register(interior, 0, "rdi")["regs"]


def test_every_incomplete_answer_still_carries_both_halves():
    """A missing key is read as "no problem there"; every refusal must name both halves."""
    record = objectflow._incomplete("nothing to analyse")
    assert set(record) >= {"local", "interprocedural", "proved", "why"}
    assert "why" in record["local"] and "why" in record["interprocedural"]
    assert record["local"]["proved"] is False
    assert record["interprocedural"]["return_provenance"]["verdict"] == "UNKNOWN"
