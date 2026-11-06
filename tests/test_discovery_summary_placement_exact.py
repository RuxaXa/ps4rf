"""Synthetic exact-pointer argument placements for function-summary hops.

No firmware bytes or holdback answers. Minimal Capstone-shaped operands allow
precise negative controls for the prior unsound backward placement heuristic.
"""
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from tools.discovery import summaries


@dataclass
class Ins:
    address: int
    mnemonic: str
    operands: list
    op_str: str = "synthetic"

    def reg_name(self, ident):
        return ident

    def regs_access(self):
        # Include a second-operand clobber for the xchg counterexample.
        writes = []
        if self.operands and self.operands[0].type == summaries.X86_OP_REG:
            writes.append(self.operands[0].reg)
        if self.mnemonic == "xchg" and len(self.operands) > 1:
            writes.append(self.operands[1].reg)
        return [], writes


def reg(name):
    return SimpleNamespace(type=summaries.X86_OP_REG, reg=name)


def mem(base, disp=0, index=0):
    return SimpleNamespace(type=summaries.X86_OP_MEM,
                           mem=SimpleNamespace(base=base, disp=disp, index=index))


def ins(addr, mnemonic, destination=None, source=None):
    ops = [destination] if destination is not None else []
    if source is not None:
        ops.append(source)
    return Ins(addr, mnemonic, ops)


def place(*ops, obj="rax"):
    view = SimpleNamespace(ins=[*ops, ins(0x80, "call")])
    return summaries._placement_for(view, 0x80, obj)


def test_full_width_move_is_proven():
    result = place(ins(0x70, "mov", reg("rdi"), reg("rax")))
    assert result["status"] == summaries.PROVEN
    assert result["argument"] == "rdi"


@pytest.mark.parametrize("source", [
    mem("rax", 0), mem("rax", 0x20), mem("rax", index="rcx")
])
def test_memory_field_load_is_not_exact_same_pointer(source):
    result = place(ins(0x70, "mov", reg("rdi"), source))
    assert result["status"] == summaries.UNKNOWN


@pytest.mark.parametrize("source", [
    mem("rax", 0x10), mem("rax", index="rcx")
])
def test_interior_or_indexed_lea_cannot_prove_exact_identity(source):
    result = place(ins(0x70, "lea", reg("rdi"), source))
    assert result["status"] == summaries.UNKNOWN


def test_identity_lea_remains_proven():
    result = place(ins(0x70, "lea", reg("rdi"), mem("rax")))
    assert result["status"] == summaries.PROVEN


@pytest.mark.parametrize("destination,source", [
    ("edi", "eax"), ("rdi", "eax"), ("r8d", "eax"), ("si", "ax")
])
def test_partial_width_register_assignment_cannot_prove_pointer(destination, source):
    result = place(ins(0x70, "mov", reg(destination), reg(source)))
    assert result["status"] != summaries.PROVEN


def test_unrelated_argument_write_does_not_hide_another_argument():
    result = place(ins(0x70, "mov", reg("rsi"), reg("rax")),
                   ins(0x74, "mov", reg("rdi"), reg("rcx")))
    assert result["status"] == summaries.PROVEN
    assert result["argument"] == "rsi"


def test_latest_write_to_same_argument_wins():
    result = place(ins(0x70, "mov", reg("rdi"), reg("rax")),
                   ins(0x74, "mov", reg("rdi"), reg("rcx")))
    assert result["status"] == summaries.REFUTED


def test_branch_cannot_be_assumed_to_execute_argument_definition():
    result = place(ins(0x6c, "je"),
                   ins(0x70, "mov", reg("rdi"), reg("rax")))
    assert result["status"] == summaries.UNKNOWN


def test_second_operand_xchg_clobber_invalidates_earlier_placement():
    result = place(ins(0x70, "mov", reg("rdi"), reg("rax")),
                   ins(0x74, "xchg", reg("rbx"), reg("rdi")))
    assert result["status"] != summaries.PROVEN
