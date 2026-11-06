"""Callee-summary caller-placement regression cases (synthetic instructions).

These cases test exact 64-bit pointer identity, not a general same-allocation
relationship.  A field load, interior address, or 32-bit truncation must not
be silently upgraded to a PROVEN ownership transfer.
"""
from dataclasses import dataclass
from types import SimpleNamespace
import pytest

from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM
from tools.discovery import summaries


@dataclass
class FakeInstruction:
    address: int
    mnemonic: str
    operands: tuple
    op_str: str = "synthetic"

    def reg_name(self, number):
        return number


def reg(name):
    return SimpleNamespace(type=X86_OP_REG, reg=name)


def imm(value):
    return SimpleNamespace(type=X86_OP_IMM, imm=value)


def memory(base, displacement=0, index=0):
    return SimpleNamespace(
        type=X86_OP_MEM,
        mem=SimpleNamespace(base=base, disp=displacement, index=index),
    )


def insn(site, mnemonic, dst=None, src=None):
    operands = tuple(v for v in (dst, src) if v is not None)
    return FakeInstruction(site, mnemonic, operands)


def call():
    return insn(0x30, "call")


def place(*instructions, object_register="rax"):
    view = SimpleNamespace(ins=list(instructions) + [call()])
    return summaries._placement_for(view, 0x30, object_register)


@pytest.mark.parametrize("source,mnemonic", [
    (memory("rax", 0x20), "mov"),
    (memory("rax", 0), "mov"),
    (memory("rax", 0x10), "lea"),
    (memory("rax", 0, index="rcx"), "lea"),
])
def test_field_load_or_interior_address_never_proves_exact_identity(source, mnemonic):
    result = place(insn(0x10, mnemonic, reg("rdi"), source))
    assert result["status"] == summaries.UNKNOWN


def test_identity_lea_without_offset_is_exact_placement():
    result = place(insn(0x10, "lea", reg("rdi"), memory("rax", 0)))
    assert result["status"] == summaries.PROVEN
    assert result["argument"] == "rdi"


@pytest.mark.parametrize("dst,src", [
    ("edi", "eax"), ("di", "ax"), ("dil", "al"),
    ("r8d", "eax"), ("r8w", "ax"), ("r8b", "al"),
])
def test_partial_register_move_does_not_prove_pointer_identity(dst, src):
    result = place(insn(0x10, "mov", reg(dst), reg(src)))
    assert result["status"] == summaries.UNKNOWN


def test_full_register_move_is_proven():
    result = place(insn(0x10, "mov", reg("rdi"), reg("rax")))
    assert result["status"] == summaries.PROVEN
    assert result["argument"] == "rdi"


def test_unrelated_argument_does_not_hide_proven_second_argument():
    result = place(insn(0x10, "mov", reg("rsi"), reg("rax")),
                   insn(0x18, "mov", reg("rdi"), reg("rbx")))
    assert result["status"] == summaries.PROVEN
    assert result["argument"] == "rsi"


def test_nearest_redefinition_of_same_register_still_wins():
    result = place(insn(0x10, "mov", reg("rdi"), reg("rax")),
                   insn(0x18, "mov", reg("rdi"), reg("rbx")))
    assert result["status"] == summaries.UNKNOWN


def test_unknown_first_argument_does_not_hide_proven_second_argument():
    result = place(insn(0x10, "mov", reg("rsi"), reg("rax")),
                   insn(0x18, "mov", reg("rdi"), memory("rax", 0x20)))
    assert result["status"] == summaries.PROVEN
    assert result["argument"] == "rsi"


def test_no_setup_remains_unknown():
    assert place()["status"] == summaries.UNKNOWN


def test_a_direct_branch_can_bypass_argument_setup():
    result = place(insn(0x05, "je", imm(0x30)),
                   insn(0x10, "mov", reg("rdi"), reg("rax")))
    assert result["status"] == summaries.UNKNOWN


def test_an_xchg_clobber_invalidates_earlier_argument_setup():
    result = place(insn(0x10, "mov", reg("rdi"), reg("rax")),
                   insn(0x18, "xchg", reg("rbx"), reg("rdi")))
    assert result["status"] == summaries.UNKNOWN


def test_distinct_register_values_are_not_evidence_of_distinct_objects():
    result = place(insn(0x10, "mov", reg("rdi"), reg("rcx")))
    assert result["status"] == summaries.UNKNOWN
