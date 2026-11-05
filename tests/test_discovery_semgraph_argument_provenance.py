"""Conservative A1-06 argument-placement counterexamples (synthetic operands).

These tests pin the semantics of Capstone operand types and register writes;
they do not claim firmware reachability or independently discovered exploits.
"""
from dataclasses import dataclass
from types import SimpleNamespace

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from tools.discovery.semgraph import _argument_carries


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
