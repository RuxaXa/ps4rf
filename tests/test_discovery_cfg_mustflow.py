"""Source-only CFG must-reach positives and negatives for object argument transfer.

The independent FW review found that a linear backwards window refused 55/55
real candidate placements. These synthetic tests instead exercise every path
through the CFG and do not use PlayStation firmware, root-cause hints or PoCs.
"""
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from tools.discovery.mustflow import must_argument_placement


@dataclass
class Ins:
    address: int
    mnemonic: str
    operands: list
    op_str: str = "fixture"

    def reg_name(self, value):
        return value

    def regs_access(self):
        written = []
        if self.operands and self.operands[0].type == X86_OP_REG:
            if self.mnemonic not in ("cmp", "test"):
                written.append(self.operands[0].reg)
        if self.mnemonic == "xchg" and len(self.operands) > 1:
            written.append(self.operands[1].reg)
        return [], written


def reg(name):
    return SimpleNamespace(type=X86_OP_REG, reg=name)


def imm(target):
    return SimpleNamespace(type=X86_OP_IMM, imm=target)


def mem(base, disp=0, index=0):
    return SimpleNamespace(type=X86_OP_MEM,
                           mem=SimpleNamespace(base=base, disp=disp, index=index))


def ins(addr, name, dst=None, src=None):
    operands = [] if dst is None else [dst]
    if src is not None:
        operands.append(src)
    return Ins(addr, name, operands)


def call(addr):
    return ins(addr, "call", imm(0x1234))


def jne(addr, target):
    return ins(addr, "jne", imm(target))


def jump(addr, target):
    return ins(addr, "jmp", imm(target))


def view(blocks, successors):
    return SimpleNamespace(ins=[item for block in blocks.values() for item in block],
                           ins_by=blocks, succ=successors)


def straight(*instructions):
    return view({instructions[0].address: list(instructions)},
                {instructions[0].address: []})


def basic_two_branch(missing=False, partial=False, source="rax"):
    left = [ins(0x20, "mov", reg("rdi"), reg(source)), jump(0x24, 0x40)]
    right = ([ins(0x30, "nop")] if missing else
             [ins(0x30, "mov", reg("rdi"), reg(source))])
    if partial:
        right.append(ins(0x34, "mov", reg("edi"), reg("eax")))
    return view({
        0x10: [call(0x10), jne(0x14, 0x30)],
        0x20: left, 0x30: right, 0x40: [call(0x40)],
    }, {0x10: [0x20, 0x30], 0x20: [0x40],
        0x30: [0x40], 0x40: []})


def result(body, acq=0x10, target=0x40, source="rax", budget=20000):
    return must_argument_placement(body, target, source, acq, max_states=budget)


def test_simple_full_width_caller_argument_is_proved():
    body = straight(call(0x10), ins(0x20, "mov", reg("rdi"), reg("rax")),
                    call(0x40))
    witness = result(body)
    assert witness["status"] == "proved"
    assert witness["argument"] == "rdi"
    assert witness["kind"] == "cfg-must-reach"
    assert witness["acquisition"] == "0x10"


def test_two_branch_paths_both_carry_object():
    assert result(basic_two_branch())["status"] == "proved"


def test_branch_that_skips_argument_definition_must_refuse():
    answer = result(basic_two_branch(missing=True))
    assert answer["status"] == "unknown"
    assert "every path" in answer["why"]


def test_partial_width_write_on_one_arm_invalidates_identity():
    assert result(basic_two_branch(partial=True))["status"] == "unknown"


def test_acquisition_bypass_is_not_a_must_proof():
    body = view({
        0x00: [jne(0x00, 0x40)],
        0x10: [call(0x10), ins(0x20, "mov", reg("rdi"), reg("rax"))],
        0x40: [call(0x40)],
    }, {0x00: [0x10, 0x40], 0x10: [0x40], 0x40: []})
    assert result(body)["status"] == "unknown"


def test_intervening_call_kills_caller_saved_argument():
    body = straight(call(0x10), ins(0x20, "mov", reg("rdi"), reg("rax")),
                    call(0x30), call(0x40))
    assert result(body)["status"] == "unknown"


def test_callee_saved_object_register_survives_intervening_call():
    body = straight(ins(0x10, "mov", reg("rbx"), mem("rax")),
                    call(0x20), ins(0x30, "mov", reg("rdi"), reg("rbx")),
                    call(0x40))
    assert result(body, source="rbx")["status"] == "proved"


def test_interior_lea_does_not_carry_same_object():
    body = straight(call(0x10),
                    ins(0x20, "lea", reg("rdi"), mem("rax", disp=0x18)),
                    call(0x40))
    assert result(body)["status"] == "unknown"


def test_identity_lea_is_full_width_same_pointer():
    body = straight(call(0x10),
                    ins(0x20, "lea", reg("rdi"), mem("rax")),
                    call(0x40))
    assert result(body)["status"] == "proved"


def test_partial_width_source_is_never_full_pointer():
    assert result(basic_two_branch(), source="eax")["status"] == "unknown"


def test_partial_width_move_is_not_full_pointer():
    body = straight(call(0x10), ins(0x20, "mov", reg("edi"), reg("eax")),
                    call(0x40))
    assert result(body)["status"] == "unknown"


def test_indirect_branch_refuses_until_cfg_is_complete():
    body = view({0x10: [call(0x10), ins(0x20, "jmp", reg("rax"))],
                 0x40: [call(0x40)]},
                {0x10: [], 0x40: []})
    assert "indirect" in result(body)["why"]


def test_missing_branch_target_refuses():
    body = view({0x10: [call(0x10), jne(0x20, 0x80)],
                 0x40: [call(0x40)]},
                {0x10: [], 0x40: []})
    assert "conditional branch" in result(body)["why"]


def test_invalid_or_exhausted_budget_is_unknown():
    for budget in (0, 1):
        answer = result(basic_two_branch(), budget=budget)
        assert answer["status"] == "unknown"


def test_unreachable_target_does_not_make_a_proved_argument():
    body = view({0x10: [call(0x10), jump(0x20, 0x30)],
                 0x30: [ins(0x30, "ret")],
                 0x40: [call(0x40)]},
                {0x10: [0x30], 0x30: [], 0x40: []})
    assert result(body)["status"] == "unknown"


def test_branch_can_put_object_in_different_arguments_but_not_prove_one():
    body = view({
        0x10: [call(0x10), jne(0x14, 0x30)],
        0x20: [ins(0x20, "mov", reg("rdi"), reg("rax")), jump(0x24, 0x40)],
        0x30: [ins(0x30, "mov", reg("rsi"), reg("rax"))],
        0x40: [call(0x40)],
    }, {0x10: [0x20, 0x30], 0x20: [0x40],
        0x30: [0x40], 0x40: []})
    assert result(body)["status"] == "unknown"


@pytest.mark.parametrize("clobber", ("ebx", "bx", "bl", "bh"))
def test_alias_clobbers_callee_saved_pointer_generation(clobber):
    body = straight(ins(0x10, "mov", reg("rbx"), mem("rax")),
                    ins(0x20, "mov", reg(clobber), reg("eax")),
                    ins(0x30, "mov", reg("rdi"), reg("rbx")),
                    call(0x40))
    assert result(body, source="rbx")["status"] == "unknown"
