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
    assert "conditional" in result(body)["why"]


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


def test_missing_taken_arm_is_not_a_false_must_proof():
    body = view({
        0x10: [call(0x10), jne(0x14, 0x30)],
        0x20: [ins(0x20, "mov", reg("rdi"), reg("rax"))],
        0x30: [ins(0x30, "nop")],
        0x40: [call(0x40)],
    }, {0x10: [0x20], 0x20: [0x40],
        0x30: [0x40], 0x40: []})
    answer = result(body)
    assert answer["status"] == "unknown"
    assert "taken edge" in answer["why"]


def test_missing_fallthrough_arm_is_not_a_false_must_proof():
    body = view({
        0x10: [call(0x10), jne(0x14, 0x30)],
        0x20: [ins(0x20, "nop")],
        0x30: [ins(0x30, "mov", reg("rdi"), reg("rax"))],
        0x40: [call(0x40)],
    }, {0x10: [0x30], 0x20: [0x40],
        0x30: [0x40], 0x40: []})
    answer = result(body)
    assert answer["status"] == "unknown"
    assert "fall-through" in answer["why"]


def test_real_capstone_decoder_uses_same_cfg_and_pointer_rules():
    """Pinned assembled fixture, not an abstract mock or a PlayStation image."""
    import json
    from pathlib import Path
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from tools.discovery.patterns import FunctionView

    root = Path(__file__).resolve().parent / "fixtures" / "discovery"
    doc = json.loads((root / "a1-regressions.json").read_text(encoding="utf-8"))

    class Image:
        def __init__(self):
            self.base = int(doc["base_rva"], 16)
            self.data = bytes.fromhex(doc["image_hex"])

        def disasm(self, addr, size, **_kwargs):
            engine = Cs(CS_ARCH_X86, CS_MODE_64)
            engine.detail = True
            blob = self.data[addr-self.base:addr-self.base+size]
            return list(engine.disasm(blob, addr)), engine

    image = Image()

    def fixture(name):
        record = doc["symbols"][name]
        view = FunctionView(image, int(record["rva"], 16),
                            int(record["size"], 16))
        return view, view.ins[0].address, next(
            i.address for i in view.ins if i.mnemonic == "call")

    # The positive tests *only register identity* after a seeded first
    # instruction. They do not claim that the fixture allocated an object.
    view_positive, seed, call_site = fixture("pass_in_arg")
    assert must_argument_placement(view_positive, call_site, "rdi", seed)[
        "status"] == "proved"

    view_negative, seed, call_site = fixture("pass_other_object")
    assert must_argument_placement(view_negative, call_site, "rax", seed)[
        "status"] == "unknown"

    view_interior, seed, call_site = fixture("pass_by_lea")
    assert must_argument_placement(view_interior, call_site, "rax", seed)[
        "status"] == "unknown"
