"""Regression for the four REFUSE blockers in independent PR #14 review.

Compile original source-only x86-64 assembler snippets via GNU binutils and
decode through production FunctionView + real Capstone. No firmware bytes,
addresses, exploit labels, or mock instruction semantics are involved.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from tools.discovery.mustflow import must_argument_placement
from tools.discovery.patterns import FunctionView

BASE = 0x1000


def assembled(tmp_path: Path, body: str) -> bytes:
    source = tmp_path / "mustflow.S"
    obj = tmp_path / "mustflow.o"
    binary = tmp_path / "mustflow.bin"
    source.write_text(".intel_syntax noprefix\n.text\n.globl entry\nentry:\n"
                      + body + "\n", encoding="utf-8")
    subprocess.run(["as", "--64", "-o", str(obj), str(source)],
                   check=True, capture_output=True, text=True)
    subprocess.run(["objcopy", "-O", "binary", "--only-section=.text",
                    str(obj), str(binary)], check=True, capture_output=True, text=True)
    return binary.read_bytes()


def decoded(blob: bytes, *, size=None, strict=True):
    class Image:
        def disasm(self, addr, count, **_kwargs):
            cap = Cs(CS_ARCH_X86, CS_MODE_64)
            cap.detail = True
            return list(cap.disasm(blob[addr - BASE:addr - BASE + count], addr)), cap
    return FunctionView(Image(), BASE, len(blob) if size is None else size,
                        strict_cfg=strict)


def seed_and_call(view, source="rax"):
    seed = view.ins[0].address
    call_site = next(i.address for i in view.ins if i.mnemonic == "call")
    return must_argument_placement(view, call_site, source, seed)


def test_real_backedge_after_call_is_a_must_kill(tmp_path):
    blob = assembled(tmp_path, """
    mov rax, qword ptr [rbp-0x20]
    mov rdi, rax
again:
    call release_stub
    xor edi, edi
    jmp again
release_stub:
    ret
""")
    ans = seed_and_call(decoded(blob))
    assert ans["status"] == "unknown", ans
    assert "every path" in ans["why"], ans


def test_real_extent_truncation_does_not_invent_must_path(tmp_path):
    blob = assembled(tmp_path, """
    mov rax, qword ptr [rbp-0x20]
    test esi, esi
    jne skip
    mov rdi, rax
join:
    call release_stub
    jmp exit
skip:
    xor edi, edi
    jmp join
release_stub:
    ret
exit:
    ret
""")
    complete = decoded(blob)
    branch = next(i for i in complete.ins if i.mnemonic == "jne")
    branch_target = next(op.imm for op in branch.operands if op.type == 2)
    assert seed_and_call(complete)["status"] == "unknown"
    # Cut off the taken arm entirely. The branch still exists and points
    # beyond the indexed extent; it must not be silently treated as an exit.
    cut = branch_target - BASE
    incomplete = decoded(blob, size=cut)
    ans = seed_and_call(incomplete)
    assert ans["status"] == "unknown", ans
    assert "outside the decoded function extent" in ans["why"], ans


def test_real_ud2_rejects_non_strict_cfg_and_unreachable_call(tmp_path):
    blob = assembled(tmp_path, """
    mov rax, qword ptr [rbp-0x20]
    ud2
    mov rdi, rax
    call release_stub
release_stub:
    ret
""")
    loose = seed_and_call(decoded(blob, strict=False))
    strict = seed_and_call(decoded(blob, strict=True))
    assert loose["status"] == "unknown"
    assert "strict CFG" in loose["why"]
    assert strict["status"] == "unknown", strict


def test_real_unvalidated_seed_is_not_a_pointer_generation(tmp_path):
    blob = assembled(tmp_path, """
    mov rbx, rax
    mov rdi, rax
    call release_stub
release_stub:
    ret
""")
    ans = seed_and_call(decoded(blob), source="rbx")
    assert ans["status"] == "unknown", ans
    assert "64-bit memory load" in ans["why"], ans


@pytest.mark.parametrize("register", ["r8d", "r8w", "r8b"])
def test_real_partial_r8_alias_kills_full_pointer(tmp_path, register):
    blob = assembled(tmp_path, f"""
    mov r8, qword ptr [rbp-0x20]
    mov {register}, 0
    mov rdi, r8
    call release_stub
release_stub:
    ret
""")
    ans = seed_and_call(decoded(blob), source="r8")
    assert ans["status"] == "unknown", ans


def test_real_indexed_lea_never_preserves_exact_pointer(tmp_path):
    blob = assembled(tmp_path, """
    mov rax, qword ptr [rbp-0x20]
    lea rdi, [rax+rcx*2]
    call release_stub
release_stub:
    ret
""")
    ans = seed_and_call(decoded(blob))
    assert ans["status"] == "unknown", ans


def test_real_two_arm_positive_means_only_load_generation_reaches_call(tmp_path):
    blob = assembled(tmp_path, """
    mov rax, qword ptr [rbp-0x20]
    test esi, esi
    jne other
    mov rdi, rax
    jmp join
other:
    mov rdi, rax
join:
    call release_stub
release_stub:
    ret
""")
    ans = seed_and_call(decoded(blob))
    assert ans["status"] == "proved", ans
    assert ans["argument"] == "rdi"
    assert ans["producer_binding"] == "unverified"
    assert "generation_site" in ans and "acquisition" not in ans
