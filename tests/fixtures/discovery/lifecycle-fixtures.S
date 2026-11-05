/* D1/D4 ownership and table-slot fixtures.  Architecture fixtures, not firmware
 * reproductions: no function name, syscall number, firmware offset or exploit
 * signature is consumed by the detectors.  The only addresses that matter are
 * the *_free / *_alloc roots, and those are supplied as data by the test. */

.text

/* ---------------------------------------------------------------- roots */

.p2align 4
.globl own_free
.type own_free,@function
own_free:
    ret
.size own_free, .-own_free

.p2align 4
.globl own_alloc
.type own_alloc,@function
own_alloc:
    ret
.size own_alloc, .-own_alloc

/* Unknown effect: never reached from a catalog entry, so it stays unknown. */
.p2align 4
.globl own_unknown
.type own_unknown,@function
own_unknown:
    ret
.size own_unknown, .-own_unknown

/* ------------------------------------------------------- catalog growth */

/* Degenerate forward: a thunk. */
.p2align 4
.globl own_thunk
.type own_thunk,@function
own_thunk:
    jmp own_free
.size own_thunk, .-own_thunk

/* Real forward: its own pointer argument reaches the release unchanged. */
.p2align 4
.globl own_forward
.type own_forward,@function
own_forward:
    pushq %rbp
    movq %rsp, %rbp
    call own_free
    popq %rbp
    ret
.size own_forward, .-own_forward

/* Negative: the argument is replaced, so this is NOT a release wrapper. */
.p2align 4
.globl own_wrapper_bad
.type own_wrapper_bad,@function
own_wrapper_bad:
    pushq %rbp
    movq %rsp, %rbp
    xorl %edi, %edi
    call own_free
    popq %rbp
    ret
.size own_wrapper_bad, .-own_wrapper_bad

/* Conditional: frees only when its second argument is non-zero.  Derived from the
 * anchor like any forward, but the branch before the call makes it conditional --
 * a caller cannot conclude that its pointer was freed. */
.p2align 4
.globl own_cond_free
.type own_cond_free,@function
own_cond_free:
    pushq %rbp
    movq %rsp, %rbp
    testq %rsi, %rsi
    je .L_cf_done
    call own_free
.L_cf_done:
    popq %rbp
    ret
.size own_cond_free, .-own_cond_free

/* ------------------------------------------------------------- D1 cases */

/* Positive: released through one alias, used through a stale slot copy. */
.p2align 4
.globl fixture_d1_direct
.type fixture_d1_direct,@function
fixture_d1_direct:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    subq $0x18, %rsp
    movq %rdi, %rbx
    movq %rbx, -0x18(%rbp)
    movq %rbx, %rdi
    call own_free
    movq -0x18(%rbp), %rax
    movq 0x8(%rax), %rdx
    addq $0x18, %rsp
    popq %rbx
    popq %rbp
    ret
.size fixture_d1_direct, .-fixture_d1_direct

/* Negative: the reference is invalidated, so the later load cannot be stale. */
.p2align 4
.globl fixture_d1_invalidated
.type fixture_d1_invalidated,@function
fixture_d1_invalidated:
    pushq %rbp
    movq %rsp, %rbp
    movq %rdi, -0x8(%rbp)
    call own_free
    movq $0, -0x8(%rbp)
    movq -0x8(%rbp), %rax
    testq %rax, %rax
    je .L_inv_done
    movq 0x8(%rax), %rdx
.L_inv_done:
    popq %rbp
    ret
.size fixture_d1_invalidated, .-fixture_d1_invalidated

/* Negative: the slot is reused for a *different* object after the release. */
.p2align 4
.globl fixture_d1_slot_reuse
.type fixture_d1_slot_reuse,@function
fixture_d1_slot_reuse:
    pushq %rbp
    movq %rsp, %rbp
    movq %rdi, -0x8(%rbp)
    call own_free
    movq %rsi, -0x8(%rbp)
    movq -0x8(%rbp), %rax
    movq 0x8(%rax), %rdx
    popq %rbp
    ret
.size fixture_d1_slot_reuse, .-fixture_d1_slot_reuse

/* Positive: two live aliases, one released, the other used. */
.p2align 4
.globl fixture_d1_alias
.type fixture_d1_alias,@function
fixture_d1_alias:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    movq %rdi, %rbx
    movq %rdi, %r12
    movq %rbx, %rdi
    call own_free
    movq 0x10(%r12), %rax
    popq %r12
    popq %rbx
    popq %rbp
    ret
.size fixture_d1_alias, .-fixture_d1_alias

/* Path dependent: released on one arm only, used after the merge. */
.p2align 4
.globl fixture_d1_path
.type fixture_d1_path,@function
fixture_d1_path:
    pushq %rbp
    movq %rsp, %rbp
    movq %rdi, -0x8(%rbp)
    testq %rsi, %rsi
    je .L_path_merge
    call own_free
.L_path_merge:
    movq -0x8(%rbp), %rax
    movq 0x8(%rax), %rdx
    popq %rbp
    ret
.size fixture_d1_path, .-fixture_d1_path

/* Unknown side effect: a call whose effect is not modelled may have freed it. */
.p2align 4
.globl fixture_d1_unknown_effect
.type fixture_d1_unknown_effect,@function
fixture_d1_unknown_effect:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    call own_unknown
    movq %rax, %rbx
    movq %rax, %rdi
    call own_unknown
    movq 0x8(%rbx), %rdx
    popq %rbx
    popq %rbp
    ret
.size fixture_d1_unknown_effect, .-fixture_d1_unknown_effect

/* ------------------------------------------------------------- D4 cases */

/* Positive: released through the slot, reloaded with the same index. */
.p2align 4
.globl fixture_d4_same_index
.type fixture_d4_same_index,@function
fixture_d4_same_index:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    movq %rdi, %r12
    movq 0x30(%rbp), %r13
    movq (%r12,%r13,8), %rbx
    movq %rbx, %rdi
    call own_free
    movq (%r12,%r13,8), %rax
    movq 0x8(%rax), %rdx
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret
.size fixture_d4_same_index, .-fixture_d4_same_index

/* Positive: the same slot written as lea + dereference instead of an index. */
.p2align 4
.globl fixture_d4_lea_equal
.type fixture_d4_lea_equal,@function
fixture_d4_lea_equal:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    movq %rdi, %r12
    movq 0x30(%rbp), %r13
    movq (%r12,%r13,8), %rbx
    movq %rbx, %rdi
    call own_free
    leaq (%r12,%r13,8), %rcx
    movq (%rcx), %rax
    movq 0x8(%rax), %rdx
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret
.size fixture_d4_lea_equal, .-fixture_d4_lea_equal

/* Positive: index scaled by shift+add instead of a hardware scale. */
.p2align 4
.globl fixture_d4_shift_equal
.type fixture_d4_shift_equal,@function
fixture_d4_shift_equal:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    movq %rdi, %r12
    movq 0x30(%rbp), %r13
    movq (%r12,%r13,8), %rbx
    movq %rbx, %rdi
    call own_free
    movq %r13, %rax
    shlq $3, %rax
    addq %r12, %rax
    movq (%rax), %rdx
    movq 0x8(%rdx), %rcx
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret
.size fixture_d4_shift_equal, .-fixture_d4_shift_equal

/* Ambiguous: a different index is a different slot, so this is only a may-alias. */
.p2align 4
.globl fixture_d4_other_index
.type fixture_d4_other_index,@function
fixture_d4_other_index:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    movq %rdi, %r12
    movq 0x30(%rbp), %r13
    movq 0x38(%rbp), %r14
    movq (%r12,%r13,8), %rbx
    movq %rbx, %rdi
    call own_free
    movq (%r12,%r14,8), %rax
    movq 0x8(%rax), %rdx
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret
.size fixture_d4_other_index, .-fixture_d4_other_index

/* Negative: the slot is cleared before it is read again. */
.p2align 4
.globl fixture_indirect_call
.type fixture_indirect_call,@function
fixture_indirect_call:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    movq %rdi, %rbx
    movq 0x10(%rbx), %rax
    call *%rax
    movq %rbx, %rdi
    call own_free
    movq 0x8(%rbx), %rdx
    popq %rbx
    popq %rbp
    ret
.size fixture_indirect_call, .-fixture_indirect_call

.p2align 4
.globl fixture_d4_cleared
.type fixture_d4_cleared,@function
fixture_d4_cleared:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    movq %rdi, %r12
    movq 0x30(%rbp), %r13
    movq (%r12,%r13,8), %rbx
    movq %rbx, %rdi
    call own_free
    movq $0, (%r12,%r13,8)
    movq (%r12,%r13,8), %rax
    movq 0x8(%rax), %rdx
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret
.size fixture_d4_cleared, .-fixture_d4_cleared

/* ================================================================ S1.2b
 * Counterexamples for the four soundness defects proved in the S1.2b review.
 * Each one is a shape the baseline gets wrong: it either confirms something it
 * cannot prove or drops something it should have reported.
 * ====================================================================== */

/* P0-2 -- the pointer is one of two objects when it is released.
 * "rdi may be A or B" is a may-release of both, never a definite release. */
.p2align 4
.globl fixture_p0_2_may_release
.type fixture_p0_2_may_release,@function
fixture_p0_2_may_release:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    movq %rdi, %rbx
    movq %rsi, %r12
    testq %rdx, %rdx
    je .L_mr_second
    movq %rbx, %rdi
    jmp .L_mr_release
.L_mr_second:
    movq %r12, %rdi
.L_mr_release:
    call own_free
    movq 0x8(%rbx), %rax
    popq %r12
    popq %rbx
    popq %rbp
    ret
.size fixture_p0_2_may_release, .-fixture_p0_2_may_release

/* P0-3a -- tail jump into the conditional wrapper.  A jump is a call in all but
 * spelling: it must not turn "frees on some path" into a definite release. */
.p2align 4
.globl fixture_p0_3_tail_cond
.type fixture_p0_3_tail_cond,@function
fixture_p0_3_tail_cond:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    movq %rdi, %rbx
    movq %rbx, -0x10(%rbp)
    movq -0x10(%rbp), %rdi
    movq $1, %rsi
    popq %rbx
    popq %rbp
    jmp own_cond_free
.size fixture_p0_3_tail_cond, .-fixture_p0_3_tail_cond

/* P0-3b -- call into the conditional wrapper, then a read.  "Freed on some path"
 * is a may-release: reportable as an observation, never as a confirmed defect. */
.p2align 4
.globl fixture_p0_3_cond_caller
.type fixture_p0_3_cond_caller,@function
fixture_p0_3_cond_caller:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    movq %rdi, %rbx
    movq $1, %rsi
    call own_cond_free
    movq 0x8(%rbx), %rax
    popq %rbx
    popq %rbp
    ret
.size fixture_p0_3_cond_caller, .-fixture_p0_3_cond_caller

/* P0-4a -- loop carried: the read sits in the block *before* the block that
 * frees, and only the back edge orders them.  The use in iteration n+1 follows
 * the free in iteration n. */
.p2align 4
.globl fixture_p0_4_loop_carried
.type fixture_p0_4_loop_carried,@function
fixture_p0_4_loop_carried:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    movq %rdi, %rbx
    xorl %ecx, %ecx
.L_lc_top:
    movq 0x8(%rbx), %rax
    incl %ecx
    cmpl $3, %ecx
    jl .L_lc_free
    jmp .L_lc_done
.L_lc_free:
    movq %rbx, %rdi
    call own_free
    jmp .L_lc_top
.L_lc_done:
    popq %rbx
    popq %rbp
    ret
.size fixture_p0_4_loop_carried, .-fixture_p0_4_loop_carried

/* P0-4b -- recycling: one call site allocates a fresh object every iteration.
 * Freeing the previous one and then using the new one is not a use-after-free. */
.p2align 4
.globl fixture_p0_4_loop_recycle
.type fixture_p0_4_loop_recycle,@function
fixture_p0_4_loop_recycle:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    xorl %ecx, %ecx
    call own_alloc
    movq %rax, %rbx
.L_lr_top:
    movq %rbx, %r12
    movq %rbx, %rdi
    call own_free
    call own_alloc
    movq %rax, %rbx
    movq 0x8(%rbx), %rdx
    incl %ecx
    cmpl $3, %ecx
    jl .L_lr_top
    popq %r12
    popq %rbx
    popq %rbp
    ret
.size fixture_p0_4_loop_recycle, .-fixture_p0_4_loop_recycle

/* P0-1a -- the slot holds one of two live objects after the merge.  The reload is
 * a may-set, so releasing it is a may-release of two candidates. */
.p2align 4
.globl fixture_p0_1_approx_may_set
.type fixture_p0_1_approx_may_set,@function
fixture_p0_1_approx_may_set:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    movq %rdi, %rbx
    movq %rsi, %r12
    movq %rdx, %r13
    testq %rcx, %rcx
    je .L_am_second
    movq %r12, 0x18(%rbx)
    jmp .L_am_merge
.L_am_second:
    movq %r13, 0x18(%rbx)
.L_am_merge:
    movq 0x18(%rbx), %rax
    movq %rax, %rdi
    call own_free
    movq 0x8(%r12), %rdx
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret
.size fixture_p0_1_approx_may_set, .-fixture_p0_1_approx_may_set

/* P0-1b -- the slot is read while it was never written, then written on both
 * arms, then read again.  The merged slot is a *different* identity from the
 * never-written slot: collapsing the two is what confirmed a use-after-free. */
.p2align 4
.globl fixture_p0_1_never_vs_merged
.type fixture_p0_1_never_vs_merged,@function
fixture_p0_1_never_vs_merged:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    movq %rdi, %rbx
    movq %rsi, %r12
    movq %rdx, %r13
    movq 0x18(%rbx), %rax
    movq %rax, %rdi
    call own_free
    testq %rcx, %rcx
    je .L_nm_second
    movq %r12, 0x18(%rbx)
    jmp .L_nm_merge
.L_nm_second:
    movq %r13, 0x18(%rbx)
.L_nm_merge:
    movq 0x18(%rbx), %rax
    movq 0x8(%rax), %rdx
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret
.size fixture_p0_1_never_vs_merged, .-fixture_p0_1_never_vs_merged

/* P1a -- store kill: the slot is released and then *overwritten* with a live
 * object.  The reload must be the new object, so there is nothing to report. */
.p2align 4
.globl fixture_p1_store_kill
.type fixture_p1_store_kill,@function
fixture_p1_store_kill:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    movq %rdi, %rbx
    movq %rsi, %r12
    movq 0x118(%rbx), %r13
    movq %r13, %rdi
    call own_free
    movq %r12, 0x118(%rbx)
    movq 0x118(%rbx), %rax
    movq 0x8(%rax), %rdx
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret
.size fixture_p1_store_kill, .-fixture_p1_store_kill

/* P1b -- out parameter: the slot is written with A, its address is handed to an
 * unknown call, and the reload is freed.  The stored object must stay a
 * candidate, so the later use of A is an observation, not silence. */
.p2align 4
.globl fixture_p1_outparam
.type fixture_p1_outparam,@function
fixture_p1_outparam:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    movq %rdi, %rbx
    movq %rsi, %r12
    movq %r12, 0x10(%rbx)
    leaq 0x10(%rbx), %rdi
    call own_unknown
    movq 0x10(%rbx), %rax
    movq %rax, %rdi
    call own_free
    movq 0x8(%r12), %rdx
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret
.size fixture_p1_outparam, .-fixture_p1_outparam
