/* D3 semantic lock-scope fixtures.  These are architecture fixtures, not
 * firmware reproductions: no function name, syscall number, firmware offset or
 * exploit signature is consumed by the detector. */

.text
.p2align 4
.globl lock_acquire
.type lock_acquire,@function
lock_acquire:
    movq %gs:0, %rbx
    xorl %eax, %eax
    lock cmpxchgq %rbx, 0x18(%rdi)
    ret
.size lock_acquire, .-lock_acquire

.p2align 4
.globl lock_release
.type lock_release,@function
lock_release:
    movq %gs:0, %rax
    movq $4, %rcx
    lock cmpxchgq %rcx, 0x18(%rdi)
    ret
.size lock_release, .-lock_release

/* Reader-mode primitive: CAS increments/decrements the encoded reader count. */
.p2align 4
.globl rw_read_acquire
.type rw_read_acquire,@function
rw_read_acquire:
    movq 0x18(%rdi), %rax
    leaq 0x10(%rax), %rcx
    lock cmpxchgq %rcx, 0x18(%rdi)
    ret
.size rw_read_acquire, .-rw_read_acquire

.p2align 4
.globl rw_read_release
.type rw_read_release,@function
rw_read_release:
    movq 0x18(%rdi), %rax
    leaq -0x10(%rax), %rcx
    lock cmpxchgq %rcx, 0x18(%rdi)
    ret
.size rw_read_release, .-rw_read_release

.p2align 4
.globl release_object
.type release_object,@function
release_object:
    ret
.size release_object, .-release_object

/* Positive: the merge can be reached with or without the lock. */
.p2align 4
.globl fixture_missing_lock
.type fixture_missing_lock,@function
fixture_missing_lock:
    pushq %rbp
    movq %rsp, %rbp
    movq %rdi, -8(%rbp)
    testl %esi, %esi
    je .Lmissing_merge
    movq -8(%rbp), %rdi
    call lock_acquire
.Lmissing_merge:
    movq -8(%rbp), %rdi
    call release_object
    leave
    ret
.size fixture_missing_lock, .-fixture_missing_lock

/* Negative: the release is dominated by acquire and followed by release. */
.p2align 4
.globl fixture_protected
.type fixture_protected,@function
fixture_protected:
    pushq %rbp
    movq %rsp, %rbp
    movq %rdi, -8(%rbp)
    movq -8(%rbp), %rdi
    call lock_acquire
    movq -8(%rbp), %rdi
    call release_object
    movq -8(%rbp), %rdi
    call lock_release
    leave
    ret
.size fixture_protected, .-fixture_protected

/* Negative coverage: a lock on arg0 cannot protect a mutation of arg1. */
.p2align 4
.globl fixture_different_lock
.type fixture_different_lock,@function
fixture_different_lock:
    pushq %rbp
    movq %rsp, %rbp
    movq %rdi, -8(%rbp)
    movq %rsi, -16(%rbp)
    movq -8(%rbp), %rdi
    call lock_acquire
    movq -16(%rbp), %rdi
    call release_object
    movq -8(%rbp), %rdi
    call lock_release
    leave
    ret
.size fixture_different_lock, .-fixture_different_lock

/* Positive alias resolution: all three calls reload the same stack-home object. */
.p2align 4
.globl fixture_alias
.type fixture_alias,@function
fixture_alias:
    pushq %rbp
    movq %rsp, %rbp
    movq %rdi, -8(%rbp)
    movq -8(%rbp), %rdi
    call lock_acquire
    movq -8(%rbp), %rdi
    call release_object
    movq -8(%rbp), %rdi
    call lock_release
    leave
    ret
.size fixture_alias, .-fixture_alias

/* Early return: both exits release; the mutation remains dominated by acquire. */
.p2align 4
.globl fixture_early_return
.type fixture_early_return,@function
fixture_early_return:
    pushq %rbp
    movq %rsp, %rbp
    movq %rdi, -8(%rbp)
    movq -8(%rbp), %rdi
    call lock_acquire
    testl %esi, %esi
    je .Learly
    movq -8(%rbp), %rdi
    call release_object
    movq -8(%rbp), %rdi
    call lock_release
    leave
    ret
.Learly:
    movq -8(%rbp), %rdi
    call lock_release
    leave
    ret
.size fixture_early_return, .-fixture_early_return

/* Generic return-object claim: acquire, stamp owner, release lock, return obj. */
.p2align 4
.globl claim_object
.type claim_object,@function
claim_object:
    pushq %rbp
    movq %rsp, %rbp
    movq %rdi, -8(%rbp)
    call lock_acquire
    movq -8(%rbp), %rcx
    movq %gs:0, %rax
    movq %rax, 0x20(%rcx)
    movq -8(%rbp), %rdi
    call lock_release
    movq -8(%rbp), %rax
    leave
    ret
.size claim_object, .-claim_object

/* A reader claim aliases the object but cannot protect a write mutation. */
.p2align 4
.globl claim_shared_object
.type claim_shared_object,@function
claim_shared_object:
    pushq %rbp
    movq %rsp, %rbp
    movq %rdi, -8(%rbp)
    call lock_acquire
    movq -8(%rbp), %rcx
    movq %gs:0, %rax
    movq %rax, 0x20(%rcx)
    movq -8(%rbp), %rdi
    call lock_release
    movq -8(%rbp), %rdi
    call rw_read_acquire
    movq -8(%rbp), %rax
    leave
    ret
.size claim_shared_object, .-claim_shared_object

.p2align 4
.globl fixture_shared_claim_write
.type fixture_shared_claim_write,@function
fixture_shared_claim_write:
    pushq %rbp
    movq %rsp, %rbp
    call claim_shared_object
    movw $0, 2(%rax)
    leave
    ret
.size fixture_shared_claim_write, .-fixture_shared_claim_write

/* A curthread spill to the stack is not an object ownership stamp. */
.p2align 4
.globl not_claim_stack
.type not_claim_stack,@function
not_claim_stack:
    pushq %rbp
    movq %rsp, %rbp
    movq %rdi, -8(%rbp)
    call lock_acquire
    movq %gs:0, %rax
    movq %rax, -16(%rbp)
    movq -8(%rbp), %rdi
    call lock_release
    movq -8(%rbp), %rax
    leave
    ret
.size not_claim_stack, .-not_claim_stack

/* Same-object claim exists on only one incoming path. */
.p2align 4
.globl fixture_claim_missing
.type fixture_claim_missing,@function
fixture_claim_missing:
    pushq %rbp
    movq %rsp, %rbp
    movq %rdi, -8(%rbp)
    testl %esi, %esi
    je .Lclaim_skipped
    movq -8(%rbp), %rdi
    call claim_object
    jmp .Lclaim_merge
.Lclaim_skipped:
    movq -8(%rbp), %rax
.Lclaim_merge:
    movw $0, 2(%rax)
    leave
    ret
.size fixture_claim_missing, .-fixture_claim_missing

/* Same-object claim dominates the mutation. */
.p2align 4
.globl fixture_claim_fixed
.type fixture_claim_fixed,@function
fixture_claim_fixed:
    pushq %rbp
    movq %rsp, %rbp
    movq %rdi, -8(%rbp)
    movq -8(%rbp), %rdi
    call claim_object
    movw $0, 2(%rax)
    leave
    ret
.size fixture_claim_fixed, .-fixture_claim_fixed

/* Unknown call effects must poison the state, never become NOT_HELD. */
.p2align 4
.globl fixture_unknown
.type fixture_unknown,@function
fixture_unknown:
    pushq %rbp
    movq %rsp, %rbp
    movq %rdi, -8(%rbp)
    call *%rax
    movq -8(%rbp), %rdi
    call release_object
    leave
    ret
.size fixture_unknown, .-fixture_unknown
