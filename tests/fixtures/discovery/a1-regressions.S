/* A1 review regressions: the four shapes the independent audit named.
 *
 * Every function here is deliberately tiny and contains exactly one property, so a
 * test can point at the instruction that decides it.  The image is assembled by real
 * binutils and decoded through the same capstone path as the firmware.
 *
 *   guard_unrelated_cmp : a refcount decrement followed by an unrelated compare and
 *                         a release call -- the audit's A1-04 counterexample
 *   guard_equal_one     : the same decrement, but a real "count == 1" test gates the
 *                         release -- the positive control for the same detector
 *   guard_no_branch     : a count compare whose flags nobody consumes
 *   store_vs_load       : one memory store and one memory load, so a summary can be
 *                         checked for recording the store and not the load (A1-05)
 */
.intel_syntax noprefix
.text

.globl own_fdrop_like
.type own_fdrop_like, @function
own_fdrop_like:
    ret
.size own_fdrop_like, .-own_fdrop_like

.globl guard_unrelated_cmp
.type guard_unrelated_cmp, @function
guard_unrelated_cmp:
    lock dec dword ptr [rdi+0x28]
    cmp eax, 0x10
    call own_fdrop_like
    ret
.size guard_unrelated_cmp, .-guard_unrelated_cmp

.globl guard_equal_one
.type guard_equal_one, @function
guard_equal_one:
    lock dec dword ptr [rdi+0x28]
    cmp dword ptr [rdi+0x28], 1
    jne 1f
    call own_fdrop_like
1:
    ret
.size guard_equal_one, .-guard_equal_one

.globl guard_no_branch
.type guard_no_branch, @function
guard_no_branch:
    lock dec dword ptr [rdi+0x28]
    cmp eax, 1
    call own_fdrop_like
    ret
.size guard_no_branch, .-guard_no_branch

.globl store_vs_load
.type store_vs_load, @function
store_vs_load:
    mov dword ptr [rdi+0x10], eax
    mov eax, dword ptr [rdi+0x20]
    ret
.size store_vs_load, .-store_vs_load

/* A1-06: the same object register rax reaches the release call in two different
 * ways.  In pass_in_arg it is moved into rdi, the first System V argument register,
 * so the callee provably receives it.  In pass_in_nonarg it is parked in rbx, which
 * the call does not receive, so nothing proves the callee acts on this object. */
.globl pass_in_arg
.type pass_in_arg, @function
pass_in_arg:
    mov rdi, rax
    call own_fdrop_like
    ret
.size pass_in_arg, .-pass_in_arg

.globl pass_in_nonarg
.type pass_in_nonarg, @function
pass_in_nonarg:
    mov rbx, rax
    call own_fdrop_like
    ret
.size pass_in_nonarg, .-pass_in_nonarg

/* A1-06 counterexample: the caller acquires one object and hands the callee a
 * different one.  The audit asked for exactly this case -- an unrelated acquired
 * object plus a callee that releases another -- so a transfers-reference edge here
 * would be invented, not witnessed. */
.globl pass_other_object
.type pass_other_object, @function
pass_other_object:
    mov rax, qword ptr [rbx]
    mov rdi, rcx
    call own_fdrop_like
    ret
.size pass_other_object, .-pass_other_object

/* The positive twin: the acquired object is reached through lea into the argument
 * register, so the callee provably receives it. */
.globl pass_by_lea
.type pass_by_lea, @function
pass_by_lea:
    mov rax, qword ptr [rbx]
    lea rdi, [rax+0x10]
    call own_fdrop_like
    ret
.size pass_by_lea, .-pass_by_lea
