/* D2_double_release fixtures: the same-object question, in six shapes.
 *
 * Every function here has *two* release call sites carrying the same slot label.  What
 * differs is whether the second site can consume the object the first one freed:
 *
 *   positive   one path keeps slot and identity  -> rank 1
 *   negative   every path ends the object        -> rank 3
 *
 * `d2_free` is a distinct function; its address reaches the engine as data (the fixture's
 * `roots`), exactly like the firmware anchors.  Nothing here is a kernel claim.
 */

    .intel_syntax noprefix
    .text

/* ---------------------------------------------------------------- callee */
    .globl d2_free
    .type d2_free, @function
d2_free:
    ret
    .size d2_free, .-d2_free

    .globl d2_alloc
    .type d2_alloc, @function
d2_alloc:
    mov rax, rdi
    ret
    .size d2_alloc, .-d2_alloc

/* ------------------------------------------- 1. same register, untouched */
/* Straight-line: rbx is callee-saved, nothing writes it between the sites, so both
 * calls consume the same object.  This is the shape the rule must still confirm. */
    .globl fixture_d2_register_positive
    .type fixture_d2_register_positive, @function
fixture_d2_register_positive:
    push rbx
    mov rbx, rdi
    mov rdi, rbx
    call d2_free
    mov rdi, rbx
    call d2_free
    pop rbx
    ret
    .size fixture_d2_register_positive, .-fixture_d2_register_positive

/* --------------------------------------- 2. same register, rebound on all */
/* Both arms of the branch install a different object into rbx before the second
 * release: equal label, different object on every path. */
    .globl fixture_d2_register_rebound_all_paths
    .type fixture_d2_register_rebound_all_paths, @function
fixture_d2_register_rebound_all_paths:
    push rbx
    mov rbx, rdi
    mov rdi, rbx
    call d2_free
    test rsi, rsi
    je 2f
    mov rbx, rsi
    jmp 3f
2:
    mov rbx, rdx
3:
    mov rdi, rbx
    call d2_free
    pop rbx
    ret
    .size fixture_d2_register_rebound_all_paths, .-fixture_d2_register_rebound_all_paths

/* --------------------------------------------- 3. field slot, never reset */
/* Two loads of the same field of one untouched object with no reset in between: a
 * genuine double d2_free through a memory slot. */
    .globl fixture_d2_field_positive
    .type fixture_d2_field_positive, @function
fixture_d2_field_positive:
    push rbx
    mov rbx, rdi
    mov rdi, qword ptr [rbx + 0x10]
    call d2_free
    test rsi, rsi
    je 5f
    nop
5:
    mov rdi, qword ptr [rbx + 0x10]
    call d2_free
    pop rbx
    ret
    .size fixture_d2_field_positive, .-fixture_d2_field_positive

/* ------------------------------------------------ 4. field slot, NULL reset */
/* The fix: the slot is reset after the release, so the second load cannot yield the
 * freed object. */
    .globl fixture_d2_field_reset
    .type fixture_d2_field_reset, @function
fixture_d2_field_reset:
    push rbx
    mov rbx, rdi
    mov rdi, qword ptr [rbx + 0x10]
    call d2_free
    mov qword ptr [rbx + 0x10], 0
    mov rdi, qword ptr [rbx + 0x10]
    call d2_free
    pop rbx
    ret
    .size fixture_d2_field_reset, .-fixture_d2_field_reset

/* --------------------------------------- 5. field slot, base register rebound */
/* Byte-identical slot labels `rbx+0x10` on both sites, but rbx is a *different* object
 * on every path to the second site.  The label is an equal string, not an identity --
 * this is the false-positive class the detector has to refuse. */
    .globl fixture_d2_base_rebound
    .type fixture_d2_base_rebound, @function
fixture_d2_base_rebound:
    push rbx
    mov rbx, rdi
    mov rdi, qword ptr [rbx + 0x10]
    call d2_free
    test rsi, rsi
    je 6f
    mov rbx, rsi
    jmp 7f
6:
    mov rbx, rdx
7:
    mov rdi, qword ptr [rbx + 0x10]
    call d2_free
    pop rbx
    ret
    .size fixture_d2_base_rebound, .-fixture_d2_base_rebound

/* ------------------------------------------ 6. caller-saved base register */
/* The base is rax, which the release call itself is d2_free to clobber: after the first
 * call the "+0x10" no longer names the same object. */
    .globl fixture_d2_caller_saved_base
    .type fixture_d2_caller_saved_base, @function
fixture_d2_caller_saved_base:
    mov rax, rdi
    mov rdi, qword ptr [rax + 0x10]
    call d2_free
    mov rdi, qword ptr [rax + 0x10]
    call d2_free
    ret
    .size fixture_d2_caller_saved_base, .-fixture_d2_caller_saved_base

/* ------------------------------------------------ 7. loop-carried identity */
/* The aio_multi_delete shape in miniature: two release sites on the same register
 * label inside a loop, and the register is reloaded from the table on every
 * iteration.  One release per iteration, never the same object twice. */
    .globl fixture_d2_loop_carried
    .type fixture_d2_loop_carried, @function
fixture_d2_loop_carried:
    push rbx
    push r12
    push r13
    mov r12, rdi
    xor r13d, r13d
8:
    mov rbx, qword ptr [r12 + r13*8]
    test rbx, rbx
    je 11f
    test r13, r13
    jne 9f
    mov rdi, rbx
    call d2_free
    jmp 10f
9:
    mov rdi, rbx
    call d2_free
10:
    inc r13
    cmp r13, rdx
    jb 8b
11:
    pop r13
    pop r12
    pop rbx
    ret
    .size fixture_d2_loop_carried, .-fixture_d2_loop_carried

/* ------------------------------------------- 8. refcount-guarded releases */
/* Both sites are skipped unless the count observed before the decrement was 1: the last
 * reference frees, and no single path can observe "last reference" twice.  The identity
 * (rbx, callee-saved, never rewritten) is intact, so only the guard refuses the claim. */
    .globl fixture_d2_refcount_guarded
    .type fixture_d2_refcount_guarded, @function
fixture_d2_refcount_guarded:
    push rbx
    mov rbx, rdi
    mov ecx, 0xffffffff
    lock xadd dword ptr [rbx + 0x28], ecx
    cmp ecx, 1
    jne 12f
    mov rdi, rbx
    call d2_free
12:
    mov ecx, 0xffffffff
    lock xadd dword ptr [rbx + 0x28], ecx
    cmp ecx, 1
    jne 13f
    mov rdi, rbx
    call d2_free
13:
    pop rbx
    ret
    .size fixture_d2_refcount_guarded, .-fixture_d2_refcount_guarded

/* ------------------------------------------------ 9. conditional releases */
/* Both releases sit on one arm.  Being conditional is *not* a refusal: on the path that
 * takes the arm the same object is freed twice, so the claim stands and the finding has
 * to say that both sites are conditional. */
    .globl fixture_d2_conditional_pair
    .type fixture_d2_conditional_pair, @function
fixture_d2_conditional_pair:
    push rbx
    mov rbx, rdi
    test rsi, rsi
    je 15f
    mov rdi, rbx
    call d2_free
    mov rdi, rbx
    call d2_free
15:
    pop rbx
    ret
    .size fixture_d2_conditional_pair, .-fixture_d2_conditional_pair
