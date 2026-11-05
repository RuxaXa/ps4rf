/* CFG fixtures: taken and fall-through edges, instruction-exact.
 *
 * The default CFG used to take only the `call`/`jmp` target, so every `je`/`jne` lost its
 * taken edge.  These six functions fix each shape down to the label, positive and negative:
 *
 *   two_ways        a conditional branch: two successors
 *   jmp_only        a direct jmp: the target only, no fall-through
 *   same_target     a branch whose target IS the next instruction: one successor, not two
 *   indirect        an indirect jmp: no successor at all
 *   loop            a back edge and its fall-through exit
 *   tail            a jmp out of the function: a tail call, never an internal edge
 *
 * `cfg_*` labels exist so the expectations can name blocks; they are not functions.
 */

    .intel_syntax noprefix
    .text

/* The cfg_* labels are block boundaries the expectations name, so they have to reach the
 * symbol table; they are data here, never functions. */
    .globl cfg_two_branch, cfg_two_fall, cfg_two_else
    .globl cfg_jmp_branch, cfg_jmp_dead, cfg_jmp_target
    .globl cfg_same_branch, cfg_same_next
    .globl cfg_indirect_branch, cfg_indirect_after
    .globl cfg_loop_body, cfg_loop_exit
    .globl cfg_tail_branch

    .globl d2_free
    .type d2_free, @function
d2_free:
    ret
    .size d2_free, .-d2_free

/* ------------------------------------------------------------ conditional */
    .globl fixture_cfg_cond_two_ways
    .type fixture_cfg_cond_two_ways, @function
fixture_cfg_cond_two_ways:
cfg_two_branch:
    test rdi, rdi
    je cfg_two_else
cfg_two_fall:
    mov eax, 1
    ret
cfg_two_else:
    xor eax, eax
    ret
    .size fixture_cfg_cond_two_ways, .-fixture_cfg_cond_two_ways

/* ------------------------------------------------------------------- jmp */
    .globl fixture_cfg_jmp_only
    .type fixture_cfg_jmp_only, @function
fixture_cfg_jmp_only:
cfg_jmp_branch:
    jmp cfg_jmp_target
cfg_jmp_dead:
    mov eax, 7
    ret
cfg_jmp_target:
    mov eax, 2
    ret
    .size fixture_cfg_jmp_only, .-fixture_cfg_jmp_only

/* ------------------------------------------------- taken == fall-through */
    .globl fixture_cfg_same_target
    .type fixture_cfg_same_target, @function
fixture_cfg_same_target:
cfg_same_branch:
    test eax, eax
    je cfg_same_next
cfg_same_next:
    mov eax, 3
    ret
    .size fixture_cfg_same_target, .-fixture_cfg_same_target

/* --------------------------------------------------------- indirect jump */
    .globl fixture_cfg_indirect
    .type fixture_cfg_indirect, @function
fixture_cfg_indirect:
cfg_indirect_branch:
    jmp rax
cfg_indirect_after:
    mov eax, 4
    ret
    .size fixture_cfg_indirect, .-fixture_cfg_indirect

/* ------------------------------------------------------------------ loop */
    .globl fixture_cfg_loop
    .type fixture_cfg_loop, @function
fixture_cfg_loop:
cfg_loop_body:
    dec rdi
    jne cfg_loop_body
cfg_loop_exit:
    ret
    .size fixture_cfg_loop, .-fixture_cfg_loop

/* ------------------------------------------------------------- tail jump */
    .globl fixture_cfg_tail
    .type fixture_cfg_tail, @function
fixture_cfg_tail:
cfg_tail_branch:
    mov rdi, rsi
    jmp d2_free
    .size fixture_cfg_tail, .-fixture_cfg_tail
