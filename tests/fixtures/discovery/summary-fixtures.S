# Deterministic fixtures for the S1.6 interprocedural summaries.
#
# Every function is a real .text symbol; the caller cases call their callees through direct
# relative calls so the summary layer resolves them the same way it resolves firmware calls.
# No names are visible to the analysis: only bytes, addresses and the release anchor.
#
# Conventions: the object arrives in %rdi unless a case says otherwise. References are counted in
# a 32-bit field at +0x28, the identity decision compares a field at +0x10.

        .text

# ---------------------------------------------------------------- release anchors
        .globl  own_release
        .type   own_release, @function
own_release:
        ret
        .size   own_release, .-own_release

# Returns a value that is not attributable to a constant, an argument or a field: a callee result
# whose provenance the layer must not guess.
        .globl  own_alloc
        .type   own_alloc, @function
own_alloc:
        pushq   %rbx
        movq    %rbx, %rax
        popq    %rbx
        ret
        .size   own_alloc, .-own_alloc

# ------------------------------------------------------------------- callees
        .globl  callee_deref
        .type   callee_deref, @function
callee_deref:
        movl    0x10(%rdi), %eax
        ret
        .size   callee_deref, .-callee_deref

        .globl  callee_two_args_same_field
        .type   callee_two_args_same_field, @function
callee_two_args_same_field:
        movq    0x10(%rdi), %rax
        cmpq    0x10(%rsi), %rax
        ret
        .size   callee_two_args_same_field, .-callee_two_args_same_field

        .globl  callee_drop_guarded
        .type   callee_drop_guarded, @function
callee_drop_guarded:
        movl    $-1, %eax
        lock xadd %eax, 0x28(%rdi)
        cmpl    $1, %eax
        jne     1f
        call    own_release
1:
        ret
        .size   callee_drop_guarded, .-callee_drop_guarded

        .globl  callee_drop_unguarded
        .type   callee_drop_unguarded, @function
callee_drop_unguarded:
        movl    $-1, %eax
        lock xadd %eax, 0x28(%rdi)
        call    own_release
        ret
        .size   callee_drop_unguarded, .-callee_drop_unguarded

        .globl  callee_take
        .type   callee_take, @function
callee_take:
        movl    $1, %eax
        lock xadd %eax, 0x28(%rdi)
        ret
        .size   callee_take, .-callee_take

        .globl  callee_conditional_free
        .type   callee_conditional_free, @function
callee_conditional_free:
        cmpq    $0, 0x8(%rdi)
        je      1f
        call    own_release
1:
        ret
        .size   callee_conditional_free, .-callee_conditional_free

        .globl  callee_escape_global
        .type   callee_escape_global, @function
callee_escape_global:
        movq    %rdi, global_slot(%rip)
        ret
        .size   callee_escape_global, .-callee_escape_global

        .globl  callee_return_arg
        .type   callee_return_arg, @function
callee_return_arg:
        movq    %rdi, %rax
        ret
        .size   callee_return_arg, .-callee_return_arg

        .globl  callee_return_field
        .type   callee_return_field, @function
callee_return_field:
        movq    0x8(%rdi), %rax
        ret
        .size   callee_return_field, .-callee_return_field

        .globl  callee_return_alloc
        .type   callee_return_alloc, @function
callee_return_alloc:
        subq    $8, %rsp
        call    own_alloc
        addq    $8, %rsp
        ret
        .size   callee_return_alloc, .-callee_return_alloc

        .globl  callee_lea_interior
        .type   callee_lea_interior, @function
callee_lea_interior:
        leaq    0x10(%rdi), %rax
        movl    (%rax), %eax
        ret
        .size   callee_lea_interior, .-callee_lea_interior

        .globl  callee_indirect
        .type   callee_indirect, @function
callee_indirect:
        call    *%rax
        ret
        .size   callee_indirect, .-callee_indirect


# The netcontrol shape: the reference is dropped on a *pointer stored in a field*, not on the
# argument itself.  The container argument stays live; the field object is the one with a life
# cycle.
        .globl  callee_drop_field_pointer
        .type   callee_drop_field_pointer, @function
callee_drop_field_pointer:
        movq    0x30(%rdi), %rax
        movq    %rax, %rdi
        call    own_release
        ret
        .size   callee_drop_field_pointer, .-callee_drop_field_pointer

# Two drops on the same field object: the reference count is decremented twice without a take.
        .globl  callee_double_drop_field
        .type   callee_double_drop_field, @function
callee_double_drop_field:
        pushq   %rbx
        movq    %rdi, %rbx
        movq    0x30(%rbx), %rdi
        call    own_release
        movq    0x30(%rbx), %rdi
        call    own_release
        popq    %rbx
        ret
        .size   callee_double_drop_field, .-callee_double_drop_field

# Negative control: two different field objects are released once each.  A detector that merges
# them by "the argument" reports a double free here, which would be a false positive.
        .globl  callee_two_fields_one_drop_each
        .type   callee_two_fields_one_drop_each, @function
callee_two_fields_one_drop_each:
        pushq   %rbx
        movq    %rdi, %rbx
        movq    0x30(%rbx), %rdi
        call    own_release
        movq    0x38(%rbx), %rdi
        call    own_release
        popq    %rbx
        ret
        .size   callee_two_fields_one_drop_each, .-callee_two_fields_one_drop_each


# Kernel reality: the object is fetched from a global, not from an argument.  The argument is not
# the released object and must not inherit its life cycle.
        .globl  callee_drop_global_pointer
        .type   callee_drop_global_pointer, @function
callee_drop_global_pointer:
        movq    global_ptr(%rip), %rdi
        call    own_release
        ret
        .size   callee_drop_global_pointer, .-callee_drop_global_pointer

# Two drops of whatever the same global points at: a global life cycle, decremented twice.
        .globl  callee_double_drop_global
        .type   callee_double_drop_global, @function
callee_double_drop_global:
        movq    global_ptr(%rip), %rdi
        call    own_release
        movq    global_ptr(%rip), %rdi
        call    own_release
        ret
        .size   callee_double_drop_global, .-callee_double_drop_global

# -------------------------------------------------------------------- callers
        .globl  caller_redefined_arg
        .type   caller_redefined_arg, @function
caller_redefined_arg:
        movq    %rax, %rdi
        movq    %rcx, %rdi
        call    callee_deref
        ret
        .size   caller_redefined_arg, .-caller_redefined_arg

        .globl  caller_subregister
        .type   caller_subregister, @function
caller_subregister:
        movl    %eax, %edi
        call    callee_deref
        ret
        .size   caller_subregister, .-caller_subregister

        .globl  caller_lea_arg
        .type   caller_lea_arg, @function
caller_lea_arg:
        leaq    0x10(%rax), %rdi
        call    callee_deref
        ret
        .size   caller_lea_arg, .-caller_lea_arg

        .globl  caller_no_setup
        .type   caller_no_setup, @function
caller_no_setup:
        call    callee_deref
        ret
        .size   caller_no_setup, .-caller_no_setup

# The two-hop case: the callee hands back its own argument, the caller forwards that alias, and
# the second callee drops a reference. The drop must be attributed to the *caller's* argument 0.
        .globl  caller_return_alias_chain
        .type   caller_return_alias_chain, @function
caller_return_alias_chain:
        subq    $8, %rsp
        call    callee_return_arg
        movq    %rax, %rdi
        call    callee_drop_unguarded
        addq    $8, %rsp
        ret
        .size   caller_return_alias_chain, .-caller_return_alias_chain

# Same shape, but the callee hands back a *field* of its argument: a different object, so the
# caller's forward must not be attributed to parameter 0's reference count.
        .globl  caller_return_field_chain
        .type   caller_return_field_chain, @function
caller_return_field_chain:
        subq    $8, %rsp
        call    callee_return_field
        movq    %rax, %rdi
        call    callee_drop_unguarded
        addq    $8, %rsp
        ret
        .size   caller_return_field_chain, .-caller_return_field_chain

# A global store is an escape, not a release: the object stays live after the call.
        .globl  caller_escape
        .type   caller_escape, @function
caller_escape:
        subq    $8, %rsp
        call    callee_escape_global
        addq    $8, %rsp
        ret
        .size   caller_escape, .-caller_escape


# The minimal goal at fixture level: one hop that really moves a reference into a wrapper that
# consumes it, and one control hop of the same shape where the callee only reads.
        .globl  caller_hop_positive
        .type   caller_hop_positive, @function
caller_hop_positive:
        movq    %rax, %rdi
        call    callee_drop_unguarded
        ret
        .size   caller_hop_positive, .-caller_hop_positive

        .globl  caller_hop_negative
        .type   caller_hop_negative, @function
caller_hop_negative:
        movq    %rax, %rdi
        call    callee_deref
        ret
        .size   caller_hop_negative, .-caller_hop_negative


# Same hop, but the callee frees on one arm only: the transfer holds on that path.
        .globl  caller_hop_conditional
        .type   caller_hop_conditional, @function
caller_hop_conditional:
        movq    %rax, %rdi
        call    callee_conditional_free
        ret
        .size   caller_hop_conditional, .-caller_hop_conditional


# ------------------------------------------------- indexed object identity (S1.7)
# The kernel shape: releasable objects live in a table, addressed by base + index*scale. The slot
# is the object; the table, the base object and the index are not.
#
# Every case keeps the base and the index in callee-saved registers, because a call is free to
# clobber rcx/rdx/rax. A fixture that carries an index across a call in a caller-saved register is
# not a test of the identity rule — it passes or fails for the wrong reason.
        .globl  callee_index_drop
        .type   callee_index_drop, @function
callee_index_drop:
        movq    (%rdi,%rsi,8), %rax
        movq    %rax, %rdi
        call    own_release
        ret
        .size   callee_index_drop, .-callee_index_drop

# Two releases of the same slot with the same index: one object, dropped twice.
        .globl  callee_index_double_drop
        .type   callee_index_double_drop, @function
callee_index_double_drop:
        pushq   %rbx
        pushq   %r12
        movq    %rdi, %rbx
        movq    %rsi, %r12
        movq    (%rbx,%r12,8), %rdi
        call    own_release
        movq    (%rbx,%r12,8), %rdi
        call    own_release
        popq    %r12
        popq    %rbx
        ret
        .size   callee_index_double_drop, .-callee_index_double_drop

# Two different indices: two different slots, one drop each. Reporting a double release here is a
# fabricated finding.
        .globl  callee_index_two_indices
        .type   callee_index_two_indices, @function
callee_index_two_indices:
        pushq   %rbx
        pushq   %r12
        pushq   %r13
        movq    %rdi, %rbx
        movq    %rsi, %r12
        movq    %rdx, %r13
        movq    (%rbx,%r12,8), %rdi
        call    own_release
        movq    (%rbx,%r13,8), %rdi
        call    own_release
        popq    %r13
        popq    %r12
        popq    %rbx
        ret
        .size   callee_index_two_indices, .-callee_index_two_indices

# The slot is overwritten between the two reads: the second value is a different object generation.
        .globl  callee_index_reallocated
        .type   callee_index_reallocated, @function
callee_index_reallocated:
        pushq   %rbx
        pushq   %r12
        movq    %rdi, %rbx
        movq    %rsi, %r12
        movq    (%rbx,%r12,8), %rdi
        call    own_release
        movq    0x8(%rbx), %rax
        movq    %rax, (%rbx,%r12,8)
        movq    (%rbx,%r12,8), %rdi
        call    own_release
        popq    %r12
        popq    %rbx
        ret
        .size   callee_index_reallocated, .-callee_index_reallocated

# The index comes from memory: no provenance, so no identity claim may be made.
        .globl  callee_index_unknown_index
        .type   callee_index_unknown_index, @function
callee_index_unknown_index:
        pushq   %rbx
        pushq   %r12
        movq    %rdi, %rbx
        movq    0x10(%rbx), %r12
        movq    (%rbx,%r12,8), %rdi
        call    own_release
        movq    0x10(%rbx), %r12
        movq    (%rbx,%r12,8), %rdi
        call    own_release
        popq    %r12
        popq    %rbx
        ret
        .size   callee_index_unknown_index, .-callee_index_unknown_index

# A constant displacement is a provenance: two reads of the same field are one object.
        .globl  callee_index_constant
        .type   callee_index_constant, @function
callee_index_constant:
        pushq   %rbx
        movq    %rdi, %rbx
        movq    0x18(%rbx), %rdi
        call    own_release
        movq    0x18(%rbx), %rdi
        call    own_release
        popq    %rbx
        ret
        .size   callee_index_constant, .-callee_index_constant

# A bucket-mask index: `i & 0xff` is an expression, so two loads through it are the same slot.
        .globl  callee_index_masked
        .type   callee_index_masked, @function
callee_index_masked:
        pushq   %rbx
        pushq   %r12
        movq    %rdi, %rbx
        movl    %esi, %r12d
        andl    $0xff, %r12d
        movq    (%rbx,%r12,8), %rdi
        call    own_release
        movq    (%rbx,%r12,8), %rdi
        call    own_release
        popq    %r12
        popq    %rbx
        ret
        .size   callee_index_masked, .-callee_index_masked

# Different mask input: a different expression, therefore a different slot.
        .globl  callee_index_masked_other_input
        .type   callee_index_masked_other_input, @function
callee_index_masked_other_input:
        pushq   %rbx
        pushq   %r12
        pushq   %r13
        movq    %rdi, %rbx
        movl    %esi, %r12d
        andl    $0xff, %r12d
        movl    %edx, %r13d
        andl    $0xff, %r13d
        movq    (%rbx,%r12,8), %rdi
        call    own_release
        movq    (%rbx,%r13,8), %rdi
        call    own_release
        popq    %r13
        popq    %r12
        popq    %rbx
        ret
        .size   callee_index_masked_other_input, .-callee_index_masked_other_input

# Array-of-struct addressing: sign-extension and a shift are part of the index expression, so the
# same expression selects the same slot on both accesses.
        .globl  callee_index_struct_scaled
        .type   callee_index_struct_scaled, @function
callee_index_struct_scaled:
        pushq   %rbx
        pushq   %r12
        movq    %rdi, %rbx
        movslq  %esi, %r12
        shlq    $4, %r12
        movq    (%rbx,%r12), %rdi
        call    own_release
        movq    (%rbx,%r12), %rdi
        call    own_release
        popq    %r12
        popq    %rbx
        ret
        .size   callee_index_struct_scaled, .-callee_index_struct_scaled

# A different shift is a different stride, therefore a different slot.
        .globl  callee_index_struct_other_stride
        .type   callee_index_struct_other_stride, @function
callee_index_struct_other_stride:
        pushq   %rbx
        pushq   %r12
        pushq   %r13
        movq    %rdi, %rbx
        movslq  %esi, %r12
        shlq    $4, %r12
        movslq  %esi, %r13
        shlq    $5, %r13
        movq    (%rbx,%r12), %rdi
        call    own_release
        movq    (%rbx,%r13), %rdi
        call    own_release
        popq    %r13
        popq    %r12
        popq    %rbx
        ret
        .size   callee_index_struct_other_stride, .-callee_index_struct_other_stride

# ------------------------------------------------- base provenance across a join (S1.8)
# The join is a loop header: the first iteration arrives with a value that is not an object, later
# ones with a tracked field, so the definite value drops and the may-channel carries the object.
        .globl  callee_may_release_in_loop
        .type   callee_may_release_in_loop, @function
callee_may_release_in_loop:
        pushq   %rbx
        movq    %rdi, %rbx
        xorl    %edi, %edi
1:      movq    0x10(%rbx), %rdi
        testq   %rdi, %rdi
        je      2f
        call    own_release
        jmp     1b
2:      popq    %rbx
        ret
        .size   callee_may_release_in_loop, .-callee_may_release_in_loop

# Two different fields reach the same release through the header: the register may hold either, so
# no identity is claimed.
        .globl  callee_may_two_objects
        .type   callee_may_two_objects, @function
callee_may_two_objects:
        pushq   %rbx
        movq    %rdi, %rbx
        movq    0x18(%rbx), %rdi
1:      testq   %rdi, %rdi
        je      2f
        call    own_release
        movq    0x10(%rbx), %rdi
        jmp     1b
2:      popq    %rbx
        ret
        .size   callee_may_two_objects, .-callee_may_two_objects

# An indirect call clobbers the argument register; the release afterwards has no object.
        .globl  callee_clobbered_by_call
        .type   callee_clobbered_by_call, @function
callee_clobbered_by_call:
        pushq   %rbx
        movq    %rdi, %rbx
        movq    0x10(%rbx), %rdi
        call    *%rax
        call    own_release
        popq    %rbx
        ret
        .size   callee_clobbered_by_call, .-callee_clobbered_by_call

# --------------------------------------------------------- storage for the global store
        .data
        .align 8
global_slot:
        .quad   0

        .align 8
global_ptr:
        .quad   0
