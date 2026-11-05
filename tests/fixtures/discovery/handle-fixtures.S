# S1.2c handle/object identity fixtures.
#
# Each case is a pair of shapes: a caller that acquires an object through an
# out-parameter, asks a callee to decide whether a stored record belongs to that
# object, and then drops the reference it acquired.  The *only* thing that differs
# between the vulnerable and the fixed case is the width of the compared field:
# a 4-byte handle number (reusable) versus an 8-byte object pointer.
#
# The release root (`own_fdrop_like`) is handed to the analyser as data, exactly
# like a firmware anchor.  Nothing here names a syscall, a command or an offset.

	.text

# ---------------------------------------------------------------- shared primitives
	.globl	own_acquire
	.type	own_acquire, @function
own_acquire:
	pushq	%rbp
	movq	%rsp, %rbp
	movq	%rdi, (%rcx)		# write the object into the out-parameter slot
	xorl	%eax, %eax
	popq	%rbp
	ret
	.size	own_acquire, .-own_acquire

	.globl	own_fdrop_like
	.type	own_fdrop_like, @function
own_fdrop_like:
	pushq	%rbp
	movq	%rsp, %rbp
	movl	(%rdi), %eax		# touch the object, then return
	popq	%rbp
	ret
	.size	own_fdrop_like, .-own_fdrop_like

# ---------------------------------------------------------------- identity decisions
	.globl	decide_by_handle
	.type	decide_by_handle, @function
decide_by_handle:
	pushq	%rbp
	movq	%rsp, %rbp
	cmpl	%esi, 16(%rdi)		# 4-byte field vs a caller-supplied number
	je	.Ldh_hit
	movl	$5, %eax
	popq	%rbp
	ret
.Ldh_hit:
	xorl	%eax, %eax
	popq	%rbp
	ret
	.size	decide_by_handle, .-decide_by_handle

	.globl	decide_by_object
	.type	decide_by_object, @function
decide_by_object:
	pushq	%rbp
	movq	%rsp, %rbp
	cmpq	%rsi, 8(%rdi)		# 8-byte field vs the object pointer
	je	.Ldo_hit
	movl	$5, %eax
	popq	%rbp
	ret
.Ldo_hit:
	xorl	%eax, %eax
	popq	%rbp
	ret
	.size	decide_by_object, .-decide_by_object

# ---------------------------------------------------------------- vulnerable caller
# acquire -> handle decision -> two drops on the acquired object
	.globl	fixture_handle_reuse
	.type	fixture_handle_reuse, @function
fixture_handle_reuse:
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r13
	subq	$0x28, %rsp
	movq	%rdi, %r14
	leaq	-0x10(%rbp), %rcx
	call	own_acquire
	testl	%eax, %eax
	jne	.Lhr_out
	movq	-0x10(%rbp), %r13
	movq	%r13, %rdi
	movq	%r14, %rsi
	call	decide_by_handle
	testl	%eax, %eax
	jne	.Lhr_drop2
	movl	$0xffffffff, %eax
	lock xaddl %eax, 0x28(%r13)
	cmpl	$1, %eax
	jne	.Lhr_drop2
	movq	%r13, %rdi
	call	own_fdrop_like
.Lhr_drop2:
	movl	$0xffffffff, %eax
	lock xaddl %eax, 0x28(%r13)
	cmpl	$1, %eax
	jne	.Lhr_out
	movq	%r13, %rdi
	call	own_fdrop_like
.Lhr_out:
	addq	$0x28, %rsp
	popq	%r13
	popq	%rbp
	ret
	.size	fixture_handle_reuse, .-fixture_handle_reuse

# ---------------------------------------------------------------- fixed caller
# same shape, but the decision compares the object pointer
	.globl	fixture_object_identity
	.type	fixture_object_identity, @function
fixture_object_identity:
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r13
	subq	$0x28, %rsp
	movq	%rdi, %r14
	leaq	-0x10(%rbp), %rcx
	call	own_acquire
	testl	%eax, %eax
	jne	.Loi_out
	movq	-0x10(%rbp), %r13
	movq	%r13, %rdi
	movq	%r14, %rsi
	call	decide_by_object
	testl	%eax, %eax
	jne	.Loi_drop2
	movl	$0xffffffff, %eax
	lock xaddl %eax, 0x28(%r13)
	cmpl	$1, %eax
	jne	.Loi_drop2
	movq	%r13, %rdi
	call	own_fdrop_like
.Loi_drop2:
	movl	$0xffffffff, %eax
	lock xaddl %eax, 0x28(%r13)
	cmpl	$1, %eax
	jne	.Loi_out
	movq	%r13, %rdi
	call	own_fdrop_like
.Loi_out:
	addq	$0x28, %rsp
	popq	%r13
	popq	%rbp
	ret
	.size	fixture_object_identity, .-fixture_object_identity

# ---------------------------------------------------------------- single drop only
# handle decision, but exactly one drop: no surplus reference
	.globl	fixture_handle_single_drop
	.type	fixture_handle_single_drop, @function
fixture_handle_single_drop:
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r13
	subq	$0x28, %rsp
	movq	%rdi, %r14
	leaq	-0x10(%rbp), %rcx
	call	own_acquire
	testl	%eax, %eax
	jne	.Lsd_out
	movq	-0x10(%rbp), %r13
	movq	%r13, %rdi
	movq	%r14, %rsi
	call	decide_by_handle
	movl	$0xffffffff, %eax
	lock xaddl %eax, 0x28(%r13)
	cmpl	$1, %eax
	jne	.Lsd_out
	movq	%r13, %rdi
	call	own_fdrop_like
.Lsd_out:
	addq	$0x28, %rsp
	popq	%r13
	popq	%rbp
	ret
	.size	fixture_handle_single_drop, .-fixture_handle_single_drop

# ---------------------------------------------------------------- no decision at all
# two drops, no callee decides ownership: an accounting question, not a claim
	.globl	fixture_no_identity_premise
	.type	fixture_no_identity_premise, @function
fixture_no_identity_premise:
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r13
	subq	$0x28, %rsp
	leaq	-0x10(%rbp), %rcx
	call	own_acquire
	testl	%eax, %eax
	jne	.Lnp_out
	movq	-0x10(%rbp), %r13
	movl	$0xffffffff, %eax
	lock xaddl %eax, 0x28(%r13)
	cmpl	$1, %eax
	jne	.Lnp_drop2
	movq	%r13, %rdi
	call	own_fdrop_like
.Lnp_drop2:
	movl	$0xffffffff, %eax
	lock xaddl %eax, 0x28(%r13)
	cmpl	$1, %eax
	jne	.Lnp_out
	movq	%r13, %rdi
	call	own_fdrop_like
.Lnp_out:
	addq	$0x28, %rsp
	popq	%r13
	popq	%rbp
	ret
	.size	fixture_no_identity_premise, .-fixture_no_identity_premise


# ---------------------------------------------------------------- two acquires, two drops
# the balance is per acquired object, not a global count: two objects, one drop each
	.globl	fixture_two_generations
	.type	fixture_two_generations, @function
fixture_two_generations:
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r12
	pushq	%r13
	subq	$0x28, %rsp
	movq	%rdi, %r14
	leaq	-0x10(%rbp), %rcx
	call	own_acquire
	testl	%eax, %eax
	jne	.Ltg_out
	movq	-0x10(%rbp), %r13
	movq	%r13, %rdi
	movq	%r14, %rsi
	call	decide_by_handle
	movl	$0xffffffff, %eax
	lock xaddl %eax, 0x28(%r13)
	cmpl	$1, %eax
	jne	.Ltg_second
	movq	%r13, %rdi
	call	own_fdrop_like
.Ltg_second:
	leaq	-0x10(%rbp), %rcx
	call	own_acquire
	testl	%eax, %eax
	jne	.Ltg_out
	movq	-0x10(%rbp), %r12
	movq	%r12, %rdi
	movq	%r14, %rsi
	call	decide_by_handle
	movl	$0xffffffff, %eax
	lock xaddl %eax, 0x28(%r12)
	cmpl	$1, %eax
	jne	.Ltg_out
	movq	%r12, %rdi
	call	own_fdrop_like
.Ltg_out:
	addq	$0x28, %rsp
	popq	%r13
	popq	%r12
	popq	%rbp
	ret
	.size	fixture_two_generations, .-fixture_two_generations

# ---------------------------------------------------------------- borrowed reference
# two drops on one object, but the caller incremented first: no surplus, no claim
	.globl	fixture_borrowed_reference
	.type	fixture_borrowed_reference, @function
fixture_borrowed_reference:
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r13
	subq	$0x28, %rsp
	movq	%rdi, %r14
	leaq	-0x10(%rbp), %rcx
	call	own_acquire
	testl	%eax, %eax
	jne	.Lbr_out
	movq	-0x10(%rbp), %r13
	movq	%r13, %rdi
	movq	%r14, %rsi
	call	decide_by_object
	movl	$1, %eax
	lock xaddl %eax, 0x28(%r13)	# the caller owns one reference itself
	movl	$0xffffffff, %eax
	lock xaddl %eax, 0x28(%r13)
	cmpl	$1, %eax
	jne	.Lbr_drop2
	movq	%r13, %rdi
	call	own_fdrop_like
.Lbr_drop2:
	movl	$0xffffffff, %eax
	lock xaddl %eax, 0x28(%r13)
	cmpl	$1, %eax
	jne	.Lbr_out
	movq	%r13, %rdi
	call	own_fdrop_like
.Lbr_out:
	addq	$0x28, %rsp
	popq	%r13
	popq	%rbp
	ret
	.size	fixture_borrowed_reference, .-fixture_borrowed_reference

	.section	.note.GNU-stack,"",@progbits
