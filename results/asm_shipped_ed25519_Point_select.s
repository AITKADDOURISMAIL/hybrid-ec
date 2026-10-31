_RNvMNtCs4dNPc0S6eIk_10hec_curves7ed25519NtB2_5Point6select:
	pushq	%rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	movq	%rcx, %r10
	movq	%rdx, %r9
	movq	%rsi, %r8
	andl	$1, %r10d
	negq	%r10
	movq	%r10, -80(%rsp)
	leaq	-80(%rsp), %rax
	#APP
	#NO_APP
	movq	-80(%rsp), %rax
	movq	(%rsi), %rcx
	movq	8(%rsi), %rdx
	movq	(%r9), %rsi
	xorq	%rcx, %rsi
	andq	%rax, %rsi
	xorq	%rcx, %rsi
	movq	%rsi, -8(%rsp)
	movq	8(%r9), %rcx
	xorq	%rdx, %rcx
	andq	%rax, %rcx
	xorq	%rdx, %rcx
	movq	%rcx, -16(%rsp)
	movq	16(%r8), %rcx
	movq	16(%r9), %rdx
	xorq	%rcx, %rdx
	andq	%rax, %rdx
	xorq	%rcx, %rdx
	movq	%rdx, -24(%rsp)
	movq	24(%r8), %rcx
	movq	24(%r9), %rdx
	xorq	%rcx, %rdx
	andq	%rax, %rdx
	xorq	%rcx, %rdx
	movq	%rdx, -32(%rsp)
	movq	32(%r8), %rcx
	movq	32(%r9), %rdx
	xorq	%rcx, %rdx
	andq	%rax, %rdx
	xorq	%rcx, %rdx
	movq	%rdx, -40(%rsp)
	movq	%r10, -80(%rsp)
	leaq	-80(%rsp), %rax
	#APP
	#NO_APP
	movq	-80(%rsp), %rax
	movq	40(%r8), %rcx
	movq	48(%r8), %rdx
	movq	40(%r9), %rsi
	xorq	%rcx, %rsi
	andq	%rax, %rsi
	xorq	%rcx, %rsi
	movq	%rsi, -48(%rsp)
	movq	48(%r9), %rcx
	xorq	%rdx, %rcx
	andq	%rax, %rcx
	xorq	%rdx, %rcx
	movq	%rcx, -56(%rsp)
	movq	56(%r8), %rcx
	movq	56(%r9), %rdx
	xorq	%rcx, %rdx
	andq	%rax, %rdx
	xorq	%rcx, %rdx
	movq	%rdx, -64(%rsp)
	movq	64(%r8), %rcx
	movq	64(%r9), %rdx
	xorq	%rcx, %rdx
	andq	%rax, %rdx
	xorq	%rcx, %rdx
	movq	%rdx, -72(%rsp)
	movq	72(%r8), %rcx
	movq	72(%r9), %r13
	xorq	%rcx, %r13
	andq	%rax, %r13
	xorq	%rcx, %r13
	movq	%r10, -80(%rsp)
	leaq	-80(%rsp), %rax
	#APP
	#NO_APP
	movq	80(%r8), %rcx
	movq	80(%r9), %rbp
	xorq	%rcx, %rbp
	movq	-80(%rsp), %rax
	andq	%rax, %rbp
	xorq	%rcx, %rbp
	movq	88(%r8), %rcx
	movq	88(%r9), %r12
	xorq	%rcx, %r12
	andq	%rax, %r12
	xorq	%rcx, %r12
	movq	96(%r8), %rcx
	movq	96(%r9), %r15
	xorq	%rcx, %r15
	andq	%rax, %r15
	xorq	%rcx, %r15
	movq	104(%r8), %rcx
	movq	104(%r9), %r14
	xorq	%rcx, %r14
	andq	%rax, %r14
	xorq	%rcx, %r14
	movq	112(%r8), %rcx
	movq	112(%r9), %rbx
	xorq	%rcx, %rbx
	andq	%rax, %rbx
	xorq	%rcx, %rbx
	movq	%r10, -80(%rsp)
	leaq	-80(%rsp), %rax
	#APP
	#NO_APP
	movq	120(%r8), %rax
	movq	120(%r9), %r10
	xorq	%rax, %r10
	movq	-80(%rsp), %rsi
	andq	%rsi, %r10
	xorq	%rax, %r10
	movq	128(%r8), %rax
	movq	128(%r9), %rdx
	xorq	%rax, %rdx
	andq	%rsi, %rdx
	xorq	%rax, %rdx
	movq	136(%r8), %rax
	movq	136(%r9), %rcx
	xorq	%rax, %rcx
	andq	%rsi, %rcx
	xorq	%rax, %rcx
	movq	144(%r8), %r11
	movq	144(%r9), %rax
	xorq	%r11, %rax
	andq	%rsi, %rax
	xorq	%r11, %rax
	movq	152(%r8), %r8
	movq	152(%r9), %r9
	xorq	%r8, %r9
	andq	%rsi, %r9
	xorq	%r8, %r9
	movq	-8(%rsp), %rsi
	movq	%rsi, (%rdi)
	movq	-16(%rsp), %rsi
	movq	%rsi, 8(%rdi)
	movq	-24(%rsp), %rsi
	movq	%rsi, 16(%rdi)
	movq	-32(%rsp), %rsi
	movq	%rsi, 24(%rdi)
	movq	-40(%rsp), %rsi
	movq	%rsi, 32(%rdi)
	movq	-48(%rsp), %rsi
	movq	%rsi, 40(%rdi)
	movq	-56(%rsp), %rsi
	movq	%rsi, 48(%rdi)
	movq	-64(%rsp), %rsi
	movq	%rsi, 56(%rdi)
	movq	-72(%rsp), %rsi
	movq	%rsi, 64(%rdi)
	movq	%r13, 72(%rdi)
	movq	%rbp, 80(%rdi)
	movq	%r12, 88(%rdi)
	movq	%r15, 96(%rdi)
	movq	%r14, 104(%rdi)
	movq	%rbx, 112(%rdi)
	movq	%r10, 120(%rdi)
	movq	%rdx, 128(%rdi)
	movq	%rcx, 136(%rdi)
	movq	%rax, 144(%rdi)
	movq	%r9, 152(%rdi)
	movq	%rdi, %rax
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	retq
.Lfunc_end19:
