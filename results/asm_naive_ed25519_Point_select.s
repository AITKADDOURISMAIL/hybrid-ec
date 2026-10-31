_RNvMNtCsaiouMV1K5cO_10hec_curves7ed25519NtB2_5Point6select:
	movq	%rdi, %rax
	testb	$1, %cl
	cmovneq	%rdx, %rsi
	movq	32(%rsi), %rcx
	movq	%rcx, 32(%rdi)
	movups	(%rsi), %xmm0
	movups	16(%rsi), %xmm1
	movups	%xmm1, 16(%rdi)
	movups	%xmm0, (%rdi)
	movq	72(%rsi), %rcx
	movq	%rcx, 72(%rdi)
	movups	40(%rsi), %xmm0
	movups	56(%rsi), %xmm1
	movups	%xmm1, 56(%rdi)
	movups	%xmm0, 40(%rdi)
	movq	112(%rsi), %rcx
	movq	%rcx, 112(%rdi)
	movups	80(%rsi), %xmm0
	movups	96(%rsi), %xmm1
	movups	%xmm1, 96(%rdi)
	movups	%xmm0, 80(%rdi)
	movups	120(%rsi), %xmm0
	movups	136(%rsi), %xmm1
	movups	%xmm0, 120(%rdi)
	movups	%xmm1, 136(%rdi)
	movq	152(%rsi), %rcx
	movq	%rcx, 152(%rdi)
	retq
.Lfunc_end19:
