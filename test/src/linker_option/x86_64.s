	.section __TEXT,__text
	.globl _entry
	.p2align 4
_entry:
	movq _ext@GOTPCREL(%rip), %rax
	ret

	.section __DATA,__data
	.globl _d
	.p2align 3
_d:
	.quad _ext
