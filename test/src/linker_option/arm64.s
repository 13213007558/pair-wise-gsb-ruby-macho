	.section __TEXT,__text
	.globl _entry
	.p2align 2
_entry:
	bl _ext
	ret

	.section __DATA,__data
	.globl _d
	.p2align 3
_d:
	.quad _ext
