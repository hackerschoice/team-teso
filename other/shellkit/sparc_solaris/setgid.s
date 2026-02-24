	.globl	cbegin
	.globl	cend

cbegin:

	mov	0x4142,	%o0
	xor	0x4344,	%o0,	%o0
	mov	0x2e,	%g1
	ta	0x8

cend:

