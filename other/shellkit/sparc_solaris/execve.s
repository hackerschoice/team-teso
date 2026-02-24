	.globl	cbegin
	.globl	cend

cbegin:

	sethi	0xbd89a, %l6
	or	%l6, 0x16e, %l6
	sethi	0xbdcda, %l7
	add	%sp, 8, %o0
	or	%sp, %sp, %o1
	add	%sp, 16, %sp
	xor	%o6, %o6, %o2
	std	%l6, [%sp - 8]
	st	%o0, [%sp - 16]
	st	%o2, [%sp - 12]
	mov	0x3b, %g1
	ta	8

cend:

