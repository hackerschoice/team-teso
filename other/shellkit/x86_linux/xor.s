	.globl	cbegin
	.globl	cend

cbegin:
	jmp	XOR_down

XOR_up:
	popl	%ebx
	movb	$0x26,	%cl		/* lenght */

XORLoop:
	xorb	$0x64,	%bl		/* xor key */
	incl	%ebx
	dec	%cl
	jnz	XORLoop
	jmp	XORLoopDone

XOR_down:
	call	XOR_up

XORLoopDone:
	.ascii	""

cend:
