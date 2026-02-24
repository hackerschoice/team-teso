	.globl	cbegin
	.globl	cend

cbegin:

main:
	pushl	$0x46
	popl	%eax
	movw	$0x4141,	%ebx
	xorw	$0x4141,	%ebx
	movw	$0x4242,	%ecx
	xorw	$0x4242,	%ecx
	int	$0x80

cend:

