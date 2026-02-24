	.globl	cbegin
	.globl	cend

cbegin:

main:
	pushb	$0x2e
	popl    %eax
	movw	$0x4141,	%ebx
	xorw	$0x4242,	%ebx
	int	$0x80

cend:

