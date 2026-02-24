/* x86/solaris exit shellcode
 *
 * lorian / teso 
 */
	.globl	cbegin
	.globl  _cbegin
	.globl	cend
	.globl  _cend

_cbegin:
cbegin:
	movl	$0x3cfff8ff, %eax
	notl	%eax
	pushl	%eax
	xorl	%eax, %eax
	movb	$0x9a, %al
	pushl	%eax
	movl	%esp, %edi
	movb	$0x01, %al
	call    *%edi


_cend:
cend:
