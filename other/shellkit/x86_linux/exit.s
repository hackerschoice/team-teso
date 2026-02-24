/* x86/linux exit shellcode
 *
 * lorian / teso 
 */
	.globl	cbegin
	.globl	cend

cbegin:

	xorl	%eax,	%eax
	incl	%eax
	int	$0x80

cend:
