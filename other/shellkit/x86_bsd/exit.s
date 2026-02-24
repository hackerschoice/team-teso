/* x86/BSD exit shellcode
 *
 * lorian / teso 
 */
	.globl	cbegin
	.globl  _cbegin
	.globl	cend
	.globl  _cend

_cbegin:
cbegin:

	xorl	%eax,	%eax
	incl	%eax
	int	$0x80

_cend:
cend:
