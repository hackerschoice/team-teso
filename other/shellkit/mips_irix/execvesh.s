/* MIPS/IRIX PIC execve code
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

	sw	zero, -4(sp)
foo:	bltzal	zero, foo
	lw	a2, -4(sp)

	addu	ra, ra, 0x0124	/* add 36 + 0x0100 */

	add	a0, ra, -(8 + 0x100)
	sb	zero, -(1 + 0x100)(ra)
	sw	a0, -8(sp)
	subu	a1, sp, 8
	li	v0, SYS_execve
	syscall

	.end	cbegin
cend:

