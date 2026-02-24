/* MIPS/IRIX PIC setgid chainable code
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

	/* setgid (a0) */
	li	a0, 0x4141	/* gid ^ 0x5555 */
	xor	a0, a0, 0x5555
	li	v0, SYS_setgid	/* 0x0416 */
	syscall
	li	t8, 0x7350

	.end	cbegin
cend:

