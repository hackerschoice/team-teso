/* MIPS/IRIX PIC setreuid chainable code
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

	/* setreuid (a0, a1) */
	li	a0, 0x4141		/* ruid ^ 0x5555 */
	li	a1, 0x4242		/* euid ^ 0x5555 */
	xor	a0, a0, 0x5555
	xor	a1, a1, 0x5555
	li	v0, SYS_setreuid	/* 0x0464 */
	syscall
	li	t8, 0x7350

	.end	cbegin
cend:

