/* MIPS/IRIX PIC exit code
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

	/* _exit (0) */
	slti	a0, zero, -1
	li	v0, SYS_exit	/* 0x03e9 */
	syscall
	li	t8, 0x7350

	.end	cbegin
cend:

