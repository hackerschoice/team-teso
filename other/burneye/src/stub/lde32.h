/* length disassembling engine - C interface header file
 */

#ifndef	LDE32_H
#define	LDE32_H

typedef void	lde_table;

/* lde_init
 *
 * initialize 2048 byte table for use with LDE at `tableptr'. `tableptr' has
 * to point to at least 2048 reserved bytes.
 *
 * return in any case
 */

void
lde_init (lde_table *tableptr);


/* lde_dis
 *
 * return opcode length in bytes on success
 * return -1 on failure
 */

int
lde_dis (unsigned char *instr, lde_table *tableptr);

#endif

