
#ifndef	MIPS_H
#define	MIPS_H

/* mips_nop
 *
 * create `dest_len' bytes of nopspace at `dest', which does not contain any
 * of the bytes in `bad', which is a char array, `bad_len' in size
 *
 * return number of bytes generated
 */

unsigned int
mips_nop (unsigned char *dest, unsigned int dest_len,
	unsigned char *bad, int bad_len);

#endif


