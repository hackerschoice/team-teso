
#ifndef	X86_H
#define	X86_H

#define x86_TERMINATOR "\x78\x56\x34\x12"


/* x86_nop
 *
 * generate `dest_len' bytes of nopspace at `dest', which does not contain
 * any of the characters in `bad', which is `bad_len' bytes long.
 *
 * return number of bytes generated
 */

unsigned int
x86_nop (unsigned char *dest, unsigned int dest_len,
	unsigned char *bad, int bad_len);

#endif

