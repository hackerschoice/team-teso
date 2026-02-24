/* interface code for the LiME polymorphism engine
 */

#include "lime-interface.h"


/* lime_generate
 *
 * generate a new polymorph code from source data at 'source', with a length
 * of 'source_len' bytes. the decrypter and encrypted data will be put at
 * 'dest', without any length check (expect no more than 4096 bytes for the
 * decrypter, so 4096 + source_len will do). 'delta' is the virtual address
 * the decryptor will be placed, its the virutal address of dest[0].
 * `rnd' is a random seed.
 *
 * return the number of bytes put at 'dest'
 */

inline unsigned int
lime_generate (unsigned char *source, unsigned int source_len,
	unsigned char *dest, unsigned long int delta, unsigned int rnd)
{
	unsigned int	rlen;

	/* FIXME: eax is not random parameter anymore, but does not hurt */
	__asm__ __volatile__ ("
		pushl %%ebp
		movl 0x14(%%ebp), %%ebp
		pushf
		pusha
		call lime
		movl %%edx, 0x14(%%esp)
		popa
		popf
		popl %%ebp\n\t"
		: "=d" (rlen)
		: "a" (rnd), "b" ((unsigned int) dest),
			"c" ((unsigned int) source), "d" (source_len));

	return (rlen);
}


