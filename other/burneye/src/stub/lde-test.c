/* lde testing
 */

#include <stdio.h>
#include <stdlib.h>
#include "lde32.h"


int disasm_me (int a, int b);


int
main (int argc, char *argv[])
{
	int		n,
			len;
	unsigned char *	d;
	unsigned char	lde_data[2048];


	memset (lde_data, '\0', sizeof (lde_data));
	lde_init ((lde_table *) lde_data);

	for (d = (unsigned char *) disasm_me ; *d != 0xcc ; d += len) {

		len = lde_dis (d, (lde_table *) lde_data);

		if (len <= 0) {
			fprintf (stderr, "len = %d\n", len);

			exit (EXIT_FAILURE);
		}

		printf ("0x%08lx [%2d]: ", (unsigned long int) d, len);
		for (n = 0 ; n < len ; ++n)
			printf ("%02x ", d[n]);

		printf ("\n");
	}

	exit (EXIT_SUCCESS);
}


int
disasm_me (int a, int b)
{
	a *= b;
	a >>= (b & 0x04);
	a += b & ~0x04;
	a ^= b;
	b ^= a;
	a ^= b;
	a ^= ~b;
	b *= a | b;

	return (a + b);

	asm ("int3");
}


