/* sparc.c - generic sparc functions
 *
 * by team teso
 */

#include <stdio.h>
#include <stdlib.h>
#include "shellcode.h"
#include "sparc.h"


static int sparc_torf (void);
static unsigned long int sparc_getinstr (unsigned char *pat,
	unsigned char *bad, int bad_len);


static int
sparc_torf (void)
{
	return (random_get (0, 1));
}


static unsigned long int
sparc_getinstr (unsigned char *pat, unsigned char *bad, int bad_len)
{
	int			x;	/* bitfield walker */
	unsigned char		bc = 0;
	unsigned long int	i = 0;	/* generated instruction */


	for (x = 31 ; x > 0 ; --x) {

		switch (pat[x]) {
		case '.':
			if (badstr (&bc, 1, bad, bad_len)) {
				/*x -= 8;*/
				printf ("redo byte! #muh\n");
			}
			bc = 0;
			break;

		case '0':
			break;

		case '1':
			i |= (1 << x);
			bc |= (1 << (x % 8));
			break;

		case 'v':
			if (badstr (&bc, 1, bad, bad_len)) {
				i |= (1 << x);
				bc |= (1 << (x % 8));
			} else if (sparc_torf ()) {
				i |= (1 << x);
				bc |= (1 << (x % 8));
			}
			break;

		case 'r':
		case 'f':
		case 's':
			if (badstr (&bc, 1, bad, bad_len)) {
				i |= (1 << x);
				bc |= (1 << (x % 8));
			} else if (sparc_torf ()) {
				i |= (1 << x);
				bc |= (1 << (x % 8));
			}
			break;
		default:
			fprintf (stderr, "sorry, can not generate nop's for "
				"trinary sparcs ...\n");

			exit (EXIT_FAILURE);
			break;
		}
	}

	return (i);
}


/* XXX: DO NOT USE UNTESTED! */
unsigned int
sparc_nop (unsigned char *dest, unsigned int dest_len,
	unsigned char *bad, int bad_len)
{
	unsigned long int *	dest_p = NULL;
	unsigned int		count = 0;

	/* abstract representation of a sparc instruction.
	 * '1', '0': real bits of the instruction
	 * 'r', 'f', 's': destination, first and second source register
	 * 'v': either a 1 or 0 bit (any value)
	 *
	 * for details see "The SPARC Architecture Manual", chapter 5
	 * ("Instructions") and appendix F + B.
	 */
	unsigned char *	pat = NULL;
	unsigned char *	instr_format[] = {
		"10rrrrr0.00011fff.ff000000.000sssss",
		"10rrrrr0.00011fff.ff1vvvvv.vvvvvvvv",	/* xor */

		"10rrrrr0.00111fff.ff000000.000sssss",
		"10rrrrr0.00111fff.ff1vvvvv.vvvvvvvv",	/* xnor */

		"10rrrrr0.00100fff.ff000000.000sssss",
		"10rrrrr0.00100fff.ff1vvvvv.vvvvvvvv",	/* sub */

		"10rrrrr0.00010fff.ff000000.000sssss",
		"10rrrrr0.00010fff.ff1vvvvv.vvvvvvvv",	/* or */

		"10rrrrr0.00000fff.ff000000.000sssss",
		"10rrrrr0.00000fff.ff1vvvvv.vvvvvvvv",	/* add */

		"10rrrrr0.00001fff.ff000000.000sssss",
		"10rrrrr0.00001fff.ff1vvvvv.vvvvvvvv",	/* and */

		/* XXX/TODO: add more codes */

		NULL,
	};


	/* take care of instruction size
	 */
	dest_len = dest_len - (dest_len % 4);
	dest_p = (unsigned long int *) dest;

	for ( ; count < dest_len ; count += 4) {
		pat = instr_format[rand () % 12];
		*dest_p++ = sparc_getinstr (pat, bad, bad_len);
	}

	return (count);
}


