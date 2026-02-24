/* x86.c - generic x86 functions
 *
 * by team teso
 */

#include <stdio.h>
#include <stdlib.h>
#include "shellcode.h"
#include "x86.h"


static unsigned long int x86_nop_rwreg (void);
static unsigned long int x86_nop_xfer (char *xferstr);


static unsigned long int
x86_nop_rwreg (void)
{
	unsigned long int	reg;

	do {
		reg = random_get (0, 7);
	} while (reg == 4);	/* 4 = $esp */

	return (reg);
}


static unsigned long int
x86_nop_xfer (char *xferstr)
{
	int			bw = 0;	/* bitfield walker */
	unsigned char		tgt;	/* resulting instruction */

	/* in a valid xferstr we trust */
	for (tgt = 0 ; xferstr != NULL && xferstr[0] != '\0' ; ++xferstr) {
		switch (xferstr[0]) {
		case ('0'):
			BSET (tgt, 1, 0, bw);
			break;
		case ('1'):
			BSET (tgt, 1, 1, bw);
			break;
		case ('r'):
			BSET (tgt, 3, x86_nop_rwreg (), bw);
			break;
		case ('.'):
			break;	/* ignore */
		default:
			fprintf (stderr, "on steroids, huh?\n");
			exit (EXIT_FAILURE);
			break;
		}
	}

	if (bw != 8) {
		fprintf (stderr, "invalid bitwalker: bw = %d\n", bw);
		exit (EXIT_FAILURE);
	}

	return (tgt);
}


unsigned int
x86_nop (unsigned char *dest, unsigned int dest_len,
	unsigned char *bad, int bad_len)
{
	int	walk;
	int	bcount;	/* bad counter */
	char *	xs;
	char *	xferstr[] = {
		"0011.0111",	/* aaa */
		"0011.1111",	/* aas */
		"1001.1000",	/* cbw */
		"1001.1001",	/* cdq */
		"1111.1000",	/* clc */
		"1111.1100",	/* cld */
		"1111.0101",	/* cmc */
		"0010.0111",	/* daa */
		"0010.1111",	/* das */
		"0100.1r",	/* dec <reg> */
		"0100.0r",	/* inc <reg> */
		"1001.1111",	/* lahf */
		"1001.0000",	/* nop */
		"1111.1001",	/* stc */
		"1111.1101",	/* std */
		"1001.0r",	/* xchg al, <reg> */
		NULL,
	};
	unsigned char	tgt;

/*
 * XXX: those nops are only one byte long. they could be used as byte values
 * in opcodes like mov (add, sub, or, ...) as value. that would increase the
 * randomness of the string. since the value is "nop save" we have no problem
 * if the execution starts within this nop.
 * now, having word sized nops, even larger nops are possible (again increasssing
 * the randomness of the nop string).
 * however, its a little complicated ;)
 */

	for (walk = 0 ; dest_len > 0 ; dest_len -= 1 , walk += 1) {
		/* avoid endless loops on excessive badlisting */
		for (bcount = 0 ; bcount < 16384 ; ++bcount) {
			xs = xferstr[random_get (0, 15)];
			tgt = x86_nop_xfer (xs);

			dest[walk] = tgt;
			if (badstr (&dest[walk], 1, bad, bad_len) == 0)
				break;
		}

		/* should not happen */
		if (bcount >= 16384) {
			fprintf (stderr, "too much blacklisting, giving up...\n");
			exit (EXIT_FAILURE);
		}
	}

	return (walk);
}


