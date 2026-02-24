/* mips.c - generic mips functions
 *
 * by team teso
 */

#include <stdio.h>
#include <stdlib.h>
#include "shellcode.h"
#include "mips.h"

static unsigned long int mips_nop_rwreg (void);
static unsigned long int mips_nop_roreg (void);
static unsigned long int mips_nop_xfer (char *xferstr);

/* mips generic isa "nop" space generator
 */

/* get random read write register (i.e. not sp, everything else allowed)
 */
static unsigned long int
mips_nop_rwreg (void)
{
	unsigned long int	reg;

	do {
		reg = random_get (0, 31);
	} while (reg == 29);	/* 29 = $sp */

	return (reg);
}


static unsigned long int
mips_nop_roreg (void)
{
	return (random_get (0, 31));
}


static unsigned long int
mips_nop_xfer (char *xferstr)
{
	int			bw = 0;	/* bitfield walker */
	unsigned long int	tgt;	/* resulting instruction */

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
			BSET (tgt, 5, mips_nop_roreg (), bw);
			break;
		case ('w'):
			BSET (tgt, 5, mips_nop_rwreg (), bw);
			break;
		case ('c'):
			BSET (tgt, 16, random_get (0, 0xffff), bw);
			break;
		case ('.'):
			break;	/* ignore */
		default:
			fprintf (stderr, "on steroids, huh?\n");
			exit (EXIT_FAILURE);
			break;
		}
	}

	if (bw != 32) {
		fprintf (stderr, "invalid bitwalker: bw = %d\n", bw);
		exit (EXIT_FAILURE);
	}

	return (tgt);
}


unsigned int
mips_nop (unsigned char *dest, unsigned int dest_len,
	unsigned char *bad, int bad_len)
{
	int	walk;
	int	bcount;	/* bad counter */
	char *	xs;
	char *	xferstr[] = {
		"000000.r.r.w.00000.000100",	/* sllv rs rt rd */
		"000000.r.r.w.00000.000110",	/* srlv rs rt rd */
		"000000.r.r.w.00000.000111",	/* srav rs rt rd */
		"000000.r.r.w.00000.100001",	/* addu rs rt rd */
		"000000.r.r.w.00000.100011",	/* subu rs rt rd */
		"000000.r.r.w.00000.100100",	/* and rs rt rd */
		"000000.r.r.w.00000.100101",	/* or rs rt rd */
		"000000.r.r.w.00000.100110",	/* xor rs rt rd */
		"000000.r.r.w.00000.100111",	/* nor rs rt rd */
		"000000.r.r.w.00000.101010",	/* slt rs rt rd */
		"000000.r.r.w.00000.101011",	/* sltu rs rt rd */
		"001001.r.w.c",			/* addiu rs rd const */
		"001010.r.w.c",			/* slti rs rd const */
		"001011.r.w.c",			/* sltiu rs rd const */
		"001100.r.w.c",			/* andi rs rd const */
		"001101.r.w.c",			/* ori rs rd const */
		"001110.r.w.c",			/* xori rs rd const */
		"001111.00000.w.c",		/* lui rd const */
		NULL,
	};
	unsigned long int	tgt;

	if (dest_len % 4) {
		fprintf (stderr, "off by %d padding of dest_len (= %u), rounding down\n",
			dest_len % 4, dest_len);
		dest_len -= (dest_len % 4);
	}

	for (walk = 0 ; dest_len > 0 ; dest_len -= 4 , walk += 4) {
		/* avoid endless loops on excessive badlisting */
		for (bcount = 0 ; bcount < 16384 ; ++bcount) {
			xs = xferstr[random_get (0, 17)];
			tgt = mips_nop_xfer (xs);

			dest[walk + 0] = (tgt >> 24) & 0xff;
			dest[walk + 1] = (tgt >> 16) & 0xff;
			dest[walk + 2] = (tgt >> 8) & 0xff;
			dest[walk + 3] = tgt & 0xff;
			if (badstr (&dest[walk], 4, bad, bad_len) == 0)
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



