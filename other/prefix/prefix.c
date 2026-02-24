
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>


int
main (int argc, char *argv[])
{
	unsigned char	prefix_arr[] = {
		0x2e,	/* cs segment override */
		0x36,	/* ss segment override */
		0x3e,	/* ds segment override */
		0x26,	/* es segment override */
		0x64,	/* fs segment override */
		0x65,	/* gs segment override */
		0x67,	/* adress size override */
		0xf2,	/* repne/repnz prefix */
		0xf3,	/* repe/repz prefix */
	/*	0xf0,*/	/* lock prefix */
	/*	0x66,*/	/* operand size override */
	};

	unsigned char	code[64];
	int		n, i,
			clen,
			cwlk;
	unsigned long	ef_should,
			ef_is;


	srandom (time (NULL));

	for (n = 0 ; n < 32 ; ++n) {
		clen = random () % 14;
		clen += 1;

		memset (code, '\x00', sizeof (code));

		for (cwlk = 0 ; clen > 0 ; --clen, ++cwlk) {
			code[cwlk] = prefix_arr[random () %
				(sizeof (prefix_arr) / sizeof (prefix_arr[0]))];
		}
		code[cwlk++] = 0x9c;	/* pushf */
		code[cwlk++] = 0x5a;	/* popl %edx */
		code[cwlk] = 0xc3;	/* ret */

		printf ("%4d (%2d):", n, cwlk);
		for (i = 0 ; i < cwlk ; ++i)
			printf (" %02x", code[i]);
		printf ("\n");

		printf ("\tef 0x%08lx  got 0x%08lx\n", ef_should, ef_is);

		__asm__ __volatile__ ("
			pushf
			popl	%%eax
			pushl	$0x41414141
			call	*%%edx
			addl	$4, %%esp"
			: "=a" (ef_should), "=d" (ef_is)
			: "d" ((unsigned long) code)
		);

		if (ef_should != ef_is) {
			printf ("\tATTENTION: difference detected.\n");

			exit (EXIT_FAILURE);
		}
	}

	exit (EXIT_SUCCESS);
}


