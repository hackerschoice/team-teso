
#include <stdio.h>
#include <stdlib.h>

int
main (int argc, char *argv[])
{
	unsigned char *	pw;
	unsigned char	poo[64];

	memset (poo, 0x00, sizeof (poo));
	gets (poo);
	quicksort (poo, 0, sizeof (poo) - 1);

	for (pw = poo ; *pw == '\0' ; ++pw)
		;
	poo[sizeof (poo) - 1] = '\0';

	printf ("%s\n", pw);
}


