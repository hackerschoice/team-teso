#include <stdio.h>
#include <string.h>

int
main (int argc, char *argv[])
{
	unsigned char	carnary[5];
	unsigned char	foo[4];

	memset (foo, '\x00', sizeof (foo));
	strcpy (carnary, "AAAA");

	fprintf (stderr, "%16u%n%16u%n%32u%n%64u%n\n", 1, (int *) &foo[0],
		1, (int *) &foo[1], 1, (int *) &foo[2], 1, (int *) &foo[3]);

	printf ("foo|carnary: %02x%02x%02x%02x | %02x%02x%02x%02x\n",
		foo[0], foo[1], foo[2], foo[3],
		carnary[0], carnary[1], carnary[2], carnary[3]);
}


