#include <stdio.h>
#include <string.h>

int
main (int argc, char *argv[])
{
	unsigned char	carnary[5];
	unsigned char	foo[4];

	memset (foo, '\x00', sizeof (foo));

	strcpy (carnary, "AAAA");
	printf ("foo|carnary: %02x%02x%02x%02x | %02x%02x%02x%02x\n",
		foo[0], foo[1], foo[2], foo[3],
		carnary[0], carnary[1], carnary[2], carnary[3]);

	fprintf (stderr, "%16u%n\n", 7350, (int *) &foo[0]);
	printf ("foo|carnary: %02x%02x%02x%02x | %02x%02x%02x%02x\n",
		foo[0], foo[1], foo[2], foo[3],
		carnary[0], carnary[1], carnary[2], carnary[3]);

	fprintf (stderr, "%32u%n\n", 7350, (int *) &foo[1]);
	printf ("foo|carnary: %02x%02x%02x%02x | %02x%02x%02x%02x\n",
		foo[0], foo[1], foo[2], foo[3],
		carnary[0], carnary[1], carnary[2], carnary[3]);

	fprintf (stderr, "%64u%n\n", 7350, (int *) &foo[2]);
	printf ("foo|carnary: %02x%02x%02x%02x | %02x%02x%02x%02x\n",
		foo[0], foo[1], foo[2], foo[3],
		carnary[0], carnary[1], carnary[2], carnary[3]);

	fprintf (stderr, "%128u%n\n", 7350, (int *) &foo[3]);
	printf ("foo|carnary: %02x%02x%02x%02x | %02x%02x%02x%02x\n",
		foo[0], foo[1], foo[2], foo[3],
		carnary[0], carnary[1], carnary[2], carnary[3]);
}


