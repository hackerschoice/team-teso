
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void foo (char *line);

int
main (int argc, char *argv[])
{
	FILE *	f;
	char	line[1024];

	f = fopen (argv[1], "rb");
	if (f == NULL) {
		fprintf (stderr, "usage: %s file\n", argv[0]);

		exit (EXIT_FAILURE);
	}

	fgets (line, sizeof (line) - 1, f);
	line[1023] = '\x00';
	foo (line);

	exit (EXIT_SUCCESS);
}

void
foo (char *line)
{
	printf (line);
}

