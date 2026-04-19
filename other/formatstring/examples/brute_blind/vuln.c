
#include <stdio.h>
#include <stdlib.h>


int
main (int argc, char *argv[])
{
	char	foobuf[512];

	if (argc < 2)
		exit (EXIT_FAILURE);

	snprintf (foobuf, sizeof (foobuf), argv[1]);
	foobuf[sizeof (foobuf) - 1] = '\x00';

	exit (EXIT_SUCCESS);
}


