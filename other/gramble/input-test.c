/* gramble - grammar ramble
 *
 * team teso
 *
 * input functions test program
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "input.h"


char * file_read (char *filename);


char *
file_read (char *filename)
{
	FILE *			fp;
	char *			array = NULL;
	unsigned long int	readbytes = 0;
	size_t			rb;


	fp = fopen (filename, "r");
	if (fp == NULL)
		return (NULL);

	do {
		array = xrealloc (array, readbytes + 1024);
		rb = fread (array + readbytes, 1, 1024, fp);
		readbytes += rb;
	} while (rb > 0);

	fclose (fp);

	return (array);
}


int
main (int argc, char **argv)
{
	void *	inp;
	char *	grammar;


	if (argc != 2) {
		printf ("usage: %s <inputfile>\n\n", argv[0]);

		exit (EXIT_FAILURE);
	}

	grammar = file_read (argv[1]);
	if (grammar == NULL) {
		fprintf (stderr, "couldn't open or read \"%s\", "
			"aborting\n", argv[1]);

		exit (EXIT_FAILURE);
	}

	inp = in_parse (grammar, strlen (grammar));
	printf ("---------------------------------------------------------"
		"----------------------\n");
	printf ("parsing of grammar %s %s.\n\n", argv[1],
		(inp == NULL) ? "failed" : "successful");

	/* TODO: sanity checking, free'ing etc.
	 */

	exit (EXIT_SUCCESS);
}


