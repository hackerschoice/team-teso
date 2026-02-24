/* fornax - distributed network
 *
 * by team teso
 *
 * compiler test program
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../shared/common.h"
#include "element.h"
#include "compiler.h"
#include "script.h"


extern void	scr_elem_exec (element **el);
char *		file_read (char *filename);


char *
file_read (char *filename)
{
	FILE			*fp;
	char			*array = NULL;
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
	element **	script_c;
	char *		script;

	if (argc != 2) {
		printf ("usage: %s <inputfile>\n\n", argv[0]);
		exit (EXIT_FAILURE);
	}

	script = file_read (argv[1]);
	if (script == NULL) {
		fprintf (stderr, "couldn't open %s, aborting\n", argv[1]);
		exit (EXIT_FAILURE);
	}

	script_c = cp_compile (script, strlen (script));
	printf ("-------------------------------------------------------------------------------\n");
	printf ("compilation of script %s %s.\n\n", argv[1], (script_c == NULL) ? "failed" : "successful");

	printf ("\ntrying to run it...\n");
	scr_elem_exec (script_c);

	elem_list_free (script_c);

	exit (EXIT_SUCCESS);
}


