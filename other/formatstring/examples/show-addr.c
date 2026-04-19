
#include <stdio.h>
#include <stdlib.h>

void foo (void);

int
main (int argc, char *argv[])
{
	foo ();

	exit (EXIT_SUCCESS);
}


void
foo (void)
{
	char	buf[128];

	buf[0] = '\0';
	strcat (buf, "AAA0AAA1.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x");

	printf (buf);
}


