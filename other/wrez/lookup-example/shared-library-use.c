
#include <stdio.h>
#include "shared-library.h"


int
main (int argc, char *argv[])
{
	void *	cow;

	printf ("before calling func\n");
	cow = mysharedfunc (2000);
	printf ("after calling func\n");
}


