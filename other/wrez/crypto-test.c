
#include <sys/utsname.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"


int
main (int argc, char *argv[])
{
	char		hw[] = "hello world";
	unsigned int	hash;
	struct utsname	un;


	hash = mhash (hw, sizeof (hw));
	printf ("mhash(hw) = 0x%08x\n", hash);

	uname (&un);
	hash = mhash ((unsigned char *) &un, sizeof (un));
	printf ("mhash(utsname) = 0x%08x\n", hash);

	if (argc == 2) {
		hash = mhash (argv[1], strlen (argv[1]));
		printf ("mhash(\"%s\") = 0x%08x\n", argv[1], hash);
	}

	exit (EXIT_SUCCESS);
}


