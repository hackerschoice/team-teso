
#include <stdio.h>
#include <stdlib.h>
#include "shellcode.h"
#include "x86_bsd.h"


typedef void (* func_ptr)(void);

int
main (int argc, char *argv[])
{
	func_ptr	fp;
	unsigned char	nopspace[20480];

	x86_nop (nopspace, sizeof (nopspace), "\x25\x0d\x0a\x00", 4);
	nopspace[sizeof (nopspace) - 1] = '\xcc';

	fp = (func_ptr) nopspace;
	fp ();

	exit (EXIT_SUCCESS);
}


