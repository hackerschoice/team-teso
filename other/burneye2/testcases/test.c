
#include <stdio.h>


int
main (int argc, char *argv[])
{
	printf ("instruction test\n");

	__asm__ __volatile__ ("das");
}


