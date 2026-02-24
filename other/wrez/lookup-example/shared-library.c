
#include <stdio.h>
#include <stdlib.h>


int
myshareddeepfunc (int cow);


void *
mysharedfunc (unsigned int size)
{
	void *	foo;


	fprintf (stderr, "mysharedfunc\n");

	foo = malloc (size);
	fprintf (stderr, "  # called malloc\n");
	
	free (foo);
	fprintf (stderr, "  # called free\n");

	foo = malloc (10 * size);
	fprintf (stderr, "  # called malloc\n");

	free (foo);
	fprintf (stderr, "  # called free\n");

	/* example for deep call */
	if (myshareddeepfunc (size / 2) == size)
		return ((void *) 0);

	return (foo);
}


int
myshareddeepfunc (int cow)
{
	return (cow / 2);
}


