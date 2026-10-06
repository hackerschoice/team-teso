#include <stdio.h>

extern void unscramble (void);

int
main (int argc, char **argv)
{
	char	*ptr = "TEST PROGRAM";

	puts (ptr);
	unscramble ();
	puts (ptr);
	return (0);
}
