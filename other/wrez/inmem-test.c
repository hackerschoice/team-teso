
/* small victim program to test in-memory infection with
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>


int
main (int argc, char *argv[])
{
	int	i = 0;

	srandom (time (NULL));

	for (;;) {
		printf ("test %5d\n", i++);
		usleep (400000);
		(void) malloc (random () % 16384);
	}
}

