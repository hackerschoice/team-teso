
/* TODO: better randomness
 */

#include <sys/types.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include "shellcode.h"


unsigned long int
random_get (unsigned long int low, unsigned long int high)
{
	unsigned long int	val;

	if (low > high) {
		low ^= high;
		high ^= low;
		low ^= high;
	}

	val = (unsigned long int) random ();
	val %= (high - low);
	val += low;

	return (val);
}


void
random_init (void)
{
	srandom (time (NULL));
}


int
bad (unsigned char u)
{
	if (u == '\x00' || u == '\x0a' || u == '\x0d' || u == '\x25')
		return (1);

	return (0);
}

int
badstr (unsigned char *code, int code_len, unsigned char *bad, int bad_len)
{
	int	n;

	for (code_len -= 1 ; code_len >= 0 ; --code_len) {
		for (n = 0 ; n < bad_len ; ++n)
			if (code[code_len] == bad[n])
				return (1);
	}

	return (0);
}


