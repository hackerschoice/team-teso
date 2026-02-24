
#include <stdio.h>
#include "common.c"


int
main (int argc, char *argv[])
{
	unsigned char	foo[4];
	unsigned char	src[64],
			dst[64];

	memset (src, 'a', 64);
	src[sizeof (src) - 1] = '\0';
	memcpy (dst, src, sizeof (dst));
	src[sizeof (src) - 1] = '\n';

	printf ("memcmp (src, dst, 64) = %d\n",
		memcmp (src, dst, sizeof (src)));

	printf ("strlen (\"hello world\") = %d\n", strlen ("hello world"));
	printf ("strlen (\"\") = %d\n", strlen (""));

	foo[3] = '\0';
	memset (foo, '\x41', 3);
	printf ("foo[0],[1],[2],[3]: 0x%02x 0x%02x 0x%02x 0x%02x\n",
		foo[0], foo[1], foo[2], foo[3]);

	printf ("strcmp (\"foobar\", \"foobaz\") == %d\n",
		strcmp ("foobar", "foobaz"));
	printf ("strcmp (\"foobar\", \"foobar\") == %d\n",
		strcmp ("foobar", "foobar"));


	return (0);
}


