/* shellcode extraction utility,
 * by type / teso, small mods by scut.
 */


#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef IRIX
#include <sys/cachectl.h>
#endif

#ifdef HPUX
extern char *	cbegin;
extern char *	cend;
#else
extern void	cbegin ();
extern void	cend ();
#endif

typedef void (* fptr)(void);

int
bad (unsigned char u);


int
main (int argc, char *argv[])
{
	int		i,
			bbytes = 0;
	unsigned char *	buf = (unsigned char *) cbegin;

	unsigned char	ebuf[1024];
	fptr		ebuf_p = (fptr) &ebuf[0];


	fprintf (stderr, "/* %lu byte shellcode */\n",
		(unsigned long int) cend - (unsigned long int) cbegin);

	for (i = 0 ; buf < (unsigned char *) cend; ++buf) {
		if (i % 12 == 0 && buf > (unsigned char *) cbegin)
			printf ("\n");
		if (i % 12 == 0)
			printf ("\"");

		if (bad (*buf & 0xff)) {
			printf ("_\\x%02x_", *buf & 0xff);
			bbytes += 1;
		} else {
			printf ("\\x%02x", *buf & 0xff);
		}

		if (++i >= 12) {
			i = 0;
			printf ("\"");
		}
	}
	if (i % 12 == 0)
		printf (";\n");
	else
		printf ("\";\n");

	printf("\n");

	fprintf (stderr, "bad bytes = %d\n", bbytes);

	if (argc > 1) {
		memcpy (ebuf, cbegin, (unsigned long int) cend -
			(unsigned long int) cbegin);
#ifdef IRIX
		memcpy (ebuf + ((unsigned long int) cend -
			(unsigned long int) cbegin), "/bin/sh\x42_ABCDEFGHIJKLMNOPQRSTUVWXYZ", 40);
		cacheflush (ebuf, sizeof (ebuf), BCACHE);
#endif
		ebuf_p ();
	}

	exit (EXIT_SUCCESS);
}


int
bad (unsigned char u)
{
	if (u == '\x00' || u == '\x0a' || u == '\x0d' || u == '\x25')
		return (1);

	return (0);
}


