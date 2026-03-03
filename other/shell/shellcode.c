/* shellcode extraction utility,
 * by type / teso, small mods by scut.
 */


#include <stdio.h>
#include <stdlib.h>

extern void	cbegin ();
extern void	cend ();


int
main (int argc, char *argv[])
{
	int		i;
	unsigned char *	buf = (unsigned char *) cbegin;
	unsigned char	ex_buf[1024];


	printf ("/* %d byte shellcode */\n", cend - cbegin);
	printf ("\"");
	for (i = 0 ; buf < (unsigned char *) cend; ++buf) {

		printf ("\\x%02x", *buf & 0xff);

		if (++i >= 12) {
			i = 0;
			printf ("\"\n\"");
		}
	}
	printf ("\";\n");

	printf("\n");

	if (argc > 1) {
		printf ("%02x\n", ((unsigned char *) cbegin)[0]);
		printf ("%02x\n", ex_buf[0]);
		memcpy (ex_buf, cbegin, cend - cbegin);
		printf ("%02x\n", ex_buf[0]);
		((void (*)()) &ex_buf)();
	}

	exit (EXIT_SUCCESS);
}

