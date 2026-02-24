/* cipher-mrsa-interface.c - interface module to the mrsa module
 *
 * works around some limitations, bugs and cryptographical weaknesses within
 * the mrsa library
 */

#ifdef	WREZ
#include "int80.h"
#include "common.h"
#include "wrutil.h"
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#include "cipher-mrsa.h"
#include "cipher-mrsa-interface.h"


#ifndef	WREZ
void
hexdump (char *desc, unsigned char *data, unsigned int amount);
#endif

#define	CLEAR_GAP_KEY	RSA_SIZE
#define	CLEAR_GAP_MSG	1

int
rsa_keypair_generate (rsa_pubkey *pub, rsa_privkey *priv)
{
	rsa_key	key;
	NN	msgtest,	/* test en/decryption */
		msgorig;
	int	fd = -1,
		try_max = 10;
#ifdef	WREZ
	char *	rndfilename;

	STRINGPTR (rndfilename, "/dev/urandom");
#else
	char *	rndfilename = "/dev/urandom";
#endif

new_key:
	fd = open (rndfilename, O_RDONLY);
	if (fd < 0)
		return (-1);

	memset (pub, 0x00, sizeof (*pub));
	memset (priv, 0x00, sizeof (*priv));

	if (read (fd, msgtest, sizeof (msgtest)) != sizeof (msgtest))
		goto bail;

try_key:
	memset (&key, 0x00, sizeof (key));
	if (read (fd, key.p, sizeof (key.p)) != sizeof (key.p) ||
		read (fd, key.q, sizeof (key.q)) != sizeof (key.q))
	{
		goto bail;
	}

	/* NUL out highest bit (i think this works around a stall bug in
	 * mrsa, though i'm not quite sure what triggers it). it works with
	 * this code at least.
	 */
#define	CLEAR_UPPER(count,key) \
	{ \
		int	cu, co = count; \
		for (cu = (sizeof (key) - 1) ; co > 0 ; --co, --cu) \
			((unsigned char *) key)[cu] = 0x00; \
	}

	CLEAR_UPPER (CLEAR_GAP_KEY, key.p);
	CLEAR_UPPER (CLEAR_GAP_KEY, key.q);

	/* try to generate a key out of the random data. if that fails, try
	 * again or give up when we had enough tries already.
	 */
	if (rsa_gen (&key) == 0) {
		try_max -= 1;
		if (try_max > 0)
			goto try_key;

		goto bail;
	}

	close (fd);

	/* public key components
	 */
	cp (pub->pq, key.pq);
	cp (pub->e, key.e);

	/* private key components
	 */
	cp (priv->d, key.d);
	cp (priv->p, key.p);
	cp (priv->q, key.q);
	cp (priv->dp, key.dp);
	cp (priv->dq, key.dq);
	cp (priv->qp, key.qp);

	/* test key to work around bug in mrsa.
	 * XXX: once this test succeeds the keys are safe to use and work with
	 *      all possible input
	 * XXX: forbid d = 1, this is silly
	 */
	if (priv->d[RSA_SIZE - 1] == 0x01)
		goto new_key;
	memcpy (msgorig, msgtest, sizeof (msgorig));
	rsa_encrypt (pub, msgtest);
	rsa_decrypt (priv, msgtest);
	if (memcmp (msgtest, msgorig, sizeof (msgtest) != 0))
		goto new_key;

	return (0);

bail:
	if (fd != -1)
		close (fd);

	return (-1);
}


void
rsa_keypair_dump (int fd, rsa_pubkey *pub, rsa_privkey *priv)
{
	char	str[RSA_SIZE * 4 + 3];

#define	KEYOUT(key) \
	nh (str, key); \
	str[strlen (str) + 1] = '\0'; \
	str[strlen (str)] = '\n'; \
	write (fd, str, strlen (str));

	if (pub != NULL) {
		KEYOUT (pub->pq);
		KEYOUT (pub->e);
	}

	if (priv != NULL) {
		KEYOUT (priv->d);
		KEYOUT (priv->p);
		KEYOUT (priv->q);
		KEYOUT (priv->dp);
		KEYOUT (priv->dq);
		KEYOUT (priv->qp);
	}
#undef	KEYOUT

	return;
}


/* rsa_keypair_import
 *
 * import a 512 bit rsa keypair from `fd' in human readable format to the
 * `pub' and `priv' structures. each can be set to NULL to skip them.
 *
 * return in any case
 */

void
rsa_keypair_import (int fd, rsa_pubkey *pub, rsa_privkey *priv)
{
	/* TODO */
}


void
rsa_encrypt (rsa_pubkey *pub, unsigned char *data)
{
	rsa_key	key;

	memset (&key, 0x00, sizeof (key));
	cp (key.pq, pub->pq);
	cp (key.e, pub->e);

	rsa_enc ((N) data, &key);
}


void
rsa_decrypt (rsa_privkey *priv, unsigned char *data)
{
	rsa_key	key;

	memset (&key, 0x00, sizeof (key));
	cp (key.d, priv->d);
	cp (key.p, priv->p);
	cp (key.q, priv->q);
	cp (key.dp, priv->dp);
	cp (key.dq, priv->dq);
	cp (key.qp, priv->qp);

	rsa_dec ((N) data, &key);
}


#ifdef	TESTING
int
main (int argc, char *argv[])
{
	int		n,
			fd;
	rsa_pubkey	pub;
	rsa_privkey	priv;

	NN		msg;
	NN		msg_orig;
	int		testcount = 100,
			matchcount = 0;

	n = rsa_keypair_generate (&pub, &priv);
	printf ("rsa_keypair_generate () = %d\n", n);

	/* dump keypair
	 */
	printf ("keypair\n");
	rsa_keypair_dump (2, &pub, &priv);
	printf ("\n");

	/* test, get random message and encrypt / decrypt it
	 */
testcrypt:
	fd = open ("/dev/urandom", O_RDONLY);
	read (fd, msg, sizeof (msg));
	close (fd);
	CLEAR_UPPER (CLEAR_GAP_MSG, msg);
	memcpy (msg_orig, msg, sizeof (msg_orig));
//	hexdump ("message", (void *) msg, sizeof (msg));

	rsa_encrypt (&pub, (unsigned char *) msg);
//	hexdump ("message-encrypted", (void *) msg, sizeof (msg));
	rsa_decrypt (&priv, (unsigned char *) msg);
//	hexdump ("message-decrypted", (void *) msg, sizeof (msg));

	if (memcmp (msg, msg_orig, sizeof (msg)) == 0)
		matchcount += 1;

	if (--testcount > 0)
		goto testcrypt;

	printf ("\n%d matched\n", matchcount);

	return (0);
}


void
hexdump (char *desc, unsigned char *data, unsigned int amount)
{
	unsigned int	dp, p;	/* data pointer */
	const char	trans[] =
		"................................ !\"#$%&'()*+,-./0123456789"
		":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
		"nopqrstuvwxyz{|}~...................................."
		"....................................................."
		"........................................";


	printf ("/* %s, %u bytes */\n", desc, amount);

	for (dp = 1; dp <= amount; dp++) {
		fprintf (stderr, "%02x ", data[dp-1]);
		if ((dp % 8) == 0)
			fprintf (stderr, " ");
		if ((dp % 16) == 0) {
			fprintf (stderr, "| ");
			p = dp;
			for (dp -= 16; dp < p; dp++)
				fprintf (stderr, "%c", trans[data[dp]]);
			fflush (stderr);
			fprintf (stderr, "\n");
		}
		fflush (stderr);
	}
	if ((amount % 16) != 0) {
		p = dp = 16 - (amount % 16);
		for (dp = p; dp > 0; dp--) {
			fprintf (stderr, "   ");
			if (((dp % 8) == 0) && (p != 8))
				fprintf (stderr, " ");
			fflush (stderr);
		}
		fprintf (stderr, " | ");
		for (dp = (amount - (16 - p)); dp < amount; dp++)
			fprintf (stderr, "%c", trans[data[dp]]);
		fflush (stderr);
	}
	fprintf (stderr, "\n");

	return;
}

#endif

