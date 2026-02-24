/*
 * Copyright (C) 2001 Sebastian Krahmer.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastian Krahmer.
 * 4. The name Sebastian Krahmer may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "session.h"

int main(int argc, char **argv)
{
	struct hostent *he;
	struct sockaddr_in sin;
	BIO *bio;
	X509 *x509;
	int sfd;
	
	if (argc < 3) {
		printf("\ncf -- SSL certfetch (C) 2001 by Sebastian Krahmer\n\n");
		printf("Usage: %s <host> <port>\n\n", *argv);
		exit(1);
	}

	// Usual network stuff
	if ((sfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(errno);
	}

	if ((he = gethostbyname(argv[1])) == NULL) {
		herror("gethostbyname");
		exit(1);
	}
	memset(&sin, 0, sizeof(sin));
	sin.sin_port = htons(atoi(argv[2]));
	sin.sin_family = AF_INET;
	memcpy(&sin.sin_addr.s_addr, he->h_addr, he->h_length);

	if (connect(sfd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
		perror("connect");
		exit(errno);
	}

	// start client-session
	CSession *sess = NULL;

	try {
		sess = new CSession;
	} catch (int) {
		fprintf(stderr, "%s", sess->why());
		exit(1);
	}

	sess->start();
	sess->fileno(sfd);
	if (sess->connect() < 0) {
		fprintf(stderr, "Host not SSL capable (handshake failed).\n");
		exit(2);
	}

	// and lets get the certificate
	x509 = SSL_get_peer_certificate(sess->ssl());

	if (!x509) {
		fprintf(stderr, "Host has no cert.\n");
		exit(3);
	}

	// just print in readable form. :> 'openssl x509 -text < cert for
	// analyzation must be done by you.
	bio = BIO_new_fp(stdout, 0);
	PEM_write_bio_X509(bio, x509);
	BIO_flush(bio);
	
	return 0;
}
	
		
