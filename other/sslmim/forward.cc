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
#include "misc.h"
#include "session.h"
#include "forward.h"

#include <stdio.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <openssl/err.h>

#define SSL_LOG "./mim"

using namespace NS_Misc;

int ssl_forward(CSession *client, SSession *server)
{
	size_t r;
	fd_set rset;
	char buf[1500];
	int max;
	char cfile[1024], sfile[1024];

	sprintf(cfile, "%s.%ld.%d.client", SSL_LOG, time(NULL), getpid());
	sprintf(sfile, "%s.%ld.%d.server", SSL_LOG, time(NULL), getpid());

	int cfd = open(cfile, O_WRONLY|O_CREAT|O_APPEND, 0600);
	int sfd = open(sfile, O_WRONLY|O_CREAT|O_APPEND, 0600);

	if (cfd < 0 || sfd < 0) {
		log("ssl_forward::open() returned error");
		die(NULL);
	}

	// I know that there exists problems with SSL+select
	// ...
	for (;;) {
		FD_ZERO(&rset);
		FD_SET(client->fileno(), &rset);
		FD_SET(server->fileno(), &rset);

		max = (client->fileno() > server->fileno() ?
			client->fileno() : server->fileno());

		if (select(max + 1, &rset, NULL, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;
			else {
				log("ssl_forward::select");
				die(NULL);
			}
		}
		if (FD_ISSET(client->fileno(), &rset)) {
			r = client->read(buf, sizeof(buf));
			if (r <= 0)
				break;
			write(cfd, buf, r);
			if (server->write(buf, r) <= 0)
				break;
		}
		if (FD_ISSET(server->fileno(), &rset)) {
			r = server->read(buf, sizeof(buf));
			if (r <= 0)
				break;
			write(sfd, buf, r);
			if (client->write(buf, r) <= 0)
				break;
		}
	}
	close(cfd);
	close(sfd);
	return 0;	// upon return here, caller
			// will shutdown connections
}			

