/*
 * Copyright (C) 1999/2000 Sebastian Krahmer.
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
#include "socket.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

// since this is entered by new process each call
// we must make itextern and increased by main()
extern short inc;

namespace NS_Filter {

const char SSL_HANDSHAKE = 22;
const char SSL_MAJOR3 = 3;
const char SSL_CLIENTHELLO = 1;

unsigned short portbase = 8888;

using namespace NS_Misc;

void check_and_forward(int server)
{
	struct sockaddr_in dst;
	int client, r = 0;

	// we are server. get real dest.
	if (NS_Socket::dstaddr(server, &dst) < 0) {
		log(NS_Socket::why());
		die(NULL);
	}
	
	// calc. port to bind to
	unsigned short port = portbase + (inc++ % (65000-portbase));

	// make connection to real server
	if ((client = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		log("NS_Filter::check_and_forward::socket");
		die(NULL);
	}


	fd_set rset;
	FD_ZERO(&rset);
	FD_SET(server, &rset);
	struct timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;

	// watch if real client sends some data
	if (select(server+1, &rset, NULL, NULL, &tv) < 0) {
		log("NS_Filter::check_and_forward::select");
		die(NULL);
	}

	char buf[4096];
	memset(buf, 0, sizeof(buf));

	// if so, check for SSLv3
	if (FD_ISSET(server, &rset)) {
		if ((r = read(server, buf, sizeof(buf))) < 0) {
			log("NS_Filter::check_and_forward::read");
			die(NULL);
		}
		if (buf[0] == SSL_HANDSHAKE &&
		    buf[1] == SSL_MAJOR3 &&
		    buf[5] == SSL_CLIENTHELLO &&
		    buf[9] == SSL_MAJOR3) {	// got SSLv3 ?

			// bind to special port to signal that
			// SSL is coming
			if (NS_Socket::bind_local(client, port, false) < 0) {
				log(NS_Socket::why());
				die(NULL);
			}
			log("Filtered SSL connection.");
		}
	}
	// Now, do the connect, aftee we bound or not
	if (connect(client, (struct sockaddr*)&dst, sizeof(dst)) < 0) {
		log("NS_Filter::check_and_forward::connect");
		die(NULL);
	}

	// If there was any data sent by client, flush it now
	if (FD_ISSET(server, &rset))
		write(client, buf, r);
			
	int max = server > client ? server : client;
	for (;;) {
		// now, do the proxy
		FD_ZERO(&rset);
		FD_SET(server, &rset);
		FD_SET(client, &rset);

		if (select(max+1, &rset, NULL, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;
			else {
				log("NS_Filter::check_and_forward::select()");
				die(NULL);
			}
		}

		if (FD_ISSET(client, &rset)) {
			r = read(client, buf, sizeof(buf));
			if (r <= 0)
				break;
			if (write(server, buf, r) < 0)
				break;
		}
		if (FD_ISSET(server, &rset)) {
			errno = 0;
			r = read(server, buf, sizeof(buf));
			if (r <= 0)
				break;
			if (write(client, buf, r) < 0)
				break;
		}
	}
	close(client);
	return;
}

}; // namespace
	
