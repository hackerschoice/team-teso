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
#include "filter.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string>
#include <signal.h>

using namespace NS_Misc;

void usage(char *s)
{
}

unsigned short inc = 0;

int main(int argc, char **argv)
{

	int c, sfd, afd;
	unsigned short port = 0;
	
	if (argc < 2)
		usage(argv[0]);
		
	// handle commandline arguments
	while ((c = getopt(argc, argv, "p:")) != -1) {
		switch (c) {
		case 'p':
			port = atoi(optarg);
			break;
		default:
			usage(argv[0]);
			break;
		}
	}
	if (signal(SIGCHLD, sig_x) < 0)
		die("main::signal");

	// do the usual network-server setup
	if ((sfd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		die("main::socket");

	// bind + listen
	if (NS_Socket::bind_local(sfd, port, true) < 0)
		die(NS_Socket::why());

	while ((afd = accept(sfd, NULL, 0)) >= 0) {
		++inc;
		if (fork() > 0) {
			close(afd);
			continue;
		}
		cerr<<"l\n";
		NS_Filter::check_and_forward(afd);
		exit(0);
	}
	return 0;
}

