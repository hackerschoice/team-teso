/*
 * Copyright (C) 2003 Sebastian Krahmer.
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
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <vector>
#include <errno.h>

#include "ssh.h"
#include "misc.h"
#include "thread.h"

using namespace std;

void *try_pubkey(void *);
static char range[128];

void usage(const char *s)
{
	printf("Usage: %s <-n threads> <-l login> <-k pubkeyfile> "
	       "<-r ip-range> [-p port]\n\n", s);
	exit(1);
}


int main(int argc, char **argv)
{
	int c, nthreads = 10, i = 0;
	thread_data td;
	
	td.port = 22;
	td.passwd = false;

	while ((c = getopt(argc, argv, "n:l:k:r:p:P")) != -1) {
		switch (c) {
		case 'P':
			td.passwd = true;
			break;
		case 'r':
			td.host = optarg;
			snprintf(range, sizeof(range), "%s", optarg);
			break;
		case 'l':
			td.login = optarg;
			break;
		case 'k':
			td.keyfile = optarg;
			break;
		case 'p':
			td.port = atoi(optarg);
			break;
		case 'n':
			nthreads = atoi(optarg);
			break;
		default:
			usage(*argv);
		}
	}

	if (td.login.size() == 0 || td.keyfile.size() == 0 ||
	    td.host.size() == 0)
		usage(*argv);

	vector<pthread_t *> tids(nthreads);

	for (i = 0; i < nthreads; ++i) {
		pthread_t *tid = new pthread_t;
		pthread_create(tid, NULL, try_pubkey, &td);
		tids[i] = tid;
	}
	for (i = 0; i < nthreads; ++i) {
		pthread_join(*tids[i], NULL);
		delete tids[i];
	}

	return 0;
}


unsigned int last_ip = 0;
pthread_mutex_t last_ip_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t cout_lock = PTHREAD_MUTEX_INITIALIZER;


void *try_pubkey(void *vp)
{
	thread_data *td = (thread_data*)vp;
	char host[128];
	struct in_addr in;
	int fd = -1, r = 0;

	while (1) {
		SSH2 ssh;	// need it here, so it is constructed
				// in every loop cycle
		pthread_mutex_lock(&last_ip_lock);
		last_ip = next_ip(range, last_ip);
		pthread_mutex_unlock(&last_ip_lock);

		if (last_ip == -1)
			break;
		if ((last_ip & 0xff000000) == 0xff000000 ||
		    (last_ip & 0xff000000) == 0)
			continue;

		memcpy(&in.s_addr, &last_ip, 4);
		if (inet_ntop(AF_INET, &in, host, sizeof(host)) < 0)
			continue;

		close(fd);
		if ((fd = tcp_connect(host, td->port)) < 0) {
			if (errno != ECONNREFUSED && errno != EINPROGRESS) {
				cerr<<"Host "<<host<<" dead ("<<strerror(errno)<<")\n";
			}
			continue;
		}

		ssh.set_socket(fd);
		if (ssh.banner_exchange() < 0) {
		//	cerr<<ssh.why()<<endl;
			continue;
		}

		if (ssh.kex_init() < 0) {
			cerr<<ssh.why()<<endl;
			continue;
		}
		if (ssh.dh_exchange() < 0) {
			cerr<<ssh.why()<<endl;
			continue;
		}
		if (ssh.newkeys() < 0) {
			cerr<<ssh.why()<<endl;
			continue;
		}

		// Uha! An undocumented feature. Scanning for
		// login/passwd ;-)
		if (td->passwd)
			r=ssh.userauth_passwd(td->login.c_str(),
		                              td->keyfile.c_str());
		else
			r=ssh.userauth_pubkey(td->login.c_str(),
			                      td->keyfile.c_str());
		if (r < 0) {
			cerr<<ssh.why()<<endl;
			break;
		}
		pthread_mutex_lock(&cout_lock);
		cout<<host<<": "<<ssh.banner()<<" ";
		if (r == 0)
			cout<<"Yes\n";
		else
			cout<<"No\n";
		pthread_mutex_unlock(&cout_lock);
	
		close(fd);
	}

	return NULL;
}

