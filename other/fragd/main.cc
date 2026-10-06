/*
 * Copyright (C) 1999/2000 Sebastian Krahmer.
 * All rights reserved.
 *
 * THIS IS NOT OPEN SOURCE, SO READ ON.
 *
 * Redistribution in source and binary forms, with or without
 * modification, are NOT permitted.
 *
 * Use of this software is permitted provided that the following conditions
 * are met:
 *
 * 1. You may not use this software to cause damage or any other illegal
 *    activities. It is for educational purpose only. You may not use this
 *    software for commercial purposes.
 * 2. You may change the sourcode to meet your needs. You are not allowed
 *    to change this copyright notice.
 * 3. This is private sourcecode, you should have received this file only
 *    from the author itself.
 * 4. The author may change the above copyright at any time. He may even publish
 *    this code without notify you first. 
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
#include <iostream>
#include <unistd.h>
extern "C" {
#include <pcap.h>
}
#include <pthread.h>
#include <string.h>
#include "fragd.h"

extern bool reverse;
extern bool nopush;

void usage(char *path)
{
	printf("\n%s: [-I input dev1] [-O input dev2] [-p filter] [-rP]\n"
	       "    -r -- send frags in reverse order\n"
	       "    -I -- input dev for capturing where datagrams are fragmented, default eth0\n"
	       "    -O -- input dev for capturing where datagrams are just written to socket, default ppp0\n"
	       "    -P -- No-PUSH. Eats IDS with content triggering (TCP!).\n"
	       "    -p -- datagrams to capture, default \"tcp\"\n\n", path);
	exit(1);
}

int main(int argc, char **argv)
{
	pthread_t thread1, thread2;

	per_thread *t1 = new per_thread;
	per_thread *t2 = new per_thread;
	
	int c = 0;
	char in_dev[10] = "eth0", out_dev[10] = "ppp0", proto[100] = "tcp";
		
	while ((c = getopt(argc, argv, "I:O:p:rP")) != -1) {
		switch (c) {
		case 'I':
			strncpy(in_dev, optarg, sizeof(in_dev)-1);
			break;
		case 'O':
			strncpy(out_dev, optarg, sizeof(out_dev)-1);
			break;
		case 'p':
			strncpy(proto, optarg, sizeof(proto)-1);
			break;
		case 'r':
			reverse = true;
			break;
		case 'P':
			nopush = true;
			break;
		default:
			usage(*argv);
		}
	}

	t1->pd = open_cap(in_dev, &t1->skipcount, proto);
	t2->pd = open_cap(out_dev, &t2->skipcount, proto);
	
	t1->sfd = open_socket();
	t2->sfd = open_socket();
	
	pthread_create(&thread1, NULL, capture_frag_send, t1);
	
	pthread_create(&thread2, NULL, capture_send, t2);

	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);
	return 0;
}

