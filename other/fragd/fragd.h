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
#ifndef _FRAGD_H_
#define _FRAGD_H_

extern "C" {
#include <pcap.h>
}
#include <list.h>
#include <stdio.h>
#include "structs.h"

using namespace mystructs;

struct per_thread {
	pcap_t *pd;
	int sfd, skipcount;
};

struct frag {
	char *buf;
	short len;
};

int open_socket();

pcap_t *open_cap(char *, int *, char *);

void *capture_frag_send(void *);
void *capture_send(void *);

list<frag*> &do_frag(list<frag*> &, char *, size_t, iphdr *, size_t);

#endif

