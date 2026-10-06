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
#ifndef __FreeBSD__
#error "Works on FreeBSD only"
#endif

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <list.h>
#include "structs.h"

bool reverse = false;
bool nopush = false;

using namespace mystructs;

struct frag {
        char *buf;
        short len;
};

list<frag*> &do_frag(list<frag*> &, char *, size_t, iphdr *, size_t);

extern unsigned short in_cksum(unsigned short*, int);

// n -> offset in 8-tupel, n+1 -> length in bytes
// -1 == end, -2 == rest of length
int offsets[] = {0, 24, 3, -2, -1};

// for frag function to check whether packet is long
// enough
const size_t maxoff = 3;

void die(char *s)
{
	perror(s);
	exit(errno);
}

// overload '<<' to print IP-adress pair
ostream &operator<<(ostream &os, iphdr &ip)
{
        printf("[%d.%d.%d.%d -> %d.%d.%d.%d]",
                ip.saddr&0xff,(ip.saddr>>8)&0xff, (ip.saddr>>16)&0xff, (ip.saddr>>24)&0xff,
                ip.daddr&0xff,(ip.daddr>>8)&0xff, (ip.daddr>>16)&0xff, (ip.daddr>>24)&0xff);
        return os;
}

// open divert socket and bind to divert port
int open_socket(unsigned short port)
{
	int fd = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT);

	if (fd < 0)
		die("socket");	

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_port = htons(port);
	sin.sin_family = AF_INET;

	if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0)
		die("bind");

	return fd;
}


int capture_frag_send(int sfd)
{	
	struct sockaddr_in saddr;	
	size_t pkt_len;
	char buf[4096];
	list<frag*> frags;
	iphdr *ip;
	int r, ihl;
	socklen_t slen = sizeof(saddr);

	for (;;) {
		r = recvfrom(sfd, buf, sizeof(buf), 0, 
			     (sockaddr*)&saddr, &slen);
		ip = (iphdr*)buf;

		// XXX: check for frags
		pkt_len = ntohs(ip->tot_len);		
		ihl = (ip->ihl<<2);

		//cout<<*ip<<endl;
		do_frag(frags, &buf[ihl], pkt_len - ihl, ip, ihl);

		if (reverse)
			frags.reverse();
		//sendto(sfd, buf,pkt_len,0,(sockaddr*)&saddr,slen);

		for (list<frag*>::iterator it = frags.begin(); 
		     it != frags.end();) {
			sendto(sfd, (*it)->buf, (*it)->len, 0,
			       (sockaddr*)&saddr, slen);
			delete [] (*it)->buf;
			it = frags.erase(it);
			cout<<".";
		}
	}
	/* NOT REACHED */
	return 0;
}

// Split up IP packet into fragments
// insert 'em into a list, so they can be send by caller
// buflen is length of data appearing after IPhdr
list<frag*> &do_frag(list<frag*> &v, char *buf, size_t buflen, iphdr *ip, size_t iplen)
{
	srand(time(NULL));
	u_int16_t id = 1 + (u_int16_t)(65000*rand()/RAND_MAX+1.0);
		
	char *d = NULL;
	iphdr *iph = NULL;
	tcphdr *tcph = NULL;
	
	// Can't be fragmented when offset points behind packet
	if (8*maxoff >= buflen) {
		d = new char[buflen+iplen];
		memcpy(d, ip, iplen);
		memcpy(d + iplen, buf, buflen);
		frag *f = new frag;
		f->buf = d;
		f->len = buflen + iplen;
		v.push_back(f);
		return v;
	}
	
	int flag = 0, fraglen;
	for (int i = 0; offsets[i] != -1; i += 2) {
		d = new char[buflen+iplen];
		memcpy(d, ip, iplen);
		
		iph = (iphdr*)d;
		iph->id = id;
		flag = (offsets[i+2] == -1 ? 0 : IP_MF);
		
		// We've been asked to remove PUSH flag.
		// Do so and recalculate TCP-checksum
		if (nopush && (iph->protocol == IPPROTO_TCP)) {
			tcph = (tcphdr*)buf;
			if (tcph->th_flags&TH_PUSH != TH_PUSH)
				goto out_of_here;	// sorry
				
			tcph->th_flags &= ~TH_PUSH;
			tcph->th_sum = 0;

			// build psuedo-hdr
			pseudohdr ph = {
				iph->saddr, 
				iph->daddr, 0, 
				IPPROTO_TCP, 
				htons(buflen)
			};
			int x = buflen+sizeof(ph);
			char *tmp = new char [x+1];	// +1 for cksum padding
			memset(tmp, 0, x+1);

			// pseudohdr, tcphdr, payload
			memcpy(tmp, &ph, sizeof(ph));
			memcpy(tmp+sizeof(ph), buf, buflen);
			
			tcph = (tcphdr*)(tmp+sizeof(ph));
			tcph->th_sum = in_cksum((unsigned short*)tmp, x);
			memcpy(buf, tmp + sizeof(ph), buflen);
			delete [] tmp;
		}
		out_of_here:

		fraglen = offsets[i+1] != -2 ?
			  offsets[i+1] : buflen-8*offsets[i];
	
//#ifdef __FreeBSD__
//		iph->frag_off = offsets[i]|flag;
//		iph->tot_len  = iplen + fraglen;
//#else
		iph->frag_off = htons(offsets[i]|flag);
		iph->tot_len  = htons(iplen + fraglen);
//#endif
		iph->check = 0;
			
		memcpy(d + iplen, buf + 8*offsets[i], fraglen);

		frag *f = new frag;
		f->buf = d;
		f->len = fraglen + iplen;
		v.push_back(f);
	}
	return v;
}

void usage(char *s)
{
	cout<<"usage: "<<s<<" [-P] [-R] [-p divert-port]\n"
	    <<"  -P -- to remove PUSH flag from TCP-hdr\n"
	    <<"  -R -- to reverse send fragments\n\n";
	exit(1);
}

int main(int argc, char **argv)
{
	unsigned short port = 8888;
	int c;

	while ((c = getopt(argc, argv, "RPp:")) != -1) {
		switch (c) {
		case 'R':
			reverse = true;
			break;
		case 'P':
			nopush = true;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		default:
			usage(*argv);
			// NOT REACHED
		}
	}
	int socket = open_socket(port);
	capture_frag_send(socket);

	// NOT REACHED
	return 0;
}
	
