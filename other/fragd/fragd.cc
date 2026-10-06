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
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "structs.h"
#include "fragd.h"
extern "C" {
#include <pcap.h>
}
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <list.h>

using namespace mystructs;

bool reverse = false;
bool nopush = false;

// n -> offset in 8-tupel, n+1 -> length in bytes
// -1 == end, -2 == rest of length
int offsets[] = {0, 16, 2, -2, -1};

// for frag function to check whether packet is long
// enough
const size_t maxoff = 2;

extern unsigned short in_cksum(unsigned short*, int);

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

// open RAW socket and set it up
int open_socket()
{
	int fd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);

	if (fd < 0)
		die("socket");	

	int one = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
		die("setsockopt");
	return fd;
}

// initialize packet capturer
pcap_t *open_cap(char *dev, int *framelen, char *filter)
{
	pcap_t *pd;
	char ebuf[PCAP_ERRBUF_SIZE];
	u_int32_t netmask, localnet;
	bpf_program f; int datalink;
	
	memset(ebuf, 0, sizeof(ebuf));
	pd = pcap_open_live(dev, 65000, 0, -1, ebuf);
	if (!pd)
		die(ebuf);
	if (pcap_lookupnet(dev, &localnet, &netmask, ebuf) < 0)
		die(ebuf);
	
	// construct real filter: We only want packets on a device which
	// come from the corresponding local net. This drops packets for the
	// 'just cap+send' thread which we just wrote to that device
	char real_filter[1000];
	memset(real_filter, 0, sizeof(real_filter));
	snprintf(real_filter, sizeof(real_filter)-1, 
		"(%s) and (src net %d.%d.%d.%d mask %d.%d.%d.%d)",
		filter, localnet&0xff,(localnet>>8)&0xff,(localnet>>16)&0xff,(localnet>>24)&0xff,
			netmask&0xff,(netmask>>8)&0xff,(netmask>>16)&0xff,(netmask>>24)&0xff);

	cout<<real_filter<<endl;	
	if (pcap_compile(pd, &f, real_filter, 1, netmask) < 0)
		die("pcap_compile");
	if (pcap_setfilter(pd, &f) < 0)
		die("pcap_setfilter");
	
	if ((datalink = pcap_datalink(pd)) < 0)
                die("pcap_datalink");


        // turn datalink into framelen
        switch (datalink) {
        case DLT_EN10MB:
                *framelen = 14;
                break;
        case DLT_PPP:
                *framelen = 4;
                break;
        case DLT_PPP_BSDOS:
                *framelen = 24;
                break;
        case DLT_SLIP:
                *framelen = 24;
                break;
        case DLT_RAW:
                *framelen = 0;
                break;
        // loopback
        case DLT_NULL:
                *framelen = 0;
                break;
        default:
                die("unknown datalink");
        }

	
	return pd; 
}

#ifndef IP_NOP
#define IP_NOP 1
#endif

// Pad an IP-datagram with as much NOPs as possible
// len == complete len including header+payload
char *pad_with_nops(iphdr *ip, size_t *len)
{
	int hlen = ip->ihl<<2;

	char *r = new char[60+*len-hlen];	// space for max. IPhdr and payload

	memcpy(r, ip, hlen);
	for (int i = hlen; i < 60; ++i)
		r[i] = IP_NOP;
	memcpy(&r[60], (char*)ip + hlen, *len - hlen);
	*len = 60 + *len - hlen;
	((iphdr*)r)->ihl = 0xf;		// update headerlength field
	return r;
}

void *capture_send(void *v)
{	
	per_thread *dispatch = (per_thread*)v;
	int pkt_fd = pcap_fileno(dispatch->pd), r;
	struct sockaddr_in saddr;
	
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(0);
	
	int skipcount = dispatch->skipcount;
	size_t pkt_len;
	char buf[4096];
	iphdr *ip;

	while (1) {
		r = read(pkt_fd, buf, sizeof(buf));
		
		ip = (iphdr*)(buf + skipcount);		
		// XXX: checkfor frags
		pkt_len = ntohs(ip->tot_len);
		
		saddr.sin_addr.s_addr = ip->daddr;
		
		sendto(dispatch->sfd, buf+skipcount, pkt_len, 0,
			       (sockaddr*)&saddr, sizeof(saddr));
	}
	/* NOT REACHED */
	return NULL;
}


void *capture_frag_send(void *v)
{	
	per_thread *dispatch = (per_thread*)v;
	int pkt_fd = pcap_fileno(dispatch->pd), r;
	struct sockaddr_in saddr;
	
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(0);
	
	int skipcount = dispatch->skipcount, ihl;
	size_t pkt_len;
	char buf[4096], *pkt_to_send;
	list<frag*> frags;
	iphdr *ip;
	
	for (;;) {
		r = read(pkt_fd, buf, sizeof(buf));
		ip = (iphdr*)(buf + skipcount);

		// XXX: checkfor frags
		pkt_len = ntohs(ip->tot_len);
		
		if (1)
			pkt_to_send = pad_with_nops(ip, &pkt_len);
		else {
			pkt_to_send = new char[pkt_len];
			memcpy(pkt_to_send, ip, pkt_len);
		}
		
		ip = (iphdr*)pkt_to_send;
		ihl = ip->ihl<<2;
		saddr.sin_addr.s_addr = ip->daddr;
		
		do_frag(frags, pkt_to_send + ihl, pkt_len - ihl, ip, ihl);
		
		delete [] pkt_to_send;		

		if (reverse)
			frags.reverse();
		cout<<*ip<<" ";
		for (list<frag*>::iterator it = frags.begin(); 
		     it != frags.end();) {
			sendto(dispatch->sfd, (*it)->buf, (*it)->len, 0,
			       (sockaddr*)&saddr, sizeof(saddr));
			delete [] (*it)->buf;
			it = frags.erase(it);
			cout<<".";
		}			
		cout<<endl;
	}
	/* NOT REACHED */
	return NULL;
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

#ifdef __FreeBSD__
		iph->frag_off = offsets[i]|flag;
#else
		iph->frag_off = htons(offsets[i]|flag);
#endif
		iph->check = 0;
			
		fraglen = offsets[i+1] != -2 ?
			  offsets[i+1] : buflen-8*offsets[i];
			  
		memcpy(d + iplen, buf + 8*offsets[i], fraglen);

		frag *f = new frag;
		f->buf = d;
		f->len = fraglen + iplen;
		v.push_back(f);
	}
	return v;
}
