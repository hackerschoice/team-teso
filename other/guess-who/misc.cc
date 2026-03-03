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
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/time.h>


void die(const char *s)
{
	perror(s);
	exit(errno);
}


int writen(int fd, const void *buf, size_t len)
{
	int o = 0, n;
	char *ptr = (char*)buf;

	while (len > 0) {
		if ((n = write(fd, ptr+o, len)) < 0)
			return n;
		len -= n;
		o += n;
	}
	return o;
}


/* Simple tcp_connect(). Disables Nagle.
 */
int tcp_connect(const char *host, u_short port = 22)
{
	int sock, one = 1, len = sizeof(one), r;
	char service[20];
	struct addrinfo *res, hints = {0, PF_INET, SOCK_STREAM, 0};

	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
		die("sock");

	sprintf(service, "%d", port);
	if ((r = getaddrinfo(host, service, &hints, &res)) != 0) {
		fprintf(stderr, "tcp_connect::getaddrinfo: %s\n", gai_strerror(r));
		exit(EXIT_FAILURE);
	}
#ifdef DONT_BLOCK
	int f = fcntl(sock, F_GETFL);
	f |= O_NONBLOCK;
	if (fcntl(sock, F_SETFL, f) < 0)
		die("fcntl");
#endif
	if (connect(sock, res->ai_addr, res->ai_addrlen) < 0 &&
	    errno != EINPROGRESS)
		return -1;
#ifdef DONT_BLOCK
	struct timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	fd_set rset;
	FD_ZERO(&rset); FD_SET(sock, &rset);
	if (select(sock+1, &rset, &rset, NULL, &tv) <= 0) {
		close(sock);
		return -1;
	}

	// fetch pending error
	int pe = 0; size_t pe_len = sizeof(pe);
	if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &pe, &pe_len) < 0)
		die("getsockopt");
	if (pe != 0) {
		errno = pe;
		close(sock);
		return -1;
	}
		
	if (fcntl(sock, F_SETFL, f&~O_NONBLOCK) < 0)
		die("fcntl");
#endif
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, len) < 0)
		die("setsockopt");

	freeaddrinfo(res);
	return sock;
}

void buffer_dump(const char *desc, unsigned char *buffer, size_t blen)
{
	unsigned int i;

	printf("%s=\n", desc);
	for (i = 0; i < blen; i++) {
		printf("%02x", buffer[i]);
		if (i%16==15)
			printf("\r\n");
		else if (i%2==1)
			printf(" ");
	}
	printf("\r\n");
}


/* accept "1.2.3.4" or "1.2.3.4-5.6.7.8".
 * use old := 0 to get first address, and pass
 * return value in subsequent calls as 'old'.
 * returns 0 when no more adresses.
 */
int next_ip(char *addr, unsigned long old)
{
	char *ptr;
	unsigned long ip, eip, sip;

	assert(addr);

	if (old == 0xffffffff)
		return -1;

	if ((ptr = strchr(addr, '-')) != NULL) {
        	*ptr++ = 0;
        	eip = inet_addr(ptr);
		sip = inet_addr(addr);
		ptr[-1] = '-';
    	} else {
        	eip = inet_addr(addr);
		if (eip == old)
			return -1;
		return eip;
    	}

	if (old == 0)
		return sip;
	if (ntohl(old)+1 > ntohl(eip))
		return -1;
	
	ip = htonl(ntohl(old)+1);
    	return ip;
}


