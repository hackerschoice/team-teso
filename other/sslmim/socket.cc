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
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <string>
#include <errno.h>

#include "socket.h"

namespace NS_Socket {

string error;

const char *why()
{
	return error.c_str();
}

// disable Mr. Nagle's algorithm
int nodelay(int sock)
{
	int one = 1;
	socklen_t len = sizeof(one);

	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, len) < 0) {
		error = "NS_Socket::nodelay::setsockopt: ";
		error += strerror(errno);
		return -1;
	}

	return 0;
}

// make socket ready for port-reuse
int reuse(int sock)
{
	int one = 1;
	socklen_t len = sizeof(one);

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, len) < 0) {
		error = "NS_Socket::reuse::setsockopt: ";
		error += strerror(errno);
		return -1;
	}

	return 0;
}

#ifdef FREEBSD
#define LINUX22
#endif

// obtain real destination of connection
int dstaddr(int sock, sockaddr_in *dst)
{
	if (!dst) {
		error = "NS_Socket::dstaddr: dst == NULL";
		return -1;
	}

#ifdef LINUX22
	socklen_t size = sizeof(sockaddr_in);
	if (getsockname(sock, (struct sockaddr*)dst, &size) < 0) {
		error = "NS_Socket::dstaddr::getsockname: ";
		error += strerror(errno);
		return -1;
	}
#elif defined(LINUX24)
#include <linux/netfilter_ipv4.h>
	socklen_t size = sizeof(sockaddr_in);
	if (getsockopt(sock, SOL_IP, SO_ORIGINAL_DST, dst, &size) < 0) {
		error = "NS_Socket::dstaddr::getsockopt: ";
		error += strerror(errno);
		return -1;
	}
#else
#error "Not supported on this OS yet."
#endif
	return 0;
}

int bind_local(int sock, int port, bool do_listen)
{
	struct sockaddr_in saddr;

	memset(&saddr, 0, sizeof(saddr));

	saddr.sin_port = htons(port);
	saddr.sin_family = AF_INET;

	if (reuse(sock) < 0)
		return -1;

	if (bind(sock, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) {
		error = "NS_Socket::bind_local::bind: ";
		error += strerror(errno);
		return -1;
	}

	if (do_listen) {
		if (listen(sock, SOMAXCONN) < 0) {
			error = "NS_Socket::bind_local::listen: ";
			error += strerror(errno);
			return -1;
		}
	}
	return 0;
}


}; // namespace
