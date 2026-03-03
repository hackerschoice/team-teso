/* SSHARP SSH 1&2 MiM implemenation (C) 2001 Stealth <stealth@segfault.net>
 *
 * TESO confidential.
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <assert.h>

#include "ssharp.h"
#include "auth.h"


int socket_connect_b(struct sockaddr *s, socklen_t len, u_short minport)
{
	int one = 1, i = 0, fd, fa;
	struct sockaddr_in local4;
	struct sockaddr_in6 local6;
	struct sockaddr *sa;

	memset(&local4, 0, sizeof(local4));
	local4.sin_family = AF_INET;

	memset(&local6, 0, sizeof(local6));
	local6.sin6_family = AF_INET6;

	if (len == sizeof(struct sockaddr_in6)) {
		sa = (struct sockaddr*)&local6;
		fa = PF_INET6;
	} else {
		sa = (struct sockaddr*)&local4;
		fa = PF_INET;
	}

	for (i = minport; i < 65500; ++i) {
		local4.sin_port = htons(i);
		local6.sin6_port = htons(i);

		fd = socket(fa, SOCK_STREAM, 0);
		if (fd < 0)
			return -1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	
		if (bind(fd, sa, len) < 0) {
			if (errno == EADDRINUSE) {
				close(fd);
				continue;
			} else
				return -1;
		}
		if (connect(fd, s, len) < 0) {
			if (errno == EADDRNOTAVAIL) {
				close(fd);
				continue;
			} else
				return -1;
		}

		break;
	}
	return fd;
}


int writen(int fd, const void *buf, size_t len)
{
	int o = 0, n;

	while (len > 0) {
		if ((n = write(fd, buf+o, len)) < 0)
			return n;
		len -= n;
		o += n;
	}
	return o;
}


int readn(int fd, char *buf, size_t len)
{
	int i = 0;
	while (len > 0) {
		if (read(fd, &buf[i], 1) < 0) {
			return -1;
		}
		++i;
		--len;
	}
	return i;
}

sharp_t sharp_dup(sharp_t *s)
{
	sharp_t ret;

	memset(&ret, 0, sizeof(ret));

	if (s->login)
		ret.login = strdup(s->login);
	if (s->pass)
		ret.pass  = strdup(s->pass);
	if (s->remote)
		ret.remote = strdup(s->remote);

	ret.remote_port = s->remote_port;
	return ret;
}

#ifdef FREEBSD
#define LINUX22
#endif

// obtain real destination of connection
int dstaddr(int sock, struct sockaddr_in *dst)
{
	socklen_t size;

	assert(dst);

#ifdef LINUX22
	size = sizeof(struct sockaddr_in);
	if (getsockname(sock, (struct sockaddr*)dst, &size) < 0) {
		perror("getsockname");
		exit(errno);
	}
#elif defined(LINUX24)
#include "netfilter.h"
	size = sizeof(struct sockaddr_in);
	if (getsockopt(sock, SOL_IP, SO_ORIGINAL_DST, dst, &size) < 0) {
		perror("getsockopt");
		exit(errno);
	}
#else
#error "Not supported on this OS yet."
#endif
	return 0;
}

Authctxt *auth_dup(Authctxt *a)
{
	Authctxt *ret = (Authctxt*)malloc(sizeof(*a));

	if (!a || !ret) {
		free(ret);
		return NULL;
	}

	*ret = *a;
	if (a->user)
		ret->user = strdup(a->user);
	if (a->service)
		ret->service = strdup(a->service);
	if (a->style)
		ret->style = strdup(a->style);
	ret->sharp = sharp_dup(&a->sharp);

	return ret;
}

