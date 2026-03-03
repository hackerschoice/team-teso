
/* scut's leet network library ;)
 * 1999 (c) scut
 *
 * networking routines
 * based on my hbot networking sources,
 * revised, extended and adapted 990405
 * extended, improved and fixed 990430
 * ripped down to minimal functionality for reverb 990803
 *
 * for the full version of this library just contact me, i'd be glad to send
 * them to you :)
 *
 * nearly all of this code wouldn't have been possible without w. richard stevens
 * excellent network coding book. if you are interested in network coding,
 * there is no way around it.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "network.h"

int	net_readtimeout = NET_READTIMEOUT;
int	net_conntimeout = NET_CONNTIMEOUT;


int
net_parseip (char *inp, char **ip, unsigned short int *port)
{
	int	n;

	if (inp == NULL)
		return (0);
	if (strchr (inp, ':') == NULL)
		return (0);

	*ip = calloc (1, 256);
	if (*ip == NULL)
		return (0);

	n = sscanf (inp, "%[^:]:%hu", *ip, port);
	if (n != 2)
		return (0);

	*ip = realloc (*ip, strlen (*ip) + 1);
	if (*ip == NULL || (*port < 1 || *port > 65535))
		return (0);

	return (1);
}


int
net_accept (int s, struct sockaddr_in *cs, int maxsec)
{
	int		flags, n;
	fd_set		ac_s;
	int		len;
	struct timeval	tval;

	flags = fcntl(s, F_GETFL, 0);
	if (flags == -1)
		return (-1);
	n = fcntl(s, F_SETFL, flags | O_NONBLOCK);
	if (flags == -1)
		return (-1);

	FD_ZERO(&ac_s);
	FD_SET(s, &ac_s);
	tval.tv_sec = maxsec;
	tval.tv_usec = 0;

	n = select(s + 1, &ac_s, NULL, NULL, maxsec ? &tval : NULL);
	if (n == 0)
		return (0);

	if (FD_ISSET(s, &ac_s)) {
		len = sizeof(struct sockaddr_in);
		n = accept(s, (struct sockaddr *) cs, &len);
		if (n == -1) {
			switch (errno) {
			case EWOULDBLOCK:
			case ECONNABORTED:
			case EPROTO:
			case EINTR:	if (fcntl(s, F_SETFL, flags) == -1)
						return (-1);
					return (0);
			default:	return (-1);
			}
		}
		if (fcntl(s, F_SETFL, flags) == -1)
			return (-1);
		return (n);
	}
	if (fcntl(s, F_SETFL, flags) == -1)
		return (-1);
	return (0);
}


void
net_boundfree (bound *bf)
{
	close (bf->bs);
	free(bf);
	return;
}


bound *
net_bind (char *ip, unsigned short int port)
{
	bound			*b;
	int			br, gsnr, lr;
	int			len, reusetmp;
	struct sockaddr_in	*sap;

	if (port >= 65536)
		return (NULL);

	b = calloc(1, sizeof (bound));
	if (b == NULL)
		return (NULL);
	b->bs = socket (AF_INET, SOCK_STREAM, 0);
	if (b->bs == -1)
		goto berror;

	reusetmp = 1;
#ifdef SO_REUSEPORT
	if (setsockopt (b->bs, SOL_SOCKET, SO_REUSEPORT, &reusetmp, sizeof (reusetmp)) == -1)
		goto berror;
#else
	if (setsockopt (b->bs, SOL_SOCKET, SO_REUSEADDR, &reusetmp, sizeof (reusetmp)) == -1)
		goto berror;
#endif

	sap = (struct sockaddr_in *) &b->bsa;
	sap->sin_family = AF_INET;
	sap->sin_port = htons (port);		/* 0 = ephemeral */

	if (ip != NULL) {
		if (strcmp (ip, "*") == 0) {
			sap->sin_addr.s_addr = htonl (INADDR_ANY);
		} else {
			if (!(sap->sin_addr.s_addr = net_resolve (ip))) {
				goto berror;
			}
		}
	} else {
		sap->sin_addr.s_addr = htonl (INADDR_ANY);
	}

	br = bind (b->bs, (struct sockaddr *) &b->bsa, sizeof (struct sockaddr));
	if (br == -1)
		goto berror;

	len = sizeof (struct sockaddr);
	gsnr = getsockname (b->bs, (struct sockaddr *) &b->bsa, &len);
	b->port = ntohs (sap->sin_port);
	if (gsnr == -1)
		goto berror;

	lr = listen (b->bs, 16);
	if (lr == -1) {
		goto berror;
	}
	return (b);

berror:
	free(b);

	return(NULL);
}


unsigned long int
net_resolve (char *host)
{
	long		i;
	struct hostent	*he;

	i = inet_addr(host);
	if (i == -1) {
		he = gethostbyname(host);
		if (he == NULL) {
			return (0);
		} else {
			return (*(unsigned long *) he->h_addr);
		}
	}
	return (i);
}


int
net_connect (struct sockaddr_in *cs, char *server, unsigned short int port, int sec)
{
	int		n, len, error, flags;
	int		fd;
	struct timeval	tv;
	fd_set		rset, wset;

	/* first allocate a socket */
	cs->sin_family = AF_INET;
	cs->sin_port = htons (port);
	fd = socket (cs->sin_family, SOCK_STREAM, 0);
	if (fd == -1)
		return (-1);

	if (!(cs->sin_addr.s_addr = net_resolve (server))) {
		close (fd);
		return (-1);
	}

	flags = fcntl (fd, F_GETFL, 0);
	if (flags == -1) {
		close (fd);
		return (-1);
	}
	n = fcntl (fd, F_SETFL, flags | O_NONBLOCK);
	if (n == -1) {
		close (fd);
		return (-1);
	}

	error = 0;

	n = connect (fd, (struct sockaddr *) cs, sizeof (struct sockaddr_in));
	if (n < 0) {
		if (errno != EINPROGRESS) {
			close (fd);
			return (-1);
		}
	}
	if (n == 0)
		goto done;

	FD_ZERO(&rset);
	FD_ZERO(&wset);
	FD_SET(fd, &rset);
	FD_SET(fd, &wset);
	tv.tv_sec = sec;
	tv.tv_usec = 0;

	n = select(fd + 1, &rset, &wset, NULL, &tv);
	if (n == 0) {
		close(fd);
		errno = ETIMEDOUT;
		return (-1);
	}
	if (n == -1)
		return (-1);

	if (FD_ISSET(fd, &rset) || FD_ISSET(fd, &wset)) {
		if (FD_ISSET(fd, &rset) && FD_ISSET(fd, &wset)) {
			len = sizeof(error);
			if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
				errno = ETIMEDOUT;
				return (-1);
			}
			if (error == 0) {
				goto done;
			} else {
				errno = error;
				return (-1);
			}
		}
	} else
		return (-1);

done:
	n = fcntl(fd, F_SETFL, flags);
	if (n == -1)
		return (-1);
	return (fd);
}


int
net_tline (char *buf, int bufsize)
{
	int	p;

	for (p = 0; p < bufsize; p++) {
		if (buf[p] == '\n')
			return (p + 1);
	}
	return (-1);
}


int
net_rlinet (int fd, char *buf, int bufsize, int sec)
{
	int			n;
	unsigned long int	rb = 0;
	struct timeval		tv_start, tv_cur;

	memset(buf, '\0', bufsize);
	(void) gettimeofday(&tv_start, NULL);

	do {
		(void) gettimeofday(&tv_cur, NULL);
		if (sec > 0) {
			if ((((tv_cur.tv_sec * 1000000) + (tv_cur.tv_usec)) -
				((tv_start.tv_sec * 1000000) + (tv_start.tv_usec))) > (sec * 1000000)) {
				return (-1);
			}
		}
		n = net_rtimeout(fd, net_readtimeout);
		if (n <= 0) {
			return (-1);
		}
		n = read(fd, buf, 1);
		if (n <= 0) {
			return (n);
		}
		rb++;
		if (*buf == '\n')
			return (rb);
		buf++;
		if (rb >= bufsize)
			return (-1);
	} while (1);
}


long int
net_rbuf (int fd, char **dst)
{
	long int	ml = 0;
	long int	read_bytes;
	int		p;

	while ((p = net_rtimeout(fd, net_readtimeout)) == 1) {
		*dst = (char *) realloc(*dst, ml + NET_BSIZE);
		if (*dst == NULL)
			return (-1);
		ml += read_bytes = read(fd, *dst + ml, NET_BSIZE);
		if (read_bytes == 0) {
			*dst = (char *) realloc(*dst, ml);
			if ((*dst == NULL) && (ml == 0)) {
				return (1);
			} else if (*dst == NULL) {
				return (-1);
			} else {
				return (ml);
			}
		}
	}
	return (-1);
}


int
net_rbuft (int fd, char *dst, unsigned long int dsize)
{
	unsigned long int	bl = 0, m;
	int			p;

	while (bl < dsize) {
		p = net_rtimeout(fd, net_readtimeout);
		if ((p == 0) || (p == -1)) {
			return (-1);
		}

		m = read(fd, dst + bl, (dsize - bl));
		if ((m == 0) || (m == -1)) {
			return (-1);
		}
		bl += m;
	}
	return (1);
}


int
net_rtimeout (int fd, int sec)
{
	fd_set		rset;
	struct timeval	tv;
	int		n, error, flags;

	error = 0;
	flags = fcntl(fd, F_GETFL, 0);
	n = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (n == -1)
		return (-1);

	FD_ZERO(&rset);
	FD_SET(fd, &rset);
	tv.tv_sec = sec;
	tv.tv_usec = 0;

	/* now we wait until more data is received then the tcp low level watermark,
	 * which should be setted to 1 in this case (1 is default)
	 */

	n = select(fd + 1, &rset, NULL, NULL, &tv);
	if (n == 0) {
		n = fcntl(fd, F_SETFL, flags);
		if (n == -1)
			return (-1);
		errno = ETIMEDOUT;
		return (-1);
	}
	if (n == -1) {
		return (-1);
	}
	/* socket readable ? */
	if (FD_ISSET(fd, &rset)) {
		n = fcntl(fd, F_SETFL, flags);
		if (n == -1)
			return (-1);
		return (1);
	} else {
		n = fcntl(fd, F_SETFL, flags);
		if (n == -1)
			return (-1);
		errno = ETIMEDOUT;
		return (-1);
	}
}


void
net_write (int fd, const char *str, ...)
{
	char	tmp[1025];
	va_list	vl;
	int	i;

	va_start(vl, str);
	memset(tmp, 0, sizeof(tmp));
	i = vsnprintf(tmp, sizeof(tmp), str, vl);
	va_end(vl);

#ifdef DEBUG
	printf("[snd] %s\n", tmp);
#endif

	send(fd, tmp, i, 0);
	return;
}

