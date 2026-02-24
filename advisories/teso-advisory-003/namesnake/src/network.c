/* namesnake
 *
 * network primitives
 *
 * by scut
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
#include "common.h"
#include "network.h"


int
net_connect (struct sockaddr_in *cs, char *server, unsigned short int port,
	int sec)
{
	int			n, len, error, flags;
	int			fd;
	struct timeval		tv;
	struct sockaddr_in	tmp_cs;
	fd_set			rset, wset;


	if (cs == NULL)
		cs = &tmp_cs;

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

	FD_ZERO (&rset);
	FD_ZERO (&wset);
	FD_SET (fd, &rset);
	FD_SET (fd, &wset);
	tv.tv_sec = sec;
	tv.tv_usec = 0;

	n = select (fd + 1, &rset, &wset, NULL, &tv);
	if (n == 0) {
		close (fd);
		errno = ETIMEDOUT;

		return (-1);
	}
	if (n == -1)
		return (-1);

	if (FD_ISSET (fd, &rset) || FD_ISSET (fd, &wset)) {
		if (FD_ISSET (fd, &rset) && FD_ISSET (fd, &wset)) {
			len = sizeof (error);
			if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
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
	n = fcntl (fd, F_SETFL, flags);
	if (n == -1)
		return (-1);
	return (fd);
}


int
net_accept (int s, struct sockaddr_in *cs, int maxsec)
{
	int		flags, n;
	fd_set		ac_s;
	int		len;
	struct timeval	tval;

	flags = fcntl (s, F_GETFL, 0);
	if (flags == -1)
		return (-1);
	n = fcntl (s, F_SETFL, flags | O_NONBLOCK);
	if (flags == -1)
		return (-1);

	FD_ZERO (&ac_s);
	FD_SET (s, &ac_s);
	tval.tv_sec = maxsec;
	tval.tv_usec = 0;

	n = select (s + 1, &ac_s, NULL, NULL, maxsec ? &tval : NULL);
	if (n == 0)
		return (0);

	if (FD_ISSET (s, &ac_s)) {
		len = sizeof (struct sockaddr_in);
		n = accept (s, (struct sockaddr *) cs, &len);
		if (n == -1) {
			switch (errno) {
			case EWOULDBLOCK:
			case ECONNABORTED:
			case EPROTO:
			case EINTR:	if (fcntl (s, F_SETFL, flags) == -1)
						return (-1);
					return (0);
			default:	return (-1);
			}
		}
		if (fcntl (s, F_SETFL, flags) == -1)
			return (-1);
		return (n);
	}
	if (fcntl (s, F_SETFL, flags) == -1)
		return (-1);

	return (0);
}


void
net_boundfree (bound *bf)
{
	close (bf->bs);
	free (bf);

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

	b = xcalloc (1, sizeof (bound));
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
	free (b);

	return(NULL);
}


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


char *
net_getlocalip (void)
{
	struct sockaddr_in	pf;
	char			name[255];

	memset (name, '\0', sizeof (name));

	if (gethostname (name, sizeof (name) - 1) == -1) {
		return (NULL);
	}

	pf.sin_addr.s_addr = net_resolve (name);

	return (strdup (inet_ntoa (pf.sin_addr)));;
}


/* partly based on resolv routine from ?
 */

unsigned long int
net_resolve (char *host)
{
	long		i;
	struct hostent	*he;

	if (host == NULL)
		return (htonl (INADDR_ANY));

	if (strcmp (host, "*") == 0)
		return (htonl (INADDR_ANY));

	i = inet_addr (host);
	if (i == -1) {
		he = gethostbyname (host);
		if (he == NULL) {
			return (0);
		} else {
			return (*(unsigned long *) he->h_addr);
		}
	}
	return (i);
}


int
net_printipr (struct in_addr *ia, char *str, size_t len)
{
        unsigned char   *ipp;

        ipp = (unsigned char *) &ia->s_addr;
	snprintf (str, len - 1, "%d.%d.%d.%d", ipp[3], ipp[2], ipp[1], ipp[0]);

	return (0);
}


int
net_printip (struct in_addr *ia, char *str, size_t len)
{
        unsigned char   *ipp;

        ipp = (unsigned char *) &ia->s_addr;
	snprintf (str, len - 1, "%d.%d.%d.%d", ipp[0], ipp[1], ipp[2], ipp[3]);

	return (0);
}


int
net_printipa (struct in_addr *ia, char **str)
{
	unsigned char	*ipp;

        ipp = (unsigned char *) &ia->s_addr;
	*str = calloc (1, 256);
	if (*str == NULL)
		return (1);

	snprintf (*str, 255, "%d.%d.%d.%d", ipp[0], ipp[1], ipp[2], ipp[3]);
	*str = realloc (*str, strlen (*str) + 1);

	return ((*str == NULL) ? 1 : 0);
}


