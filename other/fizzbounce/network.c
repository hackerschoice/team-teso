
/* scut's leet network library ;)
 * 1999 (c) scut
 *
 * networking routines
 * based on my hbot networking sources,
 * revised, extended and adapted 990405
 * extended, improved and fixed 990430
 *
 * nearly all of this code wouldn't have been possible without w. richard stevens
 * excellent network coding book. if you are interested in network coding,
 * there is no way around it.
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
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
int	net_identtimeout = NET_IDENTTIMEOUT;

int
net_socks_connect (char *socks, unsigned short int sport, char *server, unsigned short int port, int sec)
{
	int			s5s;
	struct sockaddr_in	cs;

	s5s = net_connect (&cs, socks, sport, sec);
	if (s5s == -1)
		return (-1);

	if (net_socks_put_s5info (s5s, server, port, sec) == -1) {
		close (s5s);
		return (-1);
	}
	return (s5s);
}

int
net_socks_put_s5info (int s5s, char *server, unsigned short int port, int sec)
{
	int	n;
	char	buff[1024];

	/* v5 + noauth */
	net_write (s5s, "\x05\x01%c", 0);
	if (net_rtimeout (s5s, sec) == -1)
		return (-1);
	recv (s5s, buff, sizeof (buff), 0);

	/* chain us =) */
	net_write (s5s, "\x05\x01%c\x03%c%s%c%c", 0, strlen (server), server, (port >> 8) & 0xff, port & 0xff);
	if (net_rtimeout (s5s, sec) == -1)
		return (-1);
	n = recv (s5s, buff, sizeof (buff), 0);
	if (buff[1] != 0x00) {
		return (-1);
	}
	return (1);
}

int
net_parseip (char *inp, char **ip, unsigned short int *port)
{
	int	n;

	if (inp == NULL)
		return (0);
	if (strchr (inp, ':') == NULL)
		return (0);

	n = sscanf (inp, "%a[^:]:%hu", ip, port);
	if (n != 2)
		return (0);

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

FILE *
net_descriptify (int socket)
{
	FILE	*fp;

	fp = fdopen (socket, "r+");
	return ((fp == NULL) ? (NULL) : (fp));
}

/* loosely based on rfc931.c */

int
net_ident (char **ident, struct sockaddr_in *locals, unsigned short int localport,
		struct sockaddr_in *remotes, unsigned short int remoteport)
{
	int			is;	/* ident socket */
	struct sockaddr_in	isa;
	int			n;
	char			identreply[512], *cp;
	unsigned int		rmt_port, our_port;


	*ident = NULL;

	is = net_connect (&isa, inet_ntoa (remotes->sin_addr), 113, net_identtimeout);
	if (is == -1)
		return (-1);

	/* ident request */
	net_write (is, "%u,%u\r\n", remoteport, localport);
	memset (identreply, '\0', sizeof (identreply));

	n = net_rlinet (is, identreply, sizeof(identreply) -1, net_identtimeout);
	if (n == -1) {
		close (is);
		return (-1);
	}
	close (is);

	*ident = calloc (1, 256);
#ifdef DEBUG
	printf("%s\n", identreply);
#endif
	n = sscanf (identreply, "%u , %u : USERID :%*[^:]:%255s", &rmt_port, &our_port, *ident);
	if (n != 3) {
		free (*ident);
		*ident = NULL;
		return (-1);
	}

	/* check the ports 'man */
	if ((rmt_port != remoteport) || (our_port != localport)) {
		free (*ident);
		*ident = NULL;
		return (-1);
	}

	/* strip character and save some memory */
	if ((cp = strchr (*ident, '\r')))
		*cp = '\0';
	n = strlen (*ident);
	*ident = realloc (*ident, n + 1);
	(*ident)[n] = '\0';
 
#ifdef DEBUG
	printf("ident-return: %s\n", *ident);
#endif
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

int
net_testvip (char *ip)
{
	struct ifi_info	*ifi, *ifc;
	struct in_addr	ip_n;

	if (ip == NULL)
		return (1);
	if (strcmp(ip, "*") == 0)
		return (1);

	ip_n.s_addr = net_resolve(ip);
	if (!(ip_n.s_addr))
		return (0);

	ifi = net_ifi_get (AF_INET, 1);
	if (ifi == NULL)
		return (0);
	for (ifc = ifi; ifc != NULL; ifc = ifc->ifi_next) {
		if (memcmp(&ip_n.s_addr, &ifc->ifi_saddr.s_addr, sizeof(struct in_addr)) == 0) {
			net_ifi_free(ifi);
			return (1);
		}
	}
	net_ifi_free(ifi);
	return (0);
}

void
net_ifi_free (struct ifi_info *tf)
{
	struct ifi_info	*ifi, *ifil;

	ifil = NULL;
	for (ifi = tf; ifi != NULL; ifi = ifi->ifi_next) {
		if (ifil)
			free (ifil);
		if (ifi->ifi_addr)
			free (ifi->ifi_addr);
		ifil = ifi;
	}
	if (ifil)
		free (ifil);
	return;
}

struct ifi_info *
net_ifi_get (int family, int doaliases)
{
	struct ifi_info		*ifi, *ifihead, **ifipnext;
	int			sockfd, len, lastlen, flags, myflags;
	char			*ptr, *buf, lastname[IFNAMSIZ], *cptr;
	struct ifconf		ifc;
	struct ifreq		*ifr, ifrcopy;
	struct sockaddr_in	*sinptr;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1)
		return (NULL);

	lastlen = 0;
	len = 100 * sizeof(struct ifreq);
	for (;;) {
		buf = malloc(len);
		if (buf == NULL)
			return (NULL);
		ifc.ifc_len = len;
		ifc.ifc_buf = buf;
		if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
			if (errno != EINVAL || lastlen != 0)
				return (NULL);
		} else {
			if (ifc.ifc_len == lastlen)
				break;
			lastlen = ifc.ifc_len;
		}
		len += 10 * sizeof(struct ifreq);
		free (buf);
	}
	ifihead = NULL;
	ifipnext = &ifihead;
	lastname[0] = 0;

	for (ptr = buf; ptr < buf + ifc.ifc_len;) {
		ifr = (struct ifreq *) ptr;
		if (ifr->ifr_addr.sa_family == AF_INET)
			len = sizeof(struct sockaddr);
		ptr += sizeof(ifr->ifr_name) + len;

		if (ifr->ifr_addr.sa_family != family)
			continue;
		myflags = 0;
		if ((cptr = strchr(ifr->ifr_name, ':')) != NULL)
			*cptr = 0;
		if (strncmp(lastname, ifr->ifr_name, IFNAMSIZ) == 0) {
			if (doaliases == 0)
				continue;
			myflags = IFI_ALIAS;
		}
		memcpy(lastname, ifr->ifr_name, IFNAMSIZ);

		ifrcopy = *ifr;
		if (ioctl(sockfd, SIOCGIFFLAGS, &ifrcopy) < 0)
			return (NULL);
		flags = ifrcopy.ifr_flags;
		if ((flags & IFF_UP) == 0)
			continue;

		ifi = calloc(1, sizeof(struct ifi_info));
		if (ifi == NULL)
			return (NULL);
		*ifipnext = ifi;
		ifipnext = &ifi->ifi_next;
		ifi->ifi_flags = flags;
		ifi->ifi_myflags = myflags;
		memcpy(ifi->ifi_name, ifr->ifr_name, IFI_NAME);
		ifi->ifi_name[IFI_NAME - 1] = '\0';

#ifdef DEBUG
		printf("got: %s\n", ifi->ifi_name);
#endif

		switch (ifr->ifr_addr.sa_family) {
		case AF_INET:
			sinptr = (struct sockaddr_in *) &ifr->ifr_addr;
			memcpy(&ifi->ifi_saddr, &sinptr->sin_addr, sizeof(struct in_addr));
			if (ifi->ifi_addr == NULL) {
				ifi->ifi_addr = calloc(1, sizeof(struct sockaddr_in));
				if (ifi->ifi_addr == NULL)
					return (NULL);
				memcpy(ifi->ifi_addr, sinptr, sizeof(struct sockaddr_in));
			}
			break;
		default:
			break;
		}
	}
	free (buf);
	return (ifihead);
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
	int			len;
	struct sockaddr_in	*sap;

	if (port >= 65536)
		return (NULL);

	b = calloc(1, sizeof(bound));
	if (b == NULL)
		return (NULL);
	b->bs = socket(AF_INET, SOCK_STREAM, 0);
	if (b->bs == -1)
		goto berror;

	sap = (struct sockaddr_in *) &b->bsa;
	sap->sin_family = AF_INET;
	sap->sin_port = htons(port);		/* 0 = ephemeral */

	if (ip != NULL) {
		if (strcmp(ip,"*") == 0) {
			sap->sin_addr.s_addr = htonl(INADDR_ANY);
		} else {
			if (!(sap->sin_addr.s_addr = net_resolve(ip))) {
				goto berror;
			}
		}
	} else {
		sap->sin_addr.s_addr = htonl(INADDR_ANY);
	}

	br = bind(b->bs, (struct sockaddr *) &b->bsa, sizeof(struct sockaddr));
	if (br == -1)
		goto berror;

	len = sizeof(struct sockaddr);
	gsnr = getsockname(b->bs, (struct sockaddr *) &b->bsa, &len);
	b->port = ntohs(sap->sin_port);
	if (gsnr == -1)
		goto berror;

	lr = listen(b->bs, 16);
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

	if (!(cs->sin_addr.s_addr = net_resolve(server))) {
		return (-1);
	}
	cs->sin_family = AF_INET;
	cs->sin_port = htons(port);

	fd = socket(cs->sin_family, SOCK_STREAM, 0);
	if (fd == -1)
		return (-1);

	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1)
		return (-1);
	n = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (n == -1)
		return (-1);

	error = 0;

	n = connect(fd, (struct sockaddr *) cs, sizeof(struct sockaddr_in));
	if (n < 0) {
		if (errno != EINPROGRESS) {
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

