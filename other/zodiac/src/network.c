
/* zodiac - advanced dns spoofer
 *
 * network primitives
 *
 * by scut / teso
 *    smiler
 *
 * nearly all of this code wouldn't have been possible without w. richard stevens
 * excellent network coding book. if you are interested in network coding,
 * there is no way around it.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "network.h"


struct in_addr	localip;


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
	return (strdup (inet_ntoa (localip)));;
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


