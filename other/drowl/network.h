
/* zodiac - advanced dns spoofer
 *
 * ripped down network.c for use with zodiac
 *
 * by scut / teso
 */

#ifndef Z_NETWORK_H
#define Z_NETWORK_H

#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>

#define	IFI_NAME	16
#define	IFI_HADDR	8

/* struct ifi_info
 *
 * a linked list giving information about all the network interfaces available
 * a pointer to this struct list is returned by net_get_ifi.
 */

struct ifi_info {
	char		ifi_name[IFI_NAME];
	u_char		ifi_haddr[IFI_HADDR];
	u_short		ifi_hlen;
	short		ifi_flags;
	short		ifi_myflags;
	struct sockaddr	*ifi_addr;
	struct in_addr	ifi_saddr;
	struct ifi_info	*ifi_next;
};

#define	IFI_ALIAS	1

typedef	struct bound {
	int			bs;	/* bound socket */
	unsigned short		port;	/* port we bound to */
	struct sockaddr		bsa;	/* bs_in */
} bound;

extern int	net_readtimeout;
extern int	net_conntimeout;
extern int	net_identtimeout;


/* net_parseip
 *
 * read an ip in the format "1.1.1.1:299" or "blabla:481" into
 * the char pointer *ip and into the port *port
 *
 * return 0 on failure
 * return 1 on success
 */

int	net_parseip (char *inp, char **ip, unsigned short int *port);


/* net_getlocalip
 *
 * give back the main IP of the local machine
 *
 * return the local IP address as string on success
 * return NULL on failure
 */

char	*net_getlocalip (void);


/* net_get_ifi
 *
 * get network interface information
 *
 * return NULL on failure
 * return a pointer to a linked list structure ifi_info (see above)
 */

struct ifi_info	*net_ifi_get (int family, int doaliases);


/* net_ifi_free
 *
 * free the linked list associated with `tf'.
 *
 * return in any case
 */

void	net_ifi_free (struct ifi_info *tf);


/* net_resolve
 *
 * resolve a hostname pointed to by `host' into a s_addr return value
 *
 * return the correct formatted `s_addr' for this host on success
 * return 0 on failure
 */

unsigned long int	net_resolve (char *host);


/* net_printip
 *
 * print an IP address stored in the struct in_addr pointed to by `ia' to a
 * string `str' with a maximum length of `len'.
 *
 * return 0 on success
 *Üreturn 1 on failure
 *
 * net_printipa behaves the same way, except it allocates memory and let
 * `*str' point to the string
 *
 * net_printipr behaves like net_printip, except the IP is printed in
 * reverse quad dotted order (dns labels)
 */

int	net_printip (struct in_addr *ia, char *str, size_t len);
int	net_printipa (struct in_addr *ia, char **str);
int	net_printipr (struct in_addr *ia, char *str, size_t len);


#endif

