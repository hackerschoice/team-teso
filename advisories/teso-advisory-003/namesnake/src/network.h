/* namesnake
 *
 * by scut
 */

#ifndef _FNX_NETWORK_H
#define _FNX_NETWORK_H

#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>


typedef	struct bound {
	int			bs;	/* bound socket */
	unsigned short		port;	/* port we bound to */
	struct sockaddr		bsa;	/* bs_in */
} bound;


/* net_connect
 *
 * connect to the given `server' and `port' with a max timeout of `sec'.
 * initialize the sockaddr_in struct `cs' correctly (ipv4), accept any
 * ip "123.123.123.123" or hostname "localhost", "www.yahoo.de" as hostname.
 * create a new socket and return either -1 if failed or
 * the connected socket if connection has been established within the
 * timeout limit.
 *
 * the routine is still IPv4 biased :-/
 *
 * return -1 on failure
 * return socket if success
 */

int	net_connect (struct sockaddr_in *cs, char *server, unsigned short int port,
	int sec);


/* net_accept
 *
 * accept a connection from socket s, and stores the connection
 * into cs.
 * wait a maximum amount of maxsec seconds for connections
 * maxsec can also be zero (infinite wait, until connection)
 *
 * return 0 if no connection has been made within maxsec seconds
 * return -1 if an error appears
 * return the socket number if a connection has been made
 */

int	net_accept (int s, struct sockaddr_in *cs, int maxsec);


/* net_bind
 *
 * bind a socket to an ip:port on the local machine,
 * `ip' can be either NULL (bind to all IP's on the host), or a pointer
 * to a virtual host name, or a real IP, or "*" for any.
 * `port' can be either 0 (ephemeral port), or any free port.
 *
 * return NULL on failure
 * return pointer to bound structure on success
 */

bound 	*net_bind (char *ip, unsigned short int port);


/* net_boundfree
 *
 * free the bound structure pointed to by `bf'
 *
 * return in any case
 */

void	net_boundfree (bound *bf);


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

