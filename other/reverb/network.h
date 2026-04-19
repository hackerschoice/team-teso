/* scut's leet network library ;)
 * 1999 (c) scut
 *
 * networking code 
 */

#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>

#ifndef SCUT_NETWORK_H
#define SCUT_NETWORK_H

#define NET_READTIMEOUT	180
#define NET_CONNTIMEOUT	60


typedef	struct bound {
	int			bs;	/* bound socket */
	unsigned short		port;	/* port we bound to */
	struct sockaddr		bsa;	/* bs_in */
} bound;

extern int	net_readtimeout;
extern int	net_conntimeout;


/* net_parseip
 *
 * reads an ip in the format "1.1.1.1:299" or "blabla:481" into
 * the char pointer *ip and into the port *port
 *
 * returns 0 on failure
 * returns 1 on success
 */
int	net_parseip (char *inp, char **ip, unsigned short int *port);


/* net_accept
 * accepts a connection from socket s, and stores the connection
 * into cs.
 * wait a maximum amount of maxsec seconds for connections
 * maxsec can also be zero (infinite wait, until connection)
 *
 * returns 0 if no connection has been made within maxsec seconds
 * returns -1 if an error appears
 * returns the socket number if a connection has been made
 */

int	net_accept (int s, struct sockaddr_in *cs, int maxsec);


/* net_bind
 * binds a socket to an ip:port on the local machine,
 * ip can be either NULL (bind to all IP's on the host), or a pointer
 * to a virtual host name, or a real IP, or "*" for any.
 * port can be either 0 (ephemeral port), or any free port.
 *
 * returns NULL on failure
 *         pointer to bound structure on success
 */
bound 	*net_bind (char *ip, unsigned short int port);
void	net_boundfree (bound *bf);


/* net_resolve
 * resolves host into s_addr
 */
unsigned long int	net_resolve(char *host);


/* net_connect
 * connects to the given server and port with a max timeout of sec
 * initializes the sockaddr_in struct correctly (ipv4), accepts any
 * ip "123.123.123.123" or hostname "localhost", "www.yahoo.de" as hostname
 * creates a new socket and returns either -1 if failed or
 * the socket if connection has been established within the timeout limit
 * routine is still IPv4 biased :-/
 * with sourceip/sourceport you MAY specify the source IP and source port
 * to use for the connection, but you can set the ip or port to NULL/0,
 * to choose the default IP and an ephemeral port. this was added later in
 * this library, so please update your sources.
 *
 * returns -1 on failure
 * returns socket if success
 */
int	net_connect (struct sockaddr_in *cs, char *server, unsigned short int port, int sec);


/* net_rtimeout
 * waits max <sec> seconds for fd to become readable
 * returns -1 on error (errno set)
 * returns 1 on readability
 */
int	net_rtimeout(int fd, int sec);


/* net_rbuf
 * allocates memory and reads to *dst until connection close
 * returns n if success (n = number of bytes read)
 * returns -1 if failed
 */
long int	net_rbuf(int fd, char **dst);
#define NET_BSIZE  4096


/* net_rbuft
 * reads dsize bytes into dst from fd, with timeout
 * returns 1 on success
 * returns -1 on failure
 */
int	net_rbuft(int fd, char *dst, unsigned long int dsize);


/* net_rlinet
 * reads a line from socket descriptor with timeout to buffer
 * if sec = 0, then only a continuous stream of data is required, not
 * an overall timeout.
 * returns -1 on timeout
 * returns 0  on connection close
 * returns length of readen line (including '\n')
 */
int	net_rlinet(int fd, char *buf, int bufsize, int sec);


/* net_tline
 * returns length if string contains '\n'
 * returns -1 if no '\n' in string
 */
int	net_tline(char *buf, int bufsize);


/* net_write
 * prints a formatted string to a socket
 */
void	net_write(int fd, const char *str, ...);

#endif

