/* scut's leet network library ;)
 * 1999 (c) scut
 *
 * networking code 
 */

#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>

#ifndef _NETWORK_H
#define _NETWORK_H

#define NET_READTIMEOUT	180
#define NET_CONNTIMEOUT	60
#define	NET_IDENTTIMEOUT 15

#define	IFI_NAME	16
#define	IFI_HADDR	8

/* pointer to this struct list returned by net_get_ifi
 */
struct ifi_info {
	char	ifi_name[IFI_NAME];
	u_char	ifi_haddr[IFI_HADDR];
	u_short	ifi_hlen;
	short	ifi_flags;
	short	ifi_myflags;
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

/* net_socks_connect
 *
 * relays through an open socks 5 server (NO AUTH type)
 * returns a socket descriptor which is already connected
 */

int	net_socks_connect (char *socks, unsigned short int sport, char *server, unsigned short int port, int sec);

/* net_socks_put_s5info
 *
 * inserts socks 5 compatible relay information into socket s5s,
 * used to relay over more then just one socks server
 */

int	net_socks_put_s5info (int s5s, char *server, unsigned short int port, int sec);

/* net_parseip
 *
 * reads an ip in the format "1.1.1.1:299" or "blabla:481" into
 * the char pointer *ip and into the port *port
 *
 * returns 0 on failure
 * returns 1 on success
 */
int	net_parseip (char *inp, char **ip, unsigned short int *port);

/* net_getlocalip
 *
 * returns the local IP address as string on success
 * returns NULL on failure
 */

char	*net_getlocalip (void);

/* net_descriptify
 *
 * descriptifies a socket ;)
 * returns -1 on failure
 * returns file descriptor on success
 */

FILE	*net_descriptify (int socket);

/* net_ident
 *
 * idents a connection identified by the host:port pairs on both sides,
 * returning the ident in *ident
 *
 * returns 1 on success
 * returns -1 on failure
 */

int	net_ident (char **ident, struct sockaddr_in *locals, unsigned short int localport,
			struct sockaddr_in *remotes, unsigned short int remoteport);

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

/* net_get_ifi
 * get interface information
 * returns NULL on failure
 * returns a pointer to a linked list structure ifi_info (see above)
 */

struct ifi_info	*net_ifi_get (int family, int doaliases);
void		net_ifi_free (struct ifi_info *tf);

/* net_testvip
 * tests if virtual ip/hostname is available for use on the local machine,
 * returns 1 if the ip can be used
 *         0 if the ip/host is not available
 */
int	net_testvip (char *ip);

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
 *
 * returns -1 on failure
 * returns socket if success
 */
int	net_connect(struct sockaddr_in *cs, char *server, unsigned short int port, int sec);

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

