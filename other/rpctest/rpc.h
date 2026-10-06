/* rpctest
 *
 * smiler / teso 
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <arpa/inet.h>

#define MAXARGS 10
#define TIMEOUT 3

#define VERSION "0.1"

typedef struct rpchdr {
	u_int   xid,
	        msg_type,
	        rpc_ver,
	        id,
	        ver,
	        proc;
} rpchdr;

#define RPCHDRSIZE sizeof (rpchdr)


#define SA struct sockaddr


/* stuff.c */
int     resolv (char *hostname, struct in_addr *addr);
int     udp_connect (struct in_addr addr, u_short port);
int     send_recv (int s, const void *msg, int len, void *recv_buf, int recv_len);
int     parse_args (char *str, char **args);
void    strip_crlf (char *s);

/* rpc.c */
int     rpc_null_auth (char *buf);
int     rpc_make_hdr (u_int prog, u_int proc, u_int ver, char *buf);

/* build.c */
void    build_rpc (void);
