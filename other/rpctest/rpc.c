/* rpctest
 *
 * smiler / teso
 */
#include "rpc.h"

int
rpc_null_auth (char *buf)
{
	u_int  *auth;

	auth = (u_int *) buf;
	*auth++ = htonl (0);
	*auth++ = htonl (0);
	*auth++ = htonl (0);
	*auth++ = htonl (0);
	return (16);
}

int
rpc_make_hdr (u_int prog, u_int proc, u_int ver, char *buf)
{
	rpchdr *rpc;

	rpc = (rpchdr *) buf;
	rpc->xid = random ();
	rpc->msg_type = 0;
	rpc->rpc_ver = htonl (2);
	rpc->id = htonl (prog);
	rpc->ver = htonl (ver);
	rpc->proc = htonl (proc);

	return (RPCHDRSIZE);
}
