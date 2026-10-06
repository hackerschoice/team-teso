/* rpctest
 *
 * smiler / teso
 */

#include "rpc.h"
#include "pmap.h"

mapping pmap_cache[PMAP_CACHE + 1];
struct in_addr cached_host;

void
pmap_print_cache (void)
{
	mapping *ptr;

	if (!cached_host.s_addr)
		return;

	printf ("   program vers proto port\n");

	for (ptr = pmap_cache; ptr->prog; ptr += 1) {
		printf ("%10d %4d %5s %4d\n",
			ptr->prog, ptr->vers,
			(ptr->prot == 6) ? "tcp" : "udp",
			ptr->port);
	}
	return;
}

void
pmap_parse_pkt (char *pkt)
{
	int     a;
	u_int  *ptr,
	        len;

	ptr = (u_int *) pkt;
	ptr += 4;

	len = ntohl (*ptr++);
	ptr += (len >> 2) + 1;

	a = 0;

	while (ntohl (*ptr++) && (a < (PMAP_CACHE - 1))) {
		mapping *cache_ptr;

		cache_ptr = &pmap_cache[a];
		cache_ptr->prog = ntohl (*ptr++);
		cache_ptr->vers = ntohl (*ptr++);
		cache_ptr->prot = ntohl (*ptr++);
		cache_ptr->port = ntohl (*ptr++);
		a++;
	}
	pmap_cache[a].prog = 0;
	return;
}

int
pmap_dump (char *hostname)
{
	char   *ptr,
	        send_pkt[1024],
	        recv_pkt[1024];
	int     fd;
	struct in_addr addr;

	if (!resolv (hostname, &addr)) {
		herror ("resolv");
		return (-1);
	}
	cached_host = addr;

	bzero (pmap_cache, sizeof (pmap_cache));
	fd = udp_connect (addr, PMAP_PORT);
	if (fd < 0) {
		perror ("connect");
		return (-1);
	}
	ptr = send_pkt;
	ptr += rpc_make_hdr (PMAP_PROG, PMAP_DUMP, 2, ptr);
	ptr += rpc_null_auth (ptr);


	if (send_recv (fd, send_pkt, ptr - send_pkt, recv_pkt, 1024) < 0) {
		perror ("send_recv");
		close (fd);
		return (-1);
	}
	pmap_parse_pkt (recv_pkt);
	pmap_print_cache ();
	close (fd);
	return (0);
}

void
pmap_dump_cache (void)
{
	if (cached_host.s_addr == 0) {
		printf ("No cache in memory\n");
		return;
	}
	printf ("Host: %s\n", inet_ntoa (cached_host));
	pmap_print_cache ();
	return;
}

mapping *
pmap_find (int port, int prog, int vers, int prot)
{
	mapping *ptr;

	if (!(port || prog || vers || prot))
		return (NULL);

	for (ptr = pmap_cache; ptr->prog; ptr += 1) {
		if (port && (port != ptr->port))
			continue;
		if (prog && (prog != ptr->prog))
			continue;
		if (vers && (vers != ptr->vers))
			continue;
		if (prot && (prot != ptr->prot))
			continue;
		return (ptr);
	}

	return (NULL);
}
