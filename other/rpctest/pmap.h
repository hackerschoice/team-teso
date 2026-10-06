/* rpctest
 *
 * smiler / teso
 */
#ifndef PMAP_H
#define PMAP_H
#include <arpa/inet.h>

#define PMAP_CACHE 50

#define PMAP_PORT 111
#define PMAP_PROG 100000
#define PMAP_DUMP 4

typedef struct mapping {
	u_int   prog,
	        vers,
	        prot,
	        port;
} mapping;

extern mapping pmap_cache[PMAP_CACHE + 1];
extern struct in_addr cached_host;

void    pmap_parse_pkt (char *buf);
int     pmap_dump (char *hostname);
void    pmap_dump_cache (void);
mapping *pmap_find (int port, int prog, int vers, int prot);

#endif
