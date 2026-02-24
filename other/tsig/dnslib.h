/* dns helper functions by smiler / teso
 * requires bind 8.x headers now
 */

#ifndef DNSLIB_H
#define DNSLIB_H
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/nameser.h>

/* little endian macros */

#define NS_LPUT16(s, blah) { \
	u_char *p = blah; \
	*(u_int16_t *)p = s; \
	blah += 2; \
} 

#define NS_LPUT32(s, blah) { \
	u_char *p = blah; \
	*(u_int32_t *)p = s; \
	blah += 4; \
}

/* make a fully blown query packet */
int dns_mkquery (char *name, u_char *buffer, u_int16_t id, ns_type type, ns_class klass);

/* make a query record */
int dns_mkqbody (char *name, u_char *buffer, ns_type type, ns_class klass);

/* convert to dns names, i.e. www.yahoo.com ==> \003www\005yahoo\003com\000 */
int dns_mkdn (char *in, u_char *out);

/* uncompress (unchecked) a dns name */
int dns_dn_expand (u_char *in, char *out, u_char *msg);

/* make a long dns name fragment (without terminating \000)
 * provided length > 1
 */
int dns_mklongdn (u_char *cp, int length);

/* print debug information to stderr
 */
void dns_debug (unsigned char *buf);

typedef struct {
	u_int16_t type;
	u_int16_t klass;
	u_int32_t ttl;
	u_int16_t rdlength;
} rrec_body;

/* create a resource record */
int	dns_mkrr (char *name, u_char *buf, ns_type type, ns_class klass,
		char *rdata, u_int32_t ttl);

#endif /* DNSLIB_H */
