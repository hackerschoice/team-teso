
/* zodiac - advanced dns spoofer
 *
 * dns packet builder routines include file
 *
 * by scut / teso
 */

#ifndef	Z_DNS_BUILD_H
#define	Z_DNS_BUILD_H


/* dns_pdata
 *
 * domain name service packet data part structure.
 * the data in this structure is the virtual dns packet to fire.
 */

typedef struct	dns_pdata {
	unsigned char	*p_offset;	/* internal offset to construct packet data */
	unsigned char	*p_data;	/* real packet data pointer */
} dns_pdata;


/* dns_build_random
 *
 * prequel the domain name `domain' with a random sequence of characters
 * with a random length if `len' is zero, and a fixed length if len is != 0
 *
 * return the allocated new string
 */

char		*dns_build_random (char *domain, size_t len);

/* dns_domain
 *
 * return a pointer to the beginning of the SLD within a full qualified
 * domain name `domainname'.
 *
 * return NULL on failure
 * return a pointer to the beginning of the SLD on success
 */

char		*dns_domain (char *domainname);
char		*dns_ptr_domain (char *arpaname);


/* dns_build_new
 *
 * constructor. create new packet data body
 *
 * return packet data structure pointer (initialized)
 */

dns_pdata	*dns_build_new (void);


/* dns_build_destroy
 *
 * destructor. destroy a dns_pdata structure pointed to by `pd'
 *
 * return in any case
 */

void		dns_build_destroy (dns_pdata *pd);


/* dns_build_plen
 *
 * calculate the length of the current packet data body pointed to by `pd'.
 *
 * return the packet length
 */

u_short		dns_build_plen (dns_pdata *pd);


/* dns_build_extend
 *
 * extend a dns_pdata structure data part for `amount' bytes.
 *
 * return a pointer to the beginning of the extension
 */

unsigned char	*dns_build_extend (dns_pdata *pd, size_t amount);


/* dns_build_ptr
 *
 * take a numeric quad dot notated ip address `ip_str' and build a char
 * domain out of it within the IN-ADDR.ARPA domain.
 *
 * return NULL on failure
 * return a char pointer to the converted domain name
 */

char		*dns_build_ptr (char *ip_str);


/* dns_build_q
 *
 * append a query record into a dns_pdata structure, where `dname' is the
 * domain name that should be queried, using `qtype' and `qclass' as types.
 *
 * conversion of the `dname' takes place according to the value of `qtype':
 *
 * qtype    | expected dname format | converted to
 * ---------+-----------------------+-----------------------------------------
 * TY_PTR   | char *, ip address    | IN-ADDR.ARPA dns domain name
 * TY_A     | char *, full hostname | dns domain name
 * TY_NS    | "                     | "
 * TY_CNAME | "                     | "
 * TY_WKS   | "                     | "
 * TY_HINFO | "                     | "
 * TY_MINFO | "                     | "
 * TY_MX    | "                     | "
 *
 * return (beside adding the record) the pointer to the record within the data
 */

unsigned char	*dns_build_q (dns_pdata *pd, char *dname, u_short qtype, u_short qclass);


/* dns_build_rr
 *
 * append a resource record into a dns_pdata structure, pointed ty by `pd',
 * where `dname' is the domain name the record belongs to, `type' and `class'
 * are the type and class of the dns data part, `ttl' is the time to live,
 * the time in seconds how long to cache the record. `rdlength' is the length
 * of the resource data pointed to by `rdata'.
 * depending on `type' the data at `rdata' will be converted to the appropiate
 * type:
 *
 * type   | rdata points to     | will be
 * -------+---------------------+---------------------------------------------
 * TY_A   | char IP address     | 4 byte network byte ordered IP address
 * TY_PTR | char domain name    | encoded dns domain name
 * TY_NS  | char domain name    | encoded dns domain name
 *
 * return (beside adding the record) the pointer to the record within the data
 */

unsigned char	*dns_build_rr (dns_pdata *pd, unsigned char *dname,
	u_short type, u_short class, u_long ttl, void *rdata);


/* dns_build_query_label
 *
 * build a query label given from the data `query' that should be enclosed
 * and the query type `qtype' and query class `qclass'.
 *
 * qtype	qclass		query
 * -----------+---------------+-----------------------------------------------
 * A		IN		pointer to a host- or domainname
 * PTR		IN		pointer to a struct in_addr
 *
 * ... (to be extended) ...
 *
 * return 0 on success
 * return 1 on failure
 */
int		dns_build_query_label (unsigned char **query_dst, u_short qtype, u_short qclass, void *query);


/* dns_build_domain
 *
 * build a dns domain label sequence out of a printable domain name
 * store the resulting domain in `denc', get the printable domain
 * from `domain'.
 *
 * return 0 on failure
 * return length of the created domain (include suffixing '\x00')
 */

int		dns_build_domain (unsigned char **denc, char *domain);


/* dns_build_domain_dotlen
 *
 * helper routine, determine the length of the next label in a human
 * printed domain name
 *
 * return the number of characters until an occurance of \x00 or '.'
 */

int		dns_build_domain_dotlen (char *label);


/* dns_packet_send
 *
 * send a prepared dns packet spoofing from `ip_src' to `ip_dst', using
 * source port `prt_src' and destination port `prt_dst'. the dns header
 * data is filled with `dns_id', the dns identification number of the
 * packet, `flags', which are the 16bit flags in the dns header, then
 * four count variables, each for a dns segment: `count_q' is the number
 * of queries, `count_a' the number of answers, `count_ns' the number of
 * nameserver entries and `count_ad' the number of additional entries.
 * the real dns data is aquired from the dns packet data `pd'.
 * the dns data should be constructed using the dns_build_* functions.
 * if the packet should be compressed before sending it, `compress'
 * should be set to 1.
 *
 * return 0 on success
 * return 1 on failure
 */

int		dns_packet_send (char *ip_src, char *ip_dst, u_short prt_src, u_short prt_dst,
			u_short dns_id, u_short flags, u_short count_q, u_short count_a,
			u_short count_ns, u_short count_ad, dns_pdata *pd, int compress);

#endif

