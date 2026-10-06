
/* drowl
 *
 * dns packet construction routines
 * if you need some, just borrow here and drop me a line of credit :)
 *
 * by scut / teso
 */

#include <libnet.h>	/* route's owning library =) */
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "dns.h"
#include "dns-build.h"
#include "network.h"


/* dns_labellen
 *
 * determine the length of a dns label pointed to by `wp'
 *
 * return the length of the label
 */

int
dns_labellen (unsigned char *wp)
{
	unsigned char	*wps = wp;

	while (*wp != '\x00') {
		/* in case the label is compressed we don't really care,
		 * but just skip it
		 */
		if ((*wp & 0xc0) == 0xc0) {
			wp += sizeof (u_short);

			/* non-clear RFC at this point, got to figure with some
			 * real dns packets
			 */
			return ((int) (wp - wps));
		} else {
			wp += (*wp + 1);
		}
	}

	return ((int) (wp - wps) + 1);
}


/* dns_build_random
 *
 * prequel the domain name `domain´ with a random sequence of characters
 * with a random length
 *
 * return the allocated new string
 */

char *
dns_build_random (char *domain)
{
	int	dlen, cc;
	char	*pr;

	cc = dlen = m_random (3, 16);
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

	/* parse ip string, on failure drop conversion
	 */
	n = sscanf (ip_str, "%d.%d.%d.%d", &dec[0], &dec[1], &dec[2], &dec[3]);
	if (n != 4)
		return (NULL);

	/* allocate a new string of the required length
	 */
	ip_ptr = xcalloc (1, strlen (ip_str) + strlen (".IN-ADDR.ARPA") + 1);
	sprintf (ip_ptr, "%d.%d.%d.%d.IN-ADDR.ARPA", dec[3], dec[2], dec[1], dec[0]);

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
 * TY_PTR   | char *, ip address    | IN-ADDR.ARPA dns domain name
 * TY_A     | char *, full hostname | dns domain name
 * TY_NS    | "                     | "
 * TY_CNAME | "                     | "
 * TY_SOA   | "                     | "
 * TY_WKS   | "                     | "
 * TY_HINFO | "                     | "
 * TY_MINFO | "                     | "
 * TY_MX    | "                     | "
 * TY_ANY   | "                     | "
 *
 * return (beside adding the record) the pointer to the record within the data
 */

unsigned char *
dns_build_q (dns_pdata *pd, char *dname, u_short qtype, u_short qclass)
{
	unsigned char	*qdomain = NULL;
	unsigned char	*tgt, *rp;
	int		n;

	switch (qtype) {
	case (TY_PTR):
		/* convert in itself, then convert to a dns domain
		 */
		dname = dns_build_ptr (dname);
		if (dname == NULL)
			return (NULL);

	case (TY_A):
	case (TY_NS):
	case (TY_CNAME):
	case (TY_SOA):
	case (TY_WKS):
	case (TY_HINFO):
	case (TY_MINFO):
	case (TY_MX):
	case (TY_TXT):
	case (TY_ANY):
		/* convert to a dns domain
		 */
		n = dns_build_domain (&qdomain, dname);
		if (n == 0)
			return (NULL);
		break;
	default:
		return (NULL);
	}

	tgt = rp = dns_build_extend (pd, dns_labellen (qdomain)
		+ sizeof (qtype) + sizeof (qclass));

	qtype = htons (qtype);
	qclass = htons (qclass);

	memcpy (tgt, qdomain, dns_labellen (qdomain));
	tgt += dns_labellen (qdomain);
	memcpy (tgt, &qtype, sizeof (qtype));
	tgt += sizeof (qtype);
	memcpy (tgt, &qclass, sizeof (qclass));
	tgt += sizeof (qclass);

	free (qdomain);
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
 * TY_A   | char IP address     | 4 byte network byte ordered IP address
 * TY_PTR | char domain name    | encoded dns domain name
 * TY_NS  | char domain name    | encoded dns domain name
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
	case (TY_A):

		/* resolve the quad dotted IP address, then copy it into the
		 * rdata array
		 */

		ip_addr.s_addr = net_resolve ((char *) rdata);
		rdata_converted = xcalloc (1, sizeof (struct in_addr));
		memcpy (rdata_converted, &ip_addr.s_addr, sizeof (struct in_addr));
		rdlength = 4;

		break;

	case (TY_NS):
	case (TY_CNAME):
	case (TY_PTR):

		/* build a dns domain from the plaintext domain name
		 */
                n = dns_build_domain ((unsigned char **) &rdata_converted, (char *) rdata);
                if (n == 0)
			return (NULL);
		rdlength = n;

		break;

	default:
		return (NULL);
	}

	/* create a real dns domain from the plaintext query domain
	 */
	switch (type) {
	case (TY_PTR):
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

	/* little endian fights version big bad network byte order >:-D
	 */
	type = htons (type);
	class = htons (class);
	ttl = htonl (ttl);
	rdlength = htons (rdlength);

	memcpy (tgt, qdomain, dns_labellen (qdomain));
	tgt += dns_labellen (qdomain);
	memcpy (tgt, &type, sizeof (type));
	tgt += sizeof (type);
	memcpy (tgt, &class, sizeof (class));
	tgt += sizeof (class);
	memcpy (tgt, &ttl, sizeof (ttl));
	tgt += sizeof (ttl);
	memcpy (tgt, &rdlength, sizeof (rdlength));
	tgt += sizeof (rdlength);

	rdlength = htons (rdlength);
	memcpy (tgt, rdata_converted, rdlength);
	tgt += rdlength;

	free (qdomain);
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
	if (qclass != CL_IN || query == NULL)
		return (1);

	switch (qtype) {
	case (TY_A):	*query_dst = xstrdup (query);
			break;

	case (TY_PTR):	memset (label, '\0', sizeof (label));
			ip = (struct in_addr *) query;
			net_printipr (ip, label, sizeof (label) - 1);
			scnprintf (label, sizeof (label), ".IN-ADDR.ARPA");
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
	char	*b, *dst;	/* process pointer */

	/* a bit sanity checking :)
	 */
	if (strlen (domain) >= 255)
		return (0);

	dst = *denc = xcalloc (1, strlen (domain) + 1);

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

	sock = open_raw_sock(IPPROTO_RAW);
	if (sock == -1) {
		fprintf (stderr, "[drw] !ERROR! failed to aquire raw socket\n");
		return (1);
	}

	libnet_build_dns (	htons (dns_id),	/* dns id (the famous one :) */
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
				0,		/* id :) btw, what does 242 mean ? */
				0,		/* frag */
				64,		/* ttl */
				IPPROTO_UDP,	/* subprotocol */
				s_addr.s_addr,	/* spoofa ;) */
				d_addr.s_addr,	/* local dns querier */
				NULL,		/* payload already there */
				0,		/* same */
				buf);		/* build in packet buffer */

	libnet_do_checksum (buf, IPPROTO_UDP, UDP_H + DNS_H + dbuf_s);

	n = write_ip (sock, buf, UDP_H + IP_H + DNS_H + dbuf_s);
	if (n < UDP_H + IP_H + DNS_H + dbuf_s) {
		return (1);
	}

	close (sock);
	return (0);
}


