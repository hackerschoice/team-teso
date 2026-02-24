#include <stdio.h>
#include "dnslib.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int
dns_mklongdn (u_char *cp, int length)
{
	int	orig_len = length;

	if (length == 0)
		return (0);

again:
	if (length <= 64) {		
		if (length == 1) {
			fprintf (stderr, "fuck...\n");
			exit (-1);
		}
		*cp++ = length - 1;
		memset (cp, 'A', length - 1);
		cp += length - 1;
		return (orig_len);
	} else {
		if (length == 65) {
			/* we don't want just 1 byte left over */
			*cp++ = 0x3e;
			memset (cp, 'A', 0x3f);
			cp += 0x3f;
			length -= 0x3f;
		} else {
			*cp++ = 0x3f;
			memset (cp, 'A', 0x3f);
			cp += 0x3f;
			length -= 0x40;
		}
		goto again;
	}

	return (orig_len);
}

static void
hex_dump (unsigned char *buf, int len)
{
	if (len > 0x50)
		len = 0x50;
	while (len--) {
		fprintf (stderr, "%01x ", *buf++);
	}
}

void
dns_debug (unsigned char *buf)
{
	HEADER *hdr;
	unsigned char *orig = buf;
	unsigned char tmp[1024];
	int	i;

	hdr = (HEADER *)buf;

	fprintf (stderr,
		"qr = %d\n"
		"id = %d\n"
		"opcode = %d\n"
		"aa = %d\n"
		"tc = %d\n"
		"rd = %d\n"
		"ra = %d\n"
		"rcode = %d\n"
		"qdcount = %d\n"
		"ancount = %d\n"
		"nscount = %d\n"
		"arcount = %d\n",
		hdr->qr, ntohs(hdr->id), hdr->opcode, hdr->aa, hdr->tc,
		hdr->rd, hdr->ra, hdr->rcode,
		ntohs (hdr->qdcount), ntohs(hdr->ancount),
		ntohs (hdr->nscount), ntohs (hdr->arcount));

	buf += NS_HFIXEDSZ;

	i = ntohs (hdr->qdcount);
	while (i--) {
		u_int16_t type, klass;

		buf += dns_dn_expand (buf, tmp, orig);
		NS_GET16 (type, buf);
		NS_GET16 (klass, buf);
		fprintf (stderr, "\n%s %d %d\n", tmp, type, klass); 
	}

	i = ntohs (hdr->ancount) + ntohs (hdr->nscount) + ntohs (hdr->arcount);
	while (i--) {
		u_int16_t type, klass, rdlength;
		u_int32_t ttl;

		buf += dns_dn_expand (buf, tmp, orig);
		fprintf (stderr, "%s ", tmp);
		NS_GET16 (type, buf);
		NS_GET16 (klass, buf);
		NS_GET32 (ttl, buf);
		NS_GET16 (rdlength, buf);

		fprintf (stderr, "%d %d ", type, klass);
		switch (type) {
		case ns_t_a:
			fprintf (stderr, "%s\n", inet_ntoa (*(struct in_addr *)buf));
			break;
		case ns_t_ptr:
		case ns_t_cname:
		case ns_t_ns:
			dns_dn_expand (buf, tmp, orig);
			fprintf (stderr, "%s\n", tmp);
			break;
		default:
			hex_dump (buf, rdlength);
		}
		buf += rdlength;
	}

}

/* make a full dns query including header. Returns length of packet.
 */
int
dns_mkquery (char *name, u_char *buffer, u_int16_t id, ns_type type, ns_class klass)
{
	HEADER *head;

	head = (HEADER *)buffer;

	bzero (head, NS_HFIXEDSZ);
	head->id = htons (id);
	head->qr = 0;
	head->opcode = 0;
	head->aa = 0;
	head->tc = 0;
	head->rd = 1;
	head->ra = 0;
	head->rcode = 0;
	head->qdcount = htons (1);
	head->ancount = 0;
	head->nscount = 0;
	head->arcount = 0;

	return (dns_mkqbody (name, buffer + NS_HFIXEDSZ, type, klass) + NS_HFIXEDSZ);
}

/* convert a \0-terminated string to a DNS domain name.
 * www.yahoo.com(.) => \003www\005yahoo\003\com\000
 */
int
dns_mkdn (char *in, u_char *out)
{
	char *start = in, c = 0;
	int n = strlen (in);

	in += n - 1;
	out += n + 1;

	*out-- = 0;

	n = 0;
	while (in >= start) {
		c = *in--;
		if (c == '.') {
			*out-- = n;
			n = 0;
		} else {
			*out-- = c;
			n++;
		}
	}

	if (n)
		*out-- = n;

	return (strlen (out + 1) + 1);
}

/* simple function for making a, ptr and ns resource records
 * doesn't support more complicated stuph.
 */

int 
dns_mkrr (char *name, u_char *buf, ns_type type, ns_class klass,
	char *rdata, u_int32_t ttl)
{
	int		n;
	rrec_body	*rec;
	u_char		*ptr = buf;

	/* name the resource record pertains too */
	ptr += dns_mkdn (name, ptr);
	rec = (rrec_body *)ptr;
	rec->type = htons (type);
	rec->klass = htons (klass);
	rec->ttl = htonl (ttl);
	rec->rdlength = 0;
	ptr += 10;

	switch (type) {
	case ns_t_a:
		*(u_int32_t *)ptr = inet_addr (rdata);
		rec->rdlength = htons (4);
		ptr += 4;
		break;
	case ns_t_ptr:
	case ns_t_ns:
		n = dns_mkdn (rdata, ptr);
		ptr += n;
		rec->rdlength = htons (n);
		break;
	default:
		/**/
	}
	return (ptr - buf);
}

/* make just the body of a DNS query.
 */
int
dns_mkqbody (char *name, u_char *buffer, ns_type type, ns_class klass)
{
	int len;

	len = dns_mkdn (name, buffer);
	buffer += len;
	NS_PUT16 (type, buffer);
	NS_PUT16 (klass, buffer);
	return (len + 4);
}


/* uncompress compressed dns names. ugh.
 * works for normal formatted dns names too..
 * returns the length of the first part of the compressed name (i.e.
 * before redirection).
 */

int
dns_dn_expand (u_char *in, char *out, u_char *msg)
{
	u_char *start = in, *end = NULL;
	u_char len;
	u_int16_t off;

	while ((len = *in++)) {
		if (len & NS_CMPRSFLGS) {
			if (end == NULL)
				end = in + 1;
			off = (len & ~NS_CMPRSFLGS);
			off |= *in++ << 8;
			off = ntohs (off);
			in = msg + off;
			continue;
		}
		memcpy (out, in, len);
		out += len;
		in  += len;
		*out++ = '.';
	}
	if (end == NULL)
		end = in;
	*out++ = 0;
	return (end - start);
}
