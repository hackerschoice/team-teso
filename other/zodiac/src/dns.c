/* zodiac - advanced dns spoofer
 *
 * by scut / teso
 *
 * dns handling routines
 *
 * including scut's leet dns packet decoder *welp* :-D
 *
 */

#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <ncurses.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "packet.h"
#include "dns.h"
#include "dnsid.h"
#include "dns-tag.h"
#include "dnsq.h"
#include "zodiac.h"
#include "output.h"


extern int	quiteness;

pthread_mutex_t	id_rmutex = PTHREAD_MUTEX_INITIALIZER;

static char	*types[] = {	NULL, "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG",
				"MR", "NULL", "WKS", "PTR", "HINFO", "MINFO", "MX", "TXT" };
static char	*rcodes[] = {	"OK", "EFORM", "EFAIL", "ENAME", "ENIMP", "ERFSD", NULL, NULL,
				NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };


/* dns_handle
 *
 * handle a dns packet with header pointed to by `dns_hdr' and data pointed
 * to by `dns_data'.
 *
 * do all necessary queue / decoding stuff
 */

void
dns_handle (ip_hdr *ip, udp_hdr *udp, dns_hdr *dns, unsigned char *dns_data, unsigned int plen)
{
	int		n;			/* temporary return value */
	unsigned char	*d_quer[SEG_COUNT_MAX];	/* query array */
	unsigned char	*d_answ[SEG_COUNT_MAX];	/* answer array */
	unsigned char	*d_auth[SEG_COUNT_MAX];	/* authority array */
	unsigned char	*d_addi[SEG_COUNT_MAX];	/* additional array */
	char		dns_p[2048];		/* output (for humans :) */

#ifdef	PDEBUG
	hexdump ("packet-dns", (unsigned char *) dns, 256);
#endif
	/* segmentify dns packet
	 */
	n = dns_segmentify (dns, dns_data, d_quer, d_answ, d_auth, d_addi);
	if (n != 0) {
		m_printf (ms, ms->windns, "FAILURE ON DNS PACKET DISASSEMBLY\n");
		return;
	}

	memset (dns_p, '\0', sizeof (dns_p));

	/* only print own packets if dns_print_own_packets is 1
	 */
	if (dns_print_own_packets == 1 || dns_tag_check_n (&ip->ip_src,
		&ip->ip_dst, htons (udp->uh_sport), htons (udp->uh_dport),
		htons (dns->id)) == 0)
	{
		if (quiteness == 0) {
			dns_printpkt (dns_p, sizeof (dns_p) - 1, ip, udp, dns,
				dns_data, d_quer, d_answ, d_auth, d_addi);
		}
	}

	/* do the real packet filtering stuff only if the packet isn't on the
	 * marked send queue :)
	 */
	if (dns_tag_check_n (&ip->ip_src, &ip->ip_dst, htons (udp->uh_sport),
		htons (udp->uh_dport), htons (dns->id)) == 0)
	{
		dq_handle (ip, udp, dns, plen);
	}

	/* return
	 */
	return;
} 


/* dns_p_print
 *
 * decode a dns packet pointed to by `dns' and `dns_data' to a human readable
 * form to the string pointed to by `os', with a maximum length of `len'
 *
 * return 0 on success
 * return 1 on failure
 */

int
dns_p_print (char *os, size_t len, dns_hdr *dns, unsigned char *d_quer[], unsigned char *d_answ[],
	unsigned char *d_auth[], unsigned char *d_addi[])
{
	int	n;

	scnprintf (os, len, "[%04x] ", ntohs (dns->id));

	if (dns->qr == 0) {
		/* print the query
		 */
		if (dns->opcode != 0 && dns->opcode != 1) {
			scnprintf (os, len, "unsupported opcode %02x %s", dns->opcode,
				(dns->opcode == 3) ? "ST " : "");
		} else {
			if (dns->opcode == 0)
				scnprintf (os, len, " Q ");
			else if (dns->opcode == 1)
				scnprintf (os, len, "IQ ");
		}
	} else if (dns->qr == 1) {
		char	*rcstr = NULL;

		/* authoritative answer ?
		 */
		if (dns->aa == 1)
			scnprintf (os, len, "AA ");
		else
			scnprintf (os, len, " A ");

		rcstr = rcodes[dns->rcode];
		scnprintf (os, len, "(%s)", (rcstr == NULL) ? "?" : rcstr);
	}

	for (n = 0; n < ntohs (dns->qdcount) && n < SEG_COUNT_MAX; n++) {
		if (n == 0)
			scnprintf (os, len, "\n\t-QUERIES (%hu)-", ntohs (dns->qdcount));
		scnprintf (os, len, "\n\t\t");
		dns_p_q ((unsigned char *) dns, os, len, d_quer[n]);
	}

	for (n = 0; n < ntohs (dns->ancount) && n < SEG_COUNT_MAX; n++) {
		if (n == 0)
			scnprintf (os, len, "\n\t-ANSWERS (%hu)-", ntohs (dns->ancount));
		scnprintf (os, len, "\n\t\t");
		dns_p_rr ((unsigned char *) dns, os, len, d_answ[n]);
	}
	for (n = 0; n < ntohs (dns->nscount) && n < SEG_COUNT_MAX; n++) {
		if (n == 0)
			scnprintf (os, len, "\n\t-AUTHORITY (%hu)-", ntohs (dns->nscount));
		scnprintf (os, len, "\n\t\t");
		dns_p_rr ((unsigned char *) dns, os, len, d_auth[n]);
	}
	for (n = 0; n < ntohs (dns->arcount) && n < SEG_COUNT_MAX; n++) {
		if (n == 0)
			scnprintf (os, len, "\n\t-ADDITIONAL (%hu)-", ntohs (dns->arcount));
		scnprintf (os, len, "\n\t\t");
		dns_p_rr ((unsigned char *) dns, os, len, d_addi[n]);
	}

	return (0);
}


/* dns_p_q
 *
 * print a dns query record pointed to by `wp' as a human readable string,
 * and append it to `os', which can have a maximum size of `len' characters.
 */

void
dns_p_q (unsigned char *dns_start, char *os, size_t len, unsigned char *wp)
{
	char		qname[256];
	char		*qt;
	u_short		qtype, qclass;

	memset (qname, '\0', sizeof (qname));
	dns_dcd_label (dns_start, &wp, qname, sizeof (qname) - 1, 5);

	/* get query type and class
	 */
	GETSHORT (qtype, wp);
	GETSHORT (qclass, wp);

	if (qtype <= 16)
		qt = types[qtype];
	else
		qt = NULL;

	scnprintf (os, len, "[t: %s (%04x)][c: %04x] %s", 
		(qt != NULL) ? qt : "-", qtype, qclass, qname);

	return;
}


/* dns_p_rdata
 *
 * print a resource record rdata field pointed to by `rdp' as a human readable
 * string `rdstr' with a maximum length `len', depending on rdata type `rtype'
 * the data pointed to by `rdp' has the length `rdlen'.
 *
 * return nothing
 */

void
dns_p_rdata (unsigned char *dns_start, char *rdstr, size_t len,
	u_short rtype, unsigned char *rdp, u_short rdlen)
{
	char		*ips;
	char		ipv4str[64];	/* temporary IP address string */
	struct in_addr	ip;
	unsigned char	*wps = rdp;

	memset (rdstr, '\0', len);

	switch (rtype) {
	case (T_A):
		memcpy (&ip, rdp, sizeof (struct in_addr));

		ips = ipv4_print (ipv4str, ip, 0);
		scnprintf (rdstr, len, "%s", ips);

		break;

	case (T_CNAME):
	case (T_NS):
	case (T_PTR):
		dns_dcd_label (dns_start, &wps, rdstr, len, 5);
		break;

	default:
		break;
	}

	return;
}


/* dns_p_rr
 *
 * print a dns resource record pointed to by `wp' as a human readable string,
 * and append it to `os', which can have a maximum size of `len' characters.
 */

void
dns_p_rr (unsigned char *dns_start, char *os, size_t len, unsigned char *wp)
{
	char	name[256], rdatas[256];
	char	*t;
	u_short	type, class, rdlen;
	u_long	ttl;

	/* decode label
	 */
	memset (name, '\0', sizeof (name));
	dns_dcd_label (dns_start, &wp, name, sizeof (name), 5);

	/* get type/class/ttl/rdlength/rdata
	 * then assign appropiate type description
	 */
	GETSHORT (type, wp);
	GETSHORT (class, wp);
	GETLONG (ttl, wp);
	GETSHORT (rdlen, wp);
	t = (type <= 16) ? types[type] : NULL;

	/* add decoded rdata info into rdatas
	 * different decoding depending on type
	 */
	dns_p_rdata (dns_start, rdatas, sizeof (rdatas), type, wp, rdlen);

	scnprintf (os, len, "[t: %s (%04x)][c: %04x][ttl: %lu][r: %04x] %s : %s",
		(t != NULL) ? t : "-", type, class, ttl, rdlen, name, rdatas);

	return;
}


/* dns_segmentify
 *
 * segmentify a dns datagram pointed to by `dns_hdr' and `dns_data' into it's
 * different parts, such as the query part (pointed to by `d_quer'), the
 * answer part (pointed to by `d_answ'), the authoritaty (pointed to by
 * `d_auth') and the additional information parts (pointed to by `d_addi').
 *
 * return 0 on success, and fill all the **-pointers to either NULL or data
 *                      within the `dns_data' array.
 */

int
dns_segmentify (dns_hdr *dns, unsigned char *dns_data,
	unsigned char *d_quer[], unsigned char *d_answ[], unsigned char *d_auth[],
	unsigned char *d_addi[])
{
	unsigned char	*wp;	/* work pointer */

	wp = dns_data;

	/* get queries, answers, authorities and additional information
	 */
	dns_seg_q (&wp, d_quer, htons (dns->qdcount), SEG_COUNT_MAX);
	dns_seg_rr (&wp, d_answ, htons (dns->ancount), SEG_COUNT_MAX);
	dns_seg_rr (&wp, d_auth, htons (dns->nscount), SEG_COUNT_MAX);
	dns_seg_rr (&wp, d_addi, htons (dns->arcount), SEG_COUNT_MAX);

	return (0);
}


/* dns_seg_q
 *
 * segmentify a query record of a dns datagram, starting at `wp', creating
 * an array of `c' number of pointers in `d_arry', truncating if it exceeds
 * a number of `max_size' records
 */

void
dns_seg_q (unsigned char **wp, unsigned char *d_arry[], int c, int max_size)
{
	int	count;

	for (count = 0; count < c && count < max_size; count++) {
		d_arry[count] = *wp;
		*wp += dns_labellen (*wp);	/* skip label */
		*wp += 2 * sizeof (u_short);	/* skip qtype/qclass */
	}
}


/* dns_seg_rr
 *
 * segmentify a resource record of a dns datagram, starting at `wp', creating
 * an array of `c' number of pointers in `d_arry', truncating if it exceeds
 * a number of `max_size' records
 */

void
dns_seg_rr (unsigned char **wp, unsigned char *d_arry[], int c, int max_size)
{
	int			count;
	unsigned long int	rdlen;

	for (count = 0; count < c && count < max_size; count++) {
		d_arry[count] = *wp;

		/* skip the label (most likely compressed)
		 */
		*wp += dns_labellen (*wp);

		/* skip the type, class, ttl
		 */
		*wp += 8 * sizeof (u_char);

		/* resource data length
		 */
		GETSHORT (rdlen, *wp);
		*wp += rdlen;
	}

	return;
}


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
		if ((*wp & INDIR_MASK) == INDIR_MASK) {
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


/* dns_dcd_label
 *
 * decode a label sequence pointed to by `qname' to a string pointed to by
 * `os', with a maximum length of `len' characters
 * after successful decoding it will update *qname, to point to the qtype
 * if the `dig' flag is > 0 the routine may allow to call itself recursively
 * at a maximum dig level of `dig'.
 * if `dig' is zero it is a recursive call and may not call itself once more.
 * `dns_start' is a pointer to the beginning of the dns packet, to allow
 * compressed labels to be decoded.
 *
 * return 0 on success
 * return 1 on failure
 */

int
dns_dcd_label (unsigned char *dns_start, unsigned char **qname, char *os, size_t len, int dig)
{
	unsigned char	*qn = *qname;

	while (*qn != '\0') {
		if ((*qn & INDIR_MASK) == INDIR_MASK) {
			int		offset;	/* compression offset */
			unsigned char	*tpt;	/*temporary pointer */

			if (dig == 0) {
				if (dns_start == NULL)
					return (1);

				m_printf (ms, ms->windns, "DNS attack, compr. flaw exploit attempt\n");
				return (1);
			}

			/* don't fuck with big bad endian
			 */
			
			offset = (((unsigned char) *qn) & ~0xc0) << 8;
			qn += 1;
			offset += (int) ((unsigned char) *qn);
			qn += 1;

			/* recursivly decode the label pointed to by the offset
			 * exploit here =)
			 */
			
			tpt = dns_start + offset;
			*qname = qn;

			return (dns_dcd_label (dns_start, &tpt, os, len, dig - 1));

		} else {
			char	label[65];

			memset (label, '\0', sizeof (label));
			memcpy (label, qn + 1, (*qn & ~INDIR_MASK));
			scnprintf (os, len, "%s", label);
		}

		qn += *qn + 1;
		if (*qn != 0)
			scnprintf (os, len, ".");
	}

	*qname = qn + 1;

	return (0);
}

#if 0

/*
 * My attempt at a version of dns_dcd_label that isn't recursive
 * note this version doesn't check for errors yet....like 
 * nasty compressed dns packets which cause infinite loops :-(
 * returns the length of the compressed domain name.
 * -smiler
 */

int
dns_dcd_label (unsigned char *dns_start, unsigned char **qname, char *os, size_t len, int dig)
{
	unsigned char	*qn = *qname,
			*start = qn,
			*end = NULL;
	unsigned char	labellen;
	unsigned short	off;

	while ((labellen = *qn++) != '\0') {
		if (labellen & INDIR_MASK != 0) {
			end = qn + 1;
			off = (unsigned char) (labellen & ~INDIR_MASK);
			off |= *qn++ << 8;
			/* I think this works on big endian too... */
			off = ntohs (off);
			qn = dns_start + off;
			continue;
		}
		memcpy (os, qn, labellen);
		os += labellen;
		qn += labellen;
		*os++ = '.';
	}

	if (end == NULL)
		end = qn;

	*os++ = 0;
	*qname = qn;

	return (end - start);
}

#endif


/* dns_printpkt
 *
 * print dns packet header pointed to by `dns' in human readable form
 * to dns window
 *
 * return nothing
 */

void
dns_printpkt (char *os, size_t osl, ip_hdr *ip, udp_hdr *udp, dns_hdr *dns, unsigned char *data,
	unsigned char *d_quer[], unsigned char *d_answ[], unsigned char *d_auth[],
       	unsigned char *d_addi[])
{
	char	ipsrc[64], ipdst[64];
	char	*is, *id;

	is = ipv4_print (ipsrc, ip->ip_src, 2);
	id = ipv4_print (ipdst, ip->ip_dst, 2);

	scnprintf (os, osl, "[%s:%5hu ->", is, ntohs (udp->uh_sport));
	scnprintf (os, osl, " %s:%5hu] ", id, ntohs (udp->uh_dport));

	/* print decoded dns packet to screen
	 */
	dns_p_print (os, osl, dns, d_quer, d_answ, d_auth, d_addi);
	m_printf (ms, ms->windns, "%s\n", os);

	return;
}

