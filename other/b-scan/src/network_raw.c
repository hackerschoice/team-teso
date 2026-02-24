/*
 * raw network routines
 * libnet based (not yet ..but maybe in the future :>
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef __USE_BSD
#define __USE_BSD
#endif
#ifndef __BSD_SOURCE
#define __BSD_SOURCE
#endif
#include <libnet.h>
#include <bscan/network_raw.h>

static int netraw_lrand = 0;
#define LAME_RANDOM	(netraw_lrand = (netraw_lrand + (netraw_lrand>>1)))

/*
 * init all the network_raw stuff
 * return 0 on success, -1 on error
 */
int
init_network_raw ()
{
    /* seeded by init_vars/bscan.c */
    netraw_lrand = 1 + (int) (65335.0 * rand () / (RAND_MAX + 1.0));
    return (0);
}

/*
 * calc. checksum WITH carry flag.
 * call cksum = CKSUM_CARRY(sum);
 * we calculate only the initial checksum here.
 * we can use the result for all further packets
 */
int
in_cksum (unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    u_short *w = addr;
    u_short answer = 0;

    while (nleft > 1)
    {
	sum += *w++;
	nleft -= 2;
    }

    if (nleft == 1)		/* padding */
    {
	*(u_char *) (&answer) = *(u_char *) w;
	sum += answer;
    }

    return (sum);
}


/*
 * add ICMP_ECHO or ICMP_TSTAMP
 * len = len of payload
 * add ICMP-header to pkt
 */
void
add_icmpping (unsigned char *pkt, int len, int which)
{
    struct icmp *icmp = (struct icmp *) pkt;
    int sum;
    struct timeval tv;
    memset (icmp, 0, sizeof (*icmp));	/* sizeof(*icmp) = 28 */

    if (which == ICMP_ECHO)
      {
        icmp->icmp_type = ICMP_ECHO;
      }
    else if (which == ICMP_TSTAMP)
      {
	if (len < 13)
	  printf ("packet too small for timestamp request, lets blast the packets out anyway\n");
        icmp->icmp_type = ICMP_TSTAMP;
      }
    else
      printf ("Your kung-fu is bad!\n"); 

    icmp->icmp_hun.ih_idseq.icd_id = LAME_RANDOM;
    gettimeofday (&tv, NULL);
    memcpy (icmp->icmp_dun.id_data, &tv, sizeof (tv));

    sum = in_cksum ((u_short *) icmp, ICMP_SIZE + len);
    icmp->icmp_cksum = CKSUM_CARRY (sum);
}


/*
 * add udp-header [no checksum]
 * len = len of payload
 */
void
add_udphdr(unsigned char *pkt, struct net_tuple *nt, int len)
{
    struct udphdr udp;

    memset(&udp, 0, sizeof(udp));
    udp.uh_sport = nt->sport;
    udp.uh_dport = nt->dport;
    udp.uh_ulen = htons(len + UDP_SIZE);
    udp.uh_sum = 0;	/* no checksum !*/
    memcpy(pkt, &udp, sizeof(udp));
}


/*
 * len = len of payload
 */
void
add_tcphdr (unsigned char *pkt, struct net_tuple *nt, uint8_t flags, int len,
	    tcp_seq * seq, tcp_seq * ack)
{
    struct tcphdr tcp;
    struct tcphdr *tcpptr;
    struct _fakehead fakehead;
    int sum;

    memset (&tcp, 0, sizeof (tcp));
    memset (&fakehead, 0, sizeof (fakehead));
    tcp.th_dport = nt->dport;
    tcp.th_sport = nt->sport;
    fakehead.saddr = nt->src;
    fakehead.daddr = nt->dst;
    fakehead.zero = 0;
    fakehead.protocol = IPPROTO_TCP;
    fakehead.tot_len = htons (TCP_SIZE + len);
    sum = in_cksum ((u_short *) & fakehead, sizeof (fakehead));
    tcp.th_off = TCP_SIZE >> 2;
    if (seq != NULL)
	tcp.th_seq = *seq;
    else
	tcp.th_seq = LAME_RANDOM;
    if (ack != NULL)
	tcp.th_ack = *ack;
    tcp.th_flags |= flags;	/* ADD the flags */
    tcp.th_win = htons (0x3fff);
    memcpy (pkt, &tcp, sizeof (tcp));
    sum += in_cksum ((u_short *) pkt, sizeof (tcp) + len);
    tcpptr = (struct tcphdr *)pkt;
    tcpptr->th_sum = CKSUM_CARRY (sum);
}


/*
 * add's ipv4-header of 20 bytes without any options
 * - IPPROTO_TCP and 40 bytes total length
 */
void
add_iphdr (unsigned char *pkt, uint8_t ip_p, struct net_tuple *nt, int len)
{
    struct ip ip;
    memset (&ip, 0, IP_SIZE);
    ip.ip_hl = sizeof (ip) >> 2;
    ip.ip_v = 4;
    /*ip->tos = 0; */
    ip.ip_len = htons (len + IP_SIZE);	/* htons ? */
    /*ip->id = 0;                  done by kernel */
    /*ip->frag_off = 0; */
    ip.ip_ttl = 0xff;
    ip.ip_p = ip_p;
    /*.ip->check = 0;      done by kernel */
    ip.ip_src.s_addr = nt->src;
    ip.ip_dst.s_addr = nt->dst;
    memcpy (pkt, &ip, sizeof (ip));
}

/*
 * send out ipv4-packet
 * with data 'pkt' of length 'len'
 * returns the number of characters sent, or -1 if an error occured
 */
int
send_ipv4 (int sox, u_char * pkt, size_t len)
{
    struct sockaddr_in to;
    to.sin_family = AF_INET;
    memcpy (&to.sin_addr.s_addr, (pkt + 4 * 4), sizeof (u_long));
    return (sendto (sox, pkt, len, 0, (struct sockaddr *) &to, sizeof (to)));
}


/*
 * small/lame tcp userland stack
 * give 'best' tcp-answer to a tcp-packet
 * return 0 on success
 * payload + len are optional
 */
int
answer_tcp (int sox, struct ip *ip, struct tcphdr *tcp, uint8_t flags,
	    u_char * payload, uint len)
{
    static u_char *outpkt = NULL;
    static int msize = 0;
    struct net_tuple nt;
    tcp_seq outack;

    if (TCP_SIZE + IP_SIZE + len > msize)
    {
	outpkt = realloc (outpkt, TCP_SIZE + IP_SIZE + len);
	msize = TCP_SIZE + IP_SIZE + len;
    }

    if (outpkt == NULL)
	return (-1);
    if (ip == NULL)
	return (-1);
    if (tcp == NULL)
	return (-1);

    memset (outpkt, 0, TCP_SIZE + IP_SIZE + len);

    nt.sport = tcp->th_dport;
    nt.dport = tcp->th_sport;
    nt.src = ip->ip_dst.s_addr;
    nt.dst = ip->ip_src.s_addr;

    if (payload != NULL)
	memcpy (outpkt + TCP_SIZE + IP_SIZE, payload, len);

    outack = ntohl (tcp->th_seq) + ntohs (ip->ip_len) - (tcp->th_off << 2) -
	(ip->ip_hl << 2);
    if (tcp->th_flags & (TH_SYN | TH_FIN))
	outack++;

    outack = htonl (outack);
    add_tcphdr (outpkt + IP_SIZE, &nt, flags, len, &tcp->th_ack, &outack);

    add_iphdr (outpkt, IPPROTO_TCP, &nt, TCP_SIZE + len);

    send_ipv4 (sox, outpkt, IP_SIZE + TCP_SIZE + len);

    return (0);
}


/*
 * return 0 if ip-header is valid [length only]
 * len = length from the begin of the ip-header [20 for normal ip header]
 */
int
vrfy_ip (struct ip *ip, uint32_t len, u_short * ip_options)
{
    u_short _ip_options;

    if (len < sizeof (*ip))
	return (-1);

    _ip_options = ip->ip_hl << 2;
    if (_ip_options > len)
	return (-1);

    if (_ip_options > 0xefff)
        return -1;

    if (_ip_options < sizeof (*ip))
	_ip_options = 0;
    else
	_ip_options -= sizeof (*ip);

    *ip_options = _ip_options;
    return (0);
}


/*
 * len = len of tcp-header + tcp_options + tcp_data (from wire).
 * returns 0 if tcp-header is valid [length check only]
 * returns options
 * != 0 if something went wrong [header size etc]
 */
int
vrfy_tcp (struct tcphdr *tcp, uint32_t plen, u_short * tcp_options)
{
    u_short _tcp_options;

    if (plen < sizeof (*tcp))
	return (-1);

    _tcp_options = tcp->th_off << 2;
    if (_tcp_options > plen)
	return (-1);
    if (_tcp_options > 0xefff)   /* this is quite to large for me */
        return -1;

    if (_tcp_options <= sizeof (*tcp))
	_tcp_options = 0;
    else
	_tcp_options -= sizeof (*tcp);

    *tcp_options = _tcp_options;

    return (0);
}

int 
vrfy_udp (struct udphdr *udp, uint32_t len)
{

    if (len < sizeof(*udp))
	return (-1);

    return (0);
}

/*
 * decode NetworkVirtualTerminal Data 
 * data = the raw (nvt)-input
 * len = length of 'data'
 * ans = the nvt-answer (IAC don't)
 * anslen = the calculated anser length
 * res = the decoded nvt data (login: prompt etc)
 * reslen = the calculates decoded data length
 * All parameters must be given (NULL is not allowed)
 * and initialized
 * return -1 on failure
 * return 0 on success
 * rfc-will: anslen, reslen < len
 */
#define IACFOUND	0x01
#define DOFOUND		0x02
#define UNKNOWNOPT	0x04
#define SUBNEGO		0x08
#define CRFOUND		0x10

#define NVT_SE		0xf0
#define NVT_SB		0xfa
#define NVT_WILL	0xfb
#define NVT_WONT	0xfc
#define NVT_DO		0xfd
#define NVT_DONT	0xfe
#define IAC		0xff

int
decode_nvt(u_char *data, uint len, u_char *ans, uint *anslen, 
                                                 u_char *res, uint *reslen)
{
    u_char *ptr = data;
    u_char *ansptr = ans;
    u_char *resptr = res;
    u_char flags = 0;
    int i = 0;
    u_char c;

    if ( (data == NULL) || (ans == NULL) || (res == NULL))
	return(0);

    *anslen = 0;
    *reslen = 0;

    while (1)
    {
        if (i++ >= len)
	     break;
        c = *ptr++;

	if (flags & UNKNOWNOPT)
	{
	    flags = 0;
	    continue;
	}

        if (flags & IACFOUND)
	{
	    if (c == IAC)	/* IAC IAC */
	    {
	        *resptr++ = IAC;
	        flags = 0;	/* reset */
	        continue;
	    }

	    if (flags & SUBNEGO)
	    {
		if (c == NVT_SE)	/* subnegotiation end */
		    flags = 0;
		continue;
	    }

            if (flags & DOFOUND)
	    {
/* 3com switch test		if (c == 0x03)
		{
			*ansptr++ = IAC;
			*ansptr++ = NVT_DO;
			*ansptr++ = 0x03;
			*ansptr++ = IAC;
			*ansptr++ = NVT_WILL;
			*ansptr++ = 0x18;
			*ansptr++ = IAC;
			*ansptr++ = NVT_WILL;
			*ansptr++ = 0x1f;
			*ansptr++ = IAC;
			*ansptr++ = NVT_WILL;
			*ansptr++ = 0x20;
			*ansptr++ = IAC;
			*ansptr++ = NVT_WILL;
			*ansptr++ = 0x21;
			*ansptr++ = IAC;
			*ansptr++ = NVT_WILL;
			*ansptr++ = 0x22;
			*ansptr++ = IAC;
			*ansptr++ = NVT_WILL;
			*ansptr++ = 0x27;
			*ansptr++ = IAC;
			*ansptr++ = NVT_DO;
			*ansptr++ = 0x05;
			*ansptr++ = IAC;
			*ansptr++ = NVT_WILL;
			*ansptr++ = 0x23;
			*anslen = *anslen + 24;

		}
*/
	        *ansptr++ = IAC;
	        *ansptr++ = NVT_WONT;	/* me is dump - im a kid */
	        *ansptr++ = c;
		*anslen = *anslen + 3;
	        flags = 0;
	        continue;
	    }

	    if (c == NVT_SB)	/* subnegotiation */
	    {
		flags = SUBNEGO;
		continue;
	    }

	    if (c == NVT_DO)	/* DO ... */
	    { 
		flags |= DOFOUND;
		continue;
	    } else {
		flags = ~(IACFOUND | DOFOUND);
		flags |= UNKNOWNOPT;	/* skip next */
		continue;
	    }

	}

	if (flags & SUBNEGO)
	    continue;

	if (c == IAC)
	{
	    flags = IACFOUND;	/* just IAC */
	    continue;
	}

	if (flags & CRFOUND)
	{
	    if (c == '\0')
	    {
		flags &= ~CRFOUND;
		*res++ = '\r';
		*reslen = *reslen + 1;
		continue;
	    }
	    if (c == '\n')
	    {
		flags &= ~CRFOUND;
		*res++ = '\n';
		*reslen = *reslen + 1;
		continue;
	    }
	}

	if (c == '\r')
	{
	    flags |= CRFOUND;
	    continue;
	}
	
	*res++ = c;
	*reslen = *reslen + 1;

    }

    return(0);
}



