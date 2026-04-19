/* snifflib
 *
 * by scut
 *
 */

#ifndef	Z_PACKET_H
#define	Z_PACKET_H

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <pcap.h>
#include <semaphore.h>
#include <pthread.h>

/* packet structures
 * parts ripped from snorts excellent include files
 */


typedef struct	eth_hdr
{
	u_char		eth_dst[6];	/* ethernet destination address (MAC) */
	u_char		eth_src[6];	/* ethernet source address (MAC) */
	u_short		eth_type;	/* enclosed packet type */
} eth_hdr;

typedef struct	ip_hdr
{
	u_char		ip_hlen:4, ip_ver:4;	/* IP header length, IP version */
	u_char		ip_tos;			/* IP type of service */
	u_short		ip_len;			/* IP data length */
	u_short		ip_id;			/* IP fragmentation identification */
	u_short		ip_off;			/* IP fragment offset */
	u_char		ip_ttl;			/* IP time to live */
	u_char		ip_proto;		/* subprotocol of enclosed packet */
	u_short		ip_csum;		/* IP header checksum */
	struct in_addr	ip_src;			/* IP source address */
	struct in_addr	ip_dst;			/* IP destination address */
} ip_hdr;

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH  0x08
#define TH_ACK  0x10
#define TH_URG  0x20

typedef struct	tcp_hdr
{
	u_short	th_sport;
	u_short	th_dport;
	u_long	th_seq;
	u_long	th_ack;
	u_char	th_x2:4, th_off:4;
	u_char	th_flags;
	u_short	th_win;
	u_short	th_sum;
	u_short	th_urp;
} tcp_hdr;


#define	ETHHDRSIZE	sizeof (eth_hdr);
#define	IPHDRSIZE	sizeof (ip_hdr);


void		pq_grind (void *sinfov, struct pcap_pkthdr *pkthdr, unsigned char *pkt);
void		pq_3whs (struct ip_hdr *ip, struct tcp_hdr *tcp);
void		pq_syns (char *ip_src_c, char *ip_dst_c, u_short dst_prt);

#endif

