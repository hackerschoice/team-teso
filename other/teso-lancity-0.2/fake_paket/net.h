/*
 *
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 *
 */
#ifndef __NET_H
#define __NET_H

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define max(a, b)	((a) > (b) ? (a) : (b))
#define min(a, b)	((a) > (b) ? (b) : (a))

#define IP_DF           0x4000          /* Flag: "Don't Fragment"       */
#define BUFSIZE		512
#define IPHDR		20
#define TCPHDR		20

extern int linksock;
extern char *eth_device;
extern int verbose;
extern unsigned char my_eth_mac[ETH_ALEN];
extern unsigned int my_eth_ip;

enum PACKET_TYPE {
		PACKET_NONE = 0, 
		PACKET_TCP = 1,
		PACKET_UDP = 2,
		PACKET_ICMP = 3, 
		PACKET_ARP = 4
};

#define MAX_MODULES		8
#define MODULE_DUMP_CONN	0
#define MODULE_HIJACK_CONN	1
#define MODULE_RSTD		2
#define MODULE_ARP_SPOOF	3
#define MODULE_SNIFF		4
#define MODULE_HOSTUP		5
#define MODULE_ARPSPOOF_TEST 	6

#define MAX_PORTS		16


/*
 * all is in network byte order
 */


struct arpeth_hdr {
        unsigned char           ar_sha[ETH_ALEN];       /* sender hardware address      */
        unsigned char           ar_sip[4];              /* sender IP address */
        unsigned char           ar_tha[ETH_ALEN];       /* target hardware address      */
        unsigned char           ar_tip[4];              /* target IP address */
};


#define ALIGNPOINTERS_ETH(packet, ethh) { \
	(ethh) = (struct ethhdr *) ((packet)->p_raw); \
}

#define ALIGNPOINTERS_IP(ethh, iph) { \
	(iph) = (struct iphdr *) ((char *)ethh + sizeof(struct ethhdr)); \
}

#define ALIGNPOINTERS_ARP(ethh, arph) { \
	(arph) = (struct arphdr *) ((char *)ethh + sizeof(struct ethhdr)); \
}

#define ALIGNPOINTERS_TCP(iph, tcph, pdata) { \
	(tcph) = (struct tcphdr *) (((char *) iph) + (iph->ihl << 2)); \
	(pdata) = ((char *) tcph) + (tcph->doff << 2); \
}

#define ALIGNPOINTERS_UDP(iph, udph, pdata) { \
	(udph) = (struct udphdr *) (((char *) iph) + (iph->ihl << 2)); \
	(pdata) = ((char *) udph) + sizeof(struct udphdr); \
}

#define ALIGNPOINTERS_ICMP(iph, icmph, pdata) { \
	(icmph) = (struct icmphdr *) (((char *) iph) + (iph->ihl << 2)); \
	(pdata) = ((char *) icmph) + sizeof(struct icmphdr); \
}

#define IP_DATA_LENGTH(iph) (ntohs((iph)->tot_len) - ((iph)->ihl << 2))
#define TCP_DATA_LENGTH(iph, tcph) (IP_DATA_LENGTH(iph) - ((tcph)->doff << 2))


/*
 * net.c
 * 
 * all have to be filled with network byte order
 */
struct tcp_spec {
	unsigned long saddr;
	unsigned long daddr;
	unsigned short sport;
	unsigned short dport;
	char *src_mac;
	char *dst_mac;
	unsigned long seq;
	unsigned long ack_seq;
	unsigned short window;
	unsigned short id;
	int ack;
	int rst;
	int psh;
	char *data;
	int data_len;
};

int send_tcp_packet(struct tcp_spec *ts);


struct icmp_spec {
	unsigned int src_addr;
	unsigned int dst_addr;
	char *src_mac;
	char *dst_mac;
	
	short type;
	short code;
	union {
		struct {
			unsigned short id;
			unsigned short seq;
		} idseq;
		unsigned int res;
	} un;
	
	void *data;
	int  data_len;
};

int send_icmp_packet(struct icmp_spec *is);
void send_icmp_request(unsigned int src_addr, unsigned int dst_addr,
		       char *src_mac, char *dst_mac, unsigned short seq);

struct arp_spec {
	char *src_mac;
	char *dst_mac;
	
	int oper;
	char *sender_mac;
	unsigned long sender_addr;
	char *target_mac;
	unsigned long target_addr;
};

int send_arp_packet(struct arp_spec *as);

#endif
