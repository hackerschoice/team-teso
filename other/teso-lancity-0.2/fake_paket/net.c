/*
 *
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 *
 */
#include "net.h"
#include <sys/uio.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/if_packet.h>
#include <assert.h>

unsigned short ip_in_cksum(struct iphdr *iph, unsigned short *ptr, int nbytes)
{

	register long sum = 0;	/* assumes long == 32 bits */
	u_short oddbyte;
	register u_short answer;	/* assumes u_short == 16 bits */
	int pheader_len;
	unsigned short *pheader_ptr;
	
	struct pseudo_header {
		unsigned long saddr;
		unsigned long daddr;
		unsigned char null;
		unsigned char proto;
		unsigned short tlen;
	} pheader;
	
	pheader.saddr = iph->saddr;
	pheader.daddr = iph->daddr;
	pheader.null = 0;
	pheader.proto = iph->protocol;
	pheader.tlen = htons(nbytes);

	pheader_ptr = (unsigned short *)&pheader;
	for (pheader_len = sizeof(pheader); pheader_len; pheader_len -= 2) {
		sum += *pheader_ptr++;
	}
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {	/* mop up an odd byte, if necessary */
		oddbyte = 0;	/* make sure top half is zero */
		*((u_char *) & oddbyte) = *(u_char *) ptr;	/* one byte only */
		sum += oddbyte;
	}
	sum += (sum >> 16);	/* add carry */
	answer = ~sum;		/* ones-complement, then truncate to 16 bits */
	return (answer);
}

unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
	register long sum=0;        /* assumes long == 32 bits */
	u_short oddbyte;
	register u_short answer;    /* assumes u_short == 16 bits */
        
	while(nbytes>1){
        	sum+=*ptr++;
	        nbytes-=2;    
	}
	if(nbytes==1){              /* mop up an odd byte, if necessary */
        	oddbyte=0;              /* make sure top half is zero */
	        *((u_char *)&oddbyte)=*(u_char *)ptr;   /* one byte only */
        	sum+=oddbyte;
	}               
	sum+=(sum>>16);             /* add carry */
	answer=~sum;                /* ones-complement, then truncate to 16 bits */
	return(answer);
}


int send_tcp_packet(struct tcp_spec *ts)
{
	int tot_len, retval;
	char buf[2048], *data;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct msghdr msg;
	struct sockaddr_pkt spkt;
	struct iovec iov;
	
	eth = (struct ethhdr *) buf;
	memcpy(eth->h_dest, ts->dst_mac, ETH_ALEN);
	memcpy(eth->h_source, ts->src_mac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);
	
	ip = (struct iphdr *) (eth + 1);
	tcp = (struct tcphdr *) (ip + 1);
	data = (char *) (tcp + 1);
	memset(ip, 0, sizeof(struct iphdr));
	memset(tcp, 0, sizeof(struct tcphdr));
	memcpy(data, ts->data, ts->data_len);
	tcp->dest = ts->dport;
	tcp->source = ts->sport;
	tcp->doff = 5;
	tcp->psh = ts->psh;
	tcp->ack = ts->ack;
	tcp->rst = ts->rst;
	tcp->window = ts->window;
	ip->version = 4;
	ip->ihl = 5;
	tot_len = IPHDR + TCPHDR + ts->data_len;
	ip->tot_len = htons(tot_len);   	    /* 16-bit Total length */
    	ip->ttl = 64;                	    /* 8-bit Time To Live */
    	ip->protocol = IPPROTO_TCP;  	    /* 8-bit Protocol */
	ip->frag_off = htons(IP_DF);
    	ip->saddr = ts->saddr;     	    /* 32-bit Source Address */
    	ip->daddr = ts->daddr;     	    /* 32-bit Destination Address */
	ip->id = ts->id;
	ip->check = 0;
	ip->check = in_cksum((unsigned short *)ip, IPHDR);
	tcp->seq = ts->seq;
	if (ts->ack)
		tcp->ack_seq = ts->ack_seq;
	tcp->check = 0;
	tcp->check = ip_in_cksum(ip, (unsigned short *) tcp,
				      sizeof(struct tcphdr) + ts->data_len);
	spkt.spkt_family = 0;
	strcpy(spkt.spkt_device, eth_device);
	spkt.spkt_protocol = htons(ETH_P_IP);
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &spkt;
	msg.msg_namelen = sizeof(spkt);
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_base = buf;
	iov.iov_len = sizeof(struct ethhdr) + tot_len;

	retval = sendmsg(linksock, &msg, 0);
	if (retval < 0)
	    perror( "sendmsg()" );
	return retval;
}

int send_icmp_packet(struct icmp_spec *is)
{
	int tot_len, retval;
	char buf[2048], *data;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct icmphdr *icmp;
	struct msghdr msg;
	struct sockaddr_pkt spkt;
	struct iovec iov;
	int data_len;
	
	eth = (struct ethhdr *) buf;
	memcpy(eth->h_dest, is->dst_mac, ETH_ALEN);
	memcpy(eth->h_source, is->src_mac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);
	
	ip = (struct iphdr *) (eth + 1);
	icmp = (struct icmphdr *) (ip + 1);
	data = (char *) (icmp + 1);
	memset(ip, 0, sizeof(struct iphdr));
	memset(icmp, 0, sizeof(struct icmphdr));
	if (!is->data_len) {
		memset(data, 0, 64);
		data_len = 64;
	} else {
		memcpy(data, is->data, is->data_len);
		data_len = is->data_len;
	}
	ip->version = 4;
	ip->ihl = 5;
	tot_len = IPHDR + sizeof(struct icmphdr) + data_len;
	ip->tot_len = htons(tot_len);
	ip->ttl = 64;
	ip->protocol = IPPROTO_ICMP;
	ip->saddr = is->src_addr;
	ip->daddr = is->dst_addr;
	ip->frag_off = 0;//htons(IP_DF);
	ip->id = 0;
	ip->check = 0;
	ip->check = in_cksum((unsigned short *)ip, IPHDR);

	assert(sizeof(struct icmphdr) == 8);
	icmp->type = is->type;
	icmp->code = is->code;
	icmp->un.gateway = is->un.res ;

	icmp->checksum = 0;
	icmp->checksum = in_cksum((unsigned short *)icmp, 
				  sizeof(struct icmphdr) + data_len);

	spkt.spkt_family = 0;
	strcpy(spkt.spkt_device, eth_device);
	spkt.spkt_protocol = htons(ETH_P_IP);
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &spkt;
	msg.msg_namelen = sizeof(spkt);
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_base = buf;
	iov.iov_len = sizeof(struct ethhdr) + tot_len;
	retval = sendmsg(linksock, &msg, 0);
	if (retval < 0)
	    perror( "sendmsg()" );
	return retval;
}

void send_icmp_request(unsigned int src_addr, unsigned int dst_addr,
		       char *src_mac, char *dst_mac, unsigned short seq)
{
	struct icmp_spec icmp;
	
	icmp.src_addr = src_addr;
	icmp.dst_addr = dst_addr;
	icmp.src_mac = src_mac;
	icmp.dst_mac = dst_mac;
	icmp.type = 8;
	icmp.code = 0;
	icmp.un.idseq.id = htons(0xAA);
	icmp.un.idseq.seq = seq;
	icmp.data = NULL;
	icmp.data_len = 0;
	
	send_icmp_packet(&icmp);
}


int send_arp_packet(struct arp_spec *as)
{
	char buf[512];
	int retval;
	struct msghdr msg;
	struct iovec  iov;
	struct ethhdr *eth;
	struct arphdr *arp;
	struct arpeth_hdr *arpeth;
	
	struct sockaddr_pkt spkt;

	eth = (struct ethhdr *) buf;
	memcpy(eth->h_dest, as->dst_mac, ETH_ALEN);
	memcpy(eth->h_source, as->src_mac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_ARP);

	arp = (struct arphdr *) (eth + 1);
	arp->ar_hrd = htons(ARPHRD_ETHER);
	arp->ar_pro = htons(ETH_P_IP);
	arp->ar_hln = ETH_ALEN;
	arp->ar_pln = 4;	/* IP */
	arp->ar_op = as->oper;
	
	arpeth = (struct arpeth_hdr *)(arp + 1);
	memcpy(arpeth->ar_sha, as->sender_mac, ETH_ALEN);
	*(unsigned long *)arpeth->ar_sip = as->sender_addr;
	memcpy(arpeth->ar_tha, as->target_mac, ETH_ALEN);
	*(unsigned long *)arpeth->ar_tip = as->target_addr;

	spkt.spkt_family = 0;
	strcpy(spkt.spkt_device, eth_device);
	spkt.spkt_protocol = htons(ETH_P_ARP);
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &spkt;
	msg.msg_namelen = sizeof(spkt);
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_base = buf;
	iov.iov_len = sizeof(struct ethhdr) + sizeof(struct arphdr) + sizeof(struct arpeth_hdr);

	retval = sendmsg(linksock, &msg, 0);
	if (retval < 0)
	    perror( "sendmsg()" );
	return retval;
}

