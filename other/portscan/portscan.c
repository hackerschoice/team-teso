/*
 * Here the various TCP port scans are performed, as well as a UDP RPC
 * scan.
 * Now supports threads, where one thread sends the packets and the other 
 * receives the packets, adjusting the rtt var accordingly.
 */

#include "portscan.h"
#include <stdlib.h>

#define LPORT 1104

port 	*find_port(u_int16_t port);
void	*check_response(void *arg);
int	check_resends(unsigned char flags);

int 	onfly,
	checked;
u_char	negative,
	flags;

unsigned char pkt_buffer[IP_H + TCP_H];

void do_send_tcp(u_int16_t port, u_int32_t seq)
{
	libnet_build_tcp(LPORT, port, seq, 0, flags, 0x512, 0, NULL, 0,
		pkt_buffer + IP_H);

	libnet_do_checksum(pkt_buffer, IPPROTO_TCP, TCP_H);
	libnet_do_checksum(pkt_buffer, IPPROTO_IP, IP_H);

	if (libnet_write_ip(rawfd, pkt_buffer, IP_H + TCP_H) < 0) {
		perror("Couldn't write packet");
		exit(-1);
	}
	return;
}

/*
 * Just do the actual scan now.
 * Send the packets, waiting rtt/2 between each send. If there are
 * MAXPACKET querys on the net, then wait until some of them are resolved.
 * This is probably the best way to stop over-sending of packets and
 * flooding the connection. Also, if we hit the MAXPACKET limit, should
 * we make rtt longer ?
 */

int port_scan(void) 
{
	port 		*port;
	unsigned char 	odd = 0;
	pthread_t	tid;
	int		curr_port,
			ctr;

	srand(time(NULL));

	libnet_build_ip(TCP_H, 0, libnet_get_prand(PRu16),
		0, 64, IPPROTO_TCP, local.s_addr, dest.s_addr,
		NULL, 0, pkt_buffer);

	switch (opts.scanstyle) {
	case SYN:
		flags = TH_SYN;
		negative = 0;
		break;
	case FIN:
		flags = TH_FIN;
		negative = 1;
		break;
	case XMAS:
		flags = TH_FIN|TH_URG|TH_PUSH;
		negative = 1;
		break;
	default: 
		printf("Fucked scanstyle\n");
		exit(-1);
	}

	for (ctr = 0;ctr < portcount;ctr++) 
		ports[ctr].result = P_NOCHECK;

	curr_port = checked = onfly = 0;

	if (pthread_create(&tid,NULL,check_response,NULL))
			exit(1);

	while (checked < portcount) {
		port = &ports[curr_port];
		if ((onfly<MAXPACKETS) && (port->result == P_NOCHECK)) {
			onfly++;
			port->result = P_CHECKING;
			do_send_tcp(port->port, curr_port + 1);
			gettimeofday(&port->send,NULL);
			port->numsends = 1;
			curr_port++;
			if (curr_port >= portcount) curr_port = 0;
		}

		usleep(rtt);
		if (odd) check_resends(flags);
		odd = ! odd;
	}
	usleep(100000);
	pthread_detach(tid);
#ifndef NO_PTHREAD_CANCEL /* damn freebsd... */
	pthread_cancel(tid);
#endif
	return(1);
}

int check_resends(unsigned char flags)
{
	int 		ctr;
	unsigned long	diff;
	struct timeval	now;

	gettimeofday(&now,NULL);
	for (ctr = 0;ctr < portcount;ctr++) {
		if (ports[ctr].result != P_CHECKING)
			continue;

		diff = TIMEVAL_SUBTRACT(now,ports[ctr].send);
		if (diff <= (rtt*3)) continue;
		if (ports[ctr].numsends < MAXSENDS) {
			do_send_tcp(ports[ctr].port, ctr + 1);
			gettimeofday(&ports[ctr].send,NULL);
			ports[ctr].numsends++;
		} else {
			onfly--;
			checked++;
			if (negative) {
				ports[ctr].result = P_OPEN;
				if (opts.verbose)
					printf("Port %d is open\n",ports[ctr].port);
			} else {
				ports[ctr].result = P_DONE;
			}
		}
	}
	return(1);
}

void _check_response(u_char *inf, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	ip_hdr		*ip;
	tcp_hdr		*tcp;
	u_int16_t	sport;
	u_int32_t	ack;
	port		*ptr;
	struct timeval	now;

	ip = (ip_hdr *)(pkt + dlt_len);
	if (ip->ip_p != IPPROTO_TCP) return;
	if (ip->ip_src.s_addr != dest.s_addr) return;
	tcp = (tcp_hdr *)(pkt + dlt_len + (ip->ip_hl << 2));

	if (tcp->th_dport != htons(LPORT)) return;

	sport = ntohs(tcp->th_sport);
	ack = ntohl(tcp->th_ack);

	if (opts.scanstyle == TH_SYN) {
		ack -= 2;
		if ((ack < 0) || (ack > portcount)) 
			return;
		ptr = &ports[ack];
	} else if ((ptr = find_port(sport)) == NULL) {
		return;
	}

	gettimeofday(&now, NULL);
	rtt = TIMEVAL_SUBTRACT(now, ptr->send);
	if (rtt < 0) rtt = 50000;
	if (negative) {
		ptr->result = P_CLOSED;
		onfly--;
		checked++;
	} else if (tcp->th_flags & TH_RST) {
		ptr->result = P_CLOSED;
		onfly--;
		checked++;
	} else if (tcp->th_flags == (TH_SYN|TH_ACK)) {
		ptr->result = P_OPEN;
		if (opts.verbose)
			printf("Port %d is open\n", ptr->port);
		onfly--;
		checked++;
	}
	return;
}

void *check_response(void *arg)
{
	pcap_loop(pcap_d, -1, _check_response, NULL);
	return NULL;
}

port *find_port(u_int16_t port)
{
	int ctr;

	for (ctr = 0; ctr < portcount; ctr++)
		if (ports[ctr].port == port) return(&ports[ctr]);

	return(NULL);
}

int build_rpc(char *buf,u_int32_t prog)
{
	u_int32_t *ptr;

	ptr = (u_int32_t *)buf;

	*ptr++ = rand(); /* xid */
	*ptr++ = 0;        /* msg_type */
	*ptr++ = htonl(2); /* rpc_ver */
	*ptr++ = htonl(prog);
	*ptr++ = htonl(1); /* ver */
	*ptr++ = 0;        /* proc_ping */
	/* auth */
	*ptr++ = 0;
	*ptr++ = 0;
	*ptr++ = 0;
	*ptr++ = 0;
	return(40);
}

void do_send_udp(u_int16_t port)
{
	libnet_build_udp(LPORT, port, NULL, 40, pkt_buffer + IP_H);

	build_rpc(pkt_buffer + IP_H + UDP_H, rpc_prog);

        libnet_do_checksum(pkt_buffer, IPPROTO_UDP, UDP_H + 40);
	libnet_do_checksum(pkt_buffer, IPPROTO_IP, IP_H + UDP_H + 40);

        if (libnet_write_ip(rawfd, pkt_buffer, IP_H + UDP_H + 40) < 0) {
                perror("Couldn't write packet");
                exit(-1);
        }
        return;
}



int check_rpc_resends(void)
{
	int		ctr;
	unsigned long	diff;
	struct timeval	now;

	gettimeofday(&now,NULL);

	for (ctr = 0;ctr < portcount;ctr++) {
		if (ports[ctr].result != P_CHECKING)
			continue;

		diff = TIMEVAL_SUBTRACT(now,ports[ctr].send);
		if (diff<=(rtt*2)) continue;
		if (ports[ctr].numsends < MAXSENDS) {
			/* do send packet */
			do_send_udp(ports[ctr].port);
			gettimeofday(&ports[ctr].send, NULL);
			ports[ctr].numsends++;
		} else {
			onfly--;
			checked++;
			ports[ctr].result = P_CLOSED;
		}
	}
	return(1);
}

void _check_rpc(u_char *inf, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	ip_hdr		*ip;
	icmp_hdr	*icmp;
	udp_hdr		*udp;
	port		*ptr;
	struct timeval	now;
	u_int16_t	sport;

	gettimeofday(&now,NULL);

	ip = (ip_hdr *)(pkt + dlt_len);

	if (ip->ip_src.s_addr != dest.s_addr) return;
	if (ip->ip_p != IPPROTO_UDP) goto skip;

	udp = (udp_hdr *)(pkt + dlt_len + (ip->ip_hl << 2));
	if (ntohs(udp->uh_dport)!=LPORT) return;
	sport = ntohs(udp->uh_sport);
		
	if (!(ptr = find_port(sport))) return;

	if (ptr->result != P_CHECKING) return;

	rtt = TIMEVAL_SUBTRACT(now,ptr->send);
	ptr->result = P_OPEN;
	onfly--;
	checked++;

skip:
	/* now do ICMP unreachable replys */
	gettimeofday(&now,NULL);
	if (ip->ip_p != IPPROTO_ICMP) return;

	icmp = (icmp_hdr *)(pkt + dlt_len + (ip->ip_hl << 2));
	ip = (ip_hdr *)((unsigned char *)icmp + ICMP_UNREACH_H);
	udp = (udp_hdr *)((unsigned char *)ip+(ip->ip_hl<<2));
	if ((icmp->icmp_type!=3) || (icmp->icmp_type!=3))
		return;
	if ((ptr = find_port(ntohs(udp->uh_dport))) == 0)
		return;
	ptr->result = P_CLOSED;
	onfly--;
	checked++;
	return;
}

void *check_rpc(void *arg)
{
	pcap_loop(pcap_d, -1, _check_rpc, NULL);
	fprintf(stderr,"check_rpc returned!\n");
	return NULL;
}

int rpc_scan(void)
{
	port		*port;
	int		curr_port,
			ctr;
	pthread_t	tid;

	libnet_build_ip(UDP_H + 40, 0, libnet_get_prand(PRu16),
		0, 64, IPPROTO_UDP, local.s_addr, dest.s_addr,
		NULL, 0, pkt_buffer);

	for (ctr = 0; ctr < portcount; ctr++)
		ports[ctr].result = P_NOCHECK;

	curr_port = checked = onfly = 0;

	if (pthread_create(&tid,NULL,check_rpc,NULL))
		exit(-1);

	while (checked < portcount) {
		port = &ports[curr_port];
		if ((onfly < MAXPACKETS) && (port->result == P_NOCHECK)) {
			onfly++;
			port->result = P_CHECKING;
			do_send_udp(port->port);
			gettimeofday(&port->send,NULL);
			port->numsends = 1;
			curr_port++;
			if (curr_port >= portcount) curr_port = 0;
		}
		usleep(rtt/2);
		check_rpc_resends();
	}
	return(1);
}
