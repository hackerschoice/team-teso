/*
 * Scan many hosts in parallel to see which are alive.
 */

#include "portscan.h"

#define LPORT 1104

#define RPC_H 56

int build_rpc_pmapgetport(u_int32_t find_vers,u_int32_t find_prog,unsigned char *buf);

int	id,
	querys; /* I should really put a mutex on this... */

u_char	recv_flags;

int p_check_rpc(unsigned char *buf)
{
	u_int32_t *ptr;

	ptr = (u_int32_t *)buf;

	ptr++; /*xid*/
	if (!*ptr++) return(0); /*msgtype*/
	if (*ptr++ != 0) return(0); /*replystat*/
	ptr++;ptr+=ntohl(*ptr)+1; /*flavor & body*/
	if (*ptr++) return (0); /*acceptstat*/
	return(ntohl(*ptr));
}

/* Yup, another callback */
void _flush_buffer(u_char *inf, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	udp_hdr 	*udp_h;
	icmp_hdr	*icmp_h;
	tcp_hdr		*tcp_h;
	ip_hdr		*ip_h;
	u_char		*data;
	u_int		port,
			ip_len;

	ip_h = (ip_hdr *)(pkt + dlt_len);
	ip_len = (ip_h->ip_hl << 2);

	if (opts.scanstyle == P_PING) {
		if (ip_h->ip_p != IPPROTO_ICMP) return;

		icmp_h = (icmp_hdr *)(pkt + dlt_len + IP_H);
		if (icmp_h->icmp_code == 0 && icmp_h->icmp_type == 0)
			if (icmp_h->icmp_id == htons(id)) {
				Print("%s\n",inet_ntoa(ip_h->ip_src));
				querys--;
			}
	} else if (opts.scanstyle == P_RPC) {
		if (ip_h->ip_p != IPPROTO_UDP) return;

		udp_h = (udp_hdr *)(pkt + dlt_len + ip_len);
		if (udp_h->uh_sport!=htons(111)) return;

		data = (unsigned char *)udp_h + UDP_H;
		querys--;
		if ((port=p_check_rpc(data)) != 0) 
			Print("%s:%d\n",inet_ntoa(ip_h->ip_src),port);
	} else {
		if (ip_h->ip_p != IPPROTO_TCP) return;

		tcp_h = (tcp_hdr *)(pkt + dlt_len + ip_len);

		if (tcp_h->th_dport!=htons(LPORT)) return;
		if (tcp_h->th_flags == recv_flags)	
			Print("%s open\n",inet_ntoa(ip_h->ip_src));
		else
			Print("%s closed\n",inet_ntoa(ip_h->ip_src));
		querys--;
	}
	return;
}

/* thread wrapper to _flush_buffer */
void *flush_buffer(void *arg)
{
	pcap_loop(pcap_d, -1, _flush_buffer, NULL);
	fprintf(stderr,"flush buffer returned!\n");
	return NULL;
}

int start_parallel_scan(void)
{
	pthread_t	tid;
	int 		len;
	unsigned char	pkt_buffer[IP_H + UDP_H + RPC_H], 
			proto;

	id = libnet_get_prand(PRu16);
	querys = 0;

	switch (opts.scanstyle) {
	case P_PING:
		libnet_build_icmp_echo(ICMP_ECHO, 0, id,
			0, NULL, 0, pkt_buffer + IP_H);
		len = IP_H + ICMP_ECHO_H;
		proto = IPPROTO_ICMP;
		break;
	case P_RPC:
		libnet_build_udp(LPORT, ports[0].port, NULL, RPC_H,
			pkt_buffer + IP_H);
		build_rpc_pmapgetport(1, rpc_prog, pkt_buffer + IP_H + UDP_H);
		len = IP_H + UDP_H + RPC_H;
		proto = IPPROTO_UDP;
		break;
	case P_SYN:
		libnet_build_tcp(LPORT, ports[0].port, libnet_get_prand(PRu32),
			0, TH_SYN, 0x512, 0, NULL, 0, pkt_buffer + IP_H); 
		len = IP_H + TCP_H;
		recv_flags = TH_SYN|TH_ACK;
		proto = IPPROTO_TCP;
		break;
	case P_LINUX:
		libnet_build_tcp(LPORT, ports[0].port, libnet_get_prand(PRu32),
			0, TH_SYN|TH_FIN, 0x512, 0, NULL, 0, pkt_buffer + IP_H);
		recv_flags = TH_SYN|TH_ACK|TH_FIN;
		len = IP_H + TCP_H;
		proto = IPPROTO_TCP;
		break;
	default:
		return(0);
	}

	if (pthread_create(&tid, NULL, flush_buffer, NULL))
		exit(1);

	do {
		libnet_build_ip(len, 0, libnet_get_prand(PRu16), 0,
			64, proto, local.s_addr, dest.s_addr,
			NULL, 0, pkt_buffer);

		libnet_do_checksum(pkt_buffer, proto, len - IP_H);
		libnet_do_checksum(pkt_buffer, IPPROTO_IP, len);
		libnet_write_ip(rawfd, pkt_buffer, len);

		querys++;
		usleep(30000);
	} while(nextip());

	usleep(1000000);
#ifndef NO_PTHREAD_CANCEL
	pthread_cancel(tid);
#endif
	pthread_join(tid, NULL);
	return(1);
}

int build_rpc_pmapgetport(u_int32_t find_vers,u_int32_t find_prog,unsigned char *buf)
{
	u_int32_t *ptr;

	ptr = (u_int32_t *)buf;

	*ptr++ = libnet_get_prand(PRu32);
	*ptr++ = 0;
	*ptr++ = htonl(2);      /*RPC_VER*/
	*ptr++ = htonl(100000); /*PMAP_PROG*/
	*ptr++ = htonl(2);      /*PMAP_VERS*/
	*ptr++ = htonl(3);      /*PMAPPROC_GETPORT*/

	*ptr++ = 0;
	*ptr++ = 0;
	*ptr++ = 0;
	*ptr++ = 0;

	*ptr++ = htonl(find_prog); 
	*ptr++ = htonl(find_vers);
	*ptr++ = htonl(IPPROTO_UDP);
	*ptr++ = htonl(0);
	return(56);
}

