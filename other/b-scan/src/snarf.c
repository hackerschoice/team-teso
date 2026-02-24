#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef __USE_BSD
#define __USE_BSD
#endif
#ifndef __BSD_SOURCE
#define __BSD_SOURCE
#endif

#include <pcap.h>
#include <bscan/bscan.h>
#include <bscan/snarf.h>
#include <bscan/module.h>
#include <bscan/signal.h>

pcap_t *ip_socket;

/*
 * some global variables (modules need access etc)
 */
int dlt_len;
u_char *align_buf = NULL;
unsigned short ip_options = 0;
struct ip *ip;
struct Ether_header *eth;
u_int pcaplen, plen;
struct timeval *pts;

extern struct _opt *opt;
#ifdef HAVE_DLSYM
extern const int modcount;
extern const struct _mods mods[MAX_MODULES];
#endif


/*
 * answer on arp-request.
 */
static void
handle_arp (struct pcap_pkthdr *p, struct Ether_header *eth,
	    struct Arphdr *arp)
{
    u_long *ipdummy = (u_long *) arp->ar_tip;

    if (ntohs (arp->ar_op) != ARPOP_REQUEST)
	return;

#ifdef DEBUG
    printf ("ARPG request for %s\n", int_ntoa ((u_long) * ipdummy));
#endif
    if (*ipdummy == opt->nt.src)
	play_arpg (&opt->lnet, arp->ar_tip, (u_char *) opt->spf_smac,
		   (u_char *) arp->ar_sip, eth->ether_shost);
}


/*
 * called by libpcap 
 */
static void
filter_packet (u_char * u, struct pcap_pkthdr *p, u_char * packet)
{
    int c;
    static u_char *align_eth = NULL;

    if (p->len < (dlt_len + sizeof (struct Arphdr)))
	return;
    if (align_buf == NULL)
	align_buf = (u_char *) malloc (2048);
    if (align_eth == NULL)
	align_eth = (u_char *) malloc (42);

    memcpy ((char *) align_buf, (char *) (packet + dlt_len), p->caplen);
    memcpy ((char *) align_eth, (char *) packet, 42);
    eth = (struct Ether_header *) (align_eth);
    ip = (struct ip *) (align_buf);

    if (ntohs (eth->ether_type) == ETHERTYPE_ARP)
    {
	handle_arp (p, eth, (struct Arphdr *) (align_buf));
	return;
    }


    if (ntohs (eth->ether_type) != ETHERTYPE_IP)
	return;
    if (vrfy_ip (ip, p->len - dlt_len, &ip_options) != 0)
	return;
    if (ip->ip_dst.s_addr != opt->nt.src)
	return;
    if (p->len < (dlt_len + sizeof (*ip) + ip_options))
	return;

    /* here only 'my-ip' packets */

/* module entry point TWO */
/* packet is verifite, belongs to us + valid size */
/* return of module tell us if we should procced as usual or not */
/* DROP is valid here ! */

    plen = p->len;
    pcaplen = p->caplen; 
    pts = &p->ts;

#ifdef HAVE_DLSYM
    c = 0;
    while (c < modcount)
	mods[c++].callmdl (MOD_RCV, opt);
#endif

}

/*
 * init pcap network stuff
 * only called once on startup.
 * -1 = error
 * 0 = success
 */
int
pcap_init_net (char *iface, int promisc, char *filter, int *dltlen)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program prog;
    bpf_u_int32 network, netmask;

    if (iface == NULL)
    {
	iface = pcap_lookupdev (errbuf);
	if (iface == NULL)
	{
	    fprintf (stderr, "pcap_lookupdev: %s\n", errbuf);
	    return (-1);
	}
    }
    if (pcap_lookupnet (iface, &network, &netmask, errbuf) < 0)
    {
	fprintf (stderr, "pcap_lookupnet: %s\n", errbuf);
	return (-1);
    }
    ip_socket = pcap_open_live (iface, 1024, promisc, 1024, errbuf);
    if (ip_socket == NULL)
    {
	fprintf (stderr, "pcap_open_live: %s\n", errbuf);
	return (-1);
    }
    switch (pcap_datalink (ip_socket))
    {
    case DLT_EN10MB:
	*dltlen = 14;
	break;
    case DLT_SLIP:
	*dltlen = 16;
	break;
    default:
	*dltlen = 4;
	break;
    }
    if (pcap_compile (ip_socket, &prog, filter, 1, netmask) < 0)
    {
	fprintf (stderr, "pcap_compile: %s\n", errbuf);
	return (-1);
    }
    if (pcap_setfilter (ip_socket, &prog) < 0)
    {
	fprintf (stderr, "pcap_setfilter: %s\n", errbuf);
	return (-1);
    }

    return 0;
}


/*
 * called by main-thread.
 * doing all the snarf, arp-reply, tcp-stack stuff from here
 */
void *
do_snarf (void *iface)
{
/*    sigctl (SIG_SETALL, SIG_DFL);
    signal (SIGINT, SIG_IGN);
*/

    pcap_init_net (iface, 1, PCAP_FILTER, &dlt_len);

    /* the parent thread should at least w8 until we are ready to rumble */
    opt->flags &= ~OPT_W8SEMA;

    while (1)
	pcap_loop (ip_socket, -1, (pcap_handler) filter_packet, NULL);

    undo_snarf();	/*### fixme, somewhere else */

    pthread_exit(NULL);	/* no return values needed */
    return NULL;
}

/*
 * close everything that was initialized with do_snarf
 */
void
undo_snarf ()
{
    pcap_close (ip_socket);
}

