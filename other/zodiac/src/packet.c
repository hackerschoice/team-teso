/* zodiac - advanced dns spoofer
 *
 * packet handling and queueing routines
 * by scut
 * -Smiler
 *   Changed pq_grind to remove link layer. Changed other functions to 
 *   accept ip packets instead of ethernet packets.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>
#include <pthread.h>
#include <pcap.h>
#include "common.h"
#include "packet.h"
#include "output.h"
#include "sniff.h"
#include "zodiac.h"
#include "dns.h"
#include "dnsid.h"
#include "dns-tag.h"


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
	sniff_info		*sinfo = (sniff_info *) sinfov;

	if (sinfo->device->linktype == DLT_EN10MB) {
		if (((eth_hdr *)pkt)->ether_type != htons(ETHERTYPE_IP))
			goto pq_glend;
	}
	pkt += sinfo->device->linkhdrlen;
	pkthdr->caplen -= sinfo->device->linkhdrlen;

	/* check if it is a IP/UDP packet, if not, silently skip it
	 */
	id_qprint (ms, ms->winid);
	if (pq_filter (pkt, pkthdr->caplen) == 0)
		goto pq_glend;

	/* compute real IP/UDP packet size and append it to the right queue
	 */
	if (pq_add (pkt, pkthdr->caplen, &pkthdr->ts, sinfo->pq_thd))
		goto pq_glend;

	/* notify the corresponding thread about the new packet in it's queue
	 */
	pq_notify (sinfo->pq_thd);

pq_glend:
	return;
}


/* pq_add
 *
 * append a packet queue description (pq_desc) with packet content `p_data' to
 * the packet queue associated with thread `thd'.
 * the packet data is copied, so the packet data pointer `p_data' has to be
 * freed by the calling function. the time value `rcv_time' is the time when the
 * packet was sniffed from the pcap library.
 *
 * return 0 on success
 * will never fail tho ;-D
 */

int
pq_add (unsigned char *p_data, unsigned long int p_size, struct timeval *rcv_time, pq_thread *pqt)
{
	pq_desc	*np;		/* new packet in queue */

	np = xcalloc (1, sizeof (pq_desc));

	/* initialize the packet mutex and get hold of it
	 */
	pthread_mutex_init (&np->pq_mutex, NULL);
	pthread_mutex_lock (&np->pq_mutex);

	/* get memory for the packet
	 */
	np->p_len = p_size;
	np->p_data = xcalloc (1, np->p_len);

	/* copy packet data, create hash and copy time values
	 */
	memcpy (np->p_data, p_data, np->p_len);
	np->next = NULL;
	memcpy (&np->rcv_time, rcv_time, sizeof (struct timeval));

	/* now add the packet to the thread queue
	 */
	pthread_mutex_lock (&pqt->pq_mutex);

	/* no packet added yet, then just modify the root pointer, else
	 * append the packet
	 */
	if (pqt->root == NULL) {
		pqt->root = np;
	} else {
		pq_desc	*cur = pqt->root;	/* help pointers to step through the list */
		pq_desc	*last = pqt->root;

		/* cycle through linked list, until end is reached
		 */
		while (cur != NULL) {
			last = cur;

			pthread_mutex_lock (&last->pq_mutex);
			cur = last->next;
			pthread_mutex_unlock (&last->pq_mutex);
		}

		pthread_mutex_lock (&last->pq_mutex);
		last->next = np;
		pthread_mutex_unlock (&last->pq_mutex);
	}

	pthread_mutex_unlock (&pqt->pq_mutex);
	pthread_mutex_unlock (&np->pq_mutex);

	/* added packet successfully
	 */
	return (0);
}


/* pq_handle
 *
 * main (threaded) packet processor routine
 */

void *
pq_handle (pq_thread *pq)
{
	pq_desc		*packet;	/* packet pointer */
	ip_hdr		*ip;		/* IP packet header pointer */
	udp_hdr		*udp;		/* UDP packet header pointer */
	dns_hdr		*dns;		/* DNS receive header pointer */
	unsigned char	*data;		/* packet data pointer :-) */
	char		*p_data;
//	unsigned long	p;		/* packet counter */

	m_printf (ms, ms->windns, "[zod] hello world from the packetizer thread\n");

	do {
		unsigned int	psize;

		do {
			sem_wait (&pq->pq_active);	/* wait for a packet */

			/* get, unlink and then process the packet
			 */
			packet = pq_get (pq);
		} while (packet == NULL);

		p_data = packet->p_data;

		pq_offset (p_data, &ip, &udp, &dns, &data);

/*		hexdump ("packets-rawdns", (unsigned char *) ip, (packet->p_len - sizeof (eth_hdr)));
		debugp ("packets-rawdns", "ip=%08x\nudp=%08x\ndns=%08x\ndata=%08x\n", ip, udp, dns, data);
*/
		psize = packet->p_len;
		dns_handle (ip, udp, dns, data, psize);

		/* now, if the packet is directed to port 53, we add the id to the queue
		 * then update the display. but first check whether it is a self-originated
		 * packet, then skip the whole procedure.
		 */
		if (udp->uh_dport == htons (53) && dns_tag_check_n (&ip->ip_src,
			&ip->ip_dst, htons (udp->uh_sport), htons (udp->uh_dport),
			htons (dns->id)) == 0)
		{
			id_add (ip->ip_src, ntohs (dns->id), &packet->rcv_time);
			id_qprint (ms, ms->winid);
		}

		pq_free (packet);

	} while (1);

	return (NULL);
}


/* pq_create
 *
 * create a packet handler
 *
 * return NULL on failure
 * return pointer to pq_thread structure on success
 */

pq_thread *
pq_create (void)
{
	int		n;		/* temporary return value */
	pq_thread	*pq_new;	/* main thread structure of new thread */

	pq_new = xcalloc (1, sizeof (pq_thread));

	pthread_mutex_init (&pq_new->pq_mutex, NULL);
	pq_new->pq_count = pq_new->pq_curcount = 0;
	sem_init (&pq_new->pq_active, 0, 0);

	n = pthread_create (&pq_new->pq_tid, NULL, (void *) pq_handle, (void *) pq_new);
	if (n == -1) {
		pq_destroy (pq_new);

		return (NULL);
	}

	return (pq_new);
}


void
pq_destroy (pq_thread *pq)
{
	pthread_mutex_destroy (&pq->pq_mutex);
	sem_destroy (&pq->pq_active);

	free (pq);

	return;
}

/* pq_notify
 *
 * notify the correct thread using a semaphore
 */

void
pq_notify (pq_thread *pqt)
{
	/* raise the semaphore
	 */
	sem_post (&pqt->pq_active);

	return;
}


/* pq_get
 *
 * return one packet from the packet stack pointed to by `pqt'.
 *
 * return NULL on failure
 * return pointer to packet description on success
 */

pq_desc *
pq_get (pq_thread *pqt)
{
	pq_desc	*next;
	pq_desc	*this = NULL;

	pthread_mutex_lock (&pqt->pq_mutex);

	next = pqt->root;

	if (next != NULL) {

		/* if there is a packet, unlink first one, and shift all
		 * following packets
		 */
		pthread_mutex_lock (&pqt->root->pq_mutex);
		next = pqt->root->next;
		pthread_mutex_unlock (&pqt->root->pq_mutex);

		/* shift packets, we are helding pq_mutex tho :)
		 */
		this = pqt->root;
		pqt->root = next;

	}

	pthread_mutex_unlock (&pqt->pq_mutex);

	return (this);
}

/* pq_remove
 *
 * remove the first packet from packet thread queue `thd'.
 *
 * return in any case
 */

void
pq_remove (pq_thread *pqt)
{
	pq_desc	*next;

	pthread_mutex_lock (&pqt->pq_mutex);

	if (pqt->root != NULL) {
		pthread_mutex_lock (&pqt->root->pq_mutex);
		next = pqt->root->next;
		pthread_mutex_unlock (&pqt->root->pq_mutex);

		pq_free (pqt->root);
		pqt->root = next;
	}

	pthread_mutex_unlock (&pqt->pq_mutex);
	return;
}


/* pq_free
 *
 * free a pq_desc structure with all associated data
 */

void
pq_free (pq_desc *packet)
{
	/* some sanity checking inside :)
	 */
	if (packet == NULL)
		return;

	/* if data is associated, free it
	 */
	if (packet->p_data != NULL) {
		free (packet->p_data);
	}

	/* destroy mutex and free structure
	 */
	pthread_mutex_destroy (&packet->pq_mutex);
	free (packet);

	return;
}


/* pq_filter
 *
 * check wether packet with packet data pointed to by `p_data' is a UDP
 * nameserver packet or not
 *
 * return 1 if it is
 * return 0 if it is not
 */

int
pq_filter (unsigned char *p_data, unsigned long p_size)
{
	int iplen;
	ip_hdr		*ip = NULL;
	udp_hdr		*udp = NULL;

	if (p_size < (sizeof (ip_hdr) + sizeof (udp_hdr) + sizeof (dns_hdr)))
		return (0);

	/* now check if the ip header encloses a udp packet
	 */
	ip = (ip_hdr *) (p_data);	/* caveat here: don't miss brackets ! */
	if (ip->ip_p != IPPROTO_UDP)
		return (0);

	iplen = ip->ip_hl << 2;

	/* finally check the source/destination ports for the nameserver
	 * port 53
	 */
	udp = (udp_hdr *) (p_data + iplen);
	if ((udp->uh_dport != htons (53)) && (udp->uh_sport != htons (53)))
		return (0);

	/* it is a udp dns packet
	 */
	return (1);
}


/* pq_offset
 *
 * stupidly calculate offsets for IP, UDP and DNS offsets within a IP data
 * block
 *
 * return nothing
 */

void
pq_offset (unsigned char *data, ip_hdr **ip, udp_hdr **udp, dns_hdr **dns, unsigned char **dns_data)
{
	size_t	ip_len;

	if (data == NULL)
		return;

	*ip = (ip_hdr *) data;
	ip_len = (*ip)->ip_hl << 2;
	*udp = (udp_hdr *) (data + ip_len);
	*dns = (dns_hdr *) (data + ip_len + sizeof (udp_hdr));
	*dns_data = (unsigned char *) (data + ip_len + sizeof (udp_hdr) + sizeof (dns_hdr));

	return;
}

