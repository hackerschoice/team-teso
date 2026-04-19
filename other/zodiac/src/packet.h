/* snifflib
 *
 * by scut, smiler
 *
 */

#ifndef	Z_PACKET_H
#define	Z_PACKET_H

#include <sys/time.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <pcap.h>
#include <semaphore.h>
#include <pthread.h>
#include <libnet.h>


/* packet structures
 *
 * we tried to be as portable as possible
 */

typedef struct libnet_ethernet_hdr	eth_hdr;
typedef struct libnet_ip_hdr		ip_hdr;
typedef struct libnet_udp_hdr		udp_hdr;
typedef HEADER				dns_hdr;	/* HEADER is in arpa/nameser.h */


/* pq_desc
 *
 * describe one packet within the packet queue. the data is only to be read
 * and write if `pq_mutex' is hold. `next' points to the next pq_desc within
 * this packet queue, hash is the hash id of the packet (TCP only), `p_data'
 * is the actual packet data (at IP level)
 */

typedef struct	pq_desc {
	pthread_mutex_t		pq_mutex;	/* mutex over this structure */

	struct pq_desc		*next;		/* pointer to the next packet in the queue */
	struct timeval		rcv_time;	/* time when the packet was received */
	unsigned long int	p_len;		/* overall packet length */

	unsigned char		*p_data;	/* actual packet data, link layer stripped already */
} pq_desc;


/* pq_thread
 *
 * describe a) one packet processing thread (tid, semaphore)
 *          b) packet queue root pointer (linked list of pq_desc structs)
 *          c) stats for this queue
 *
 * if the sniffing thread has encountered a packet that it added to this
 * packetizing queue, it will raise the `pq_active' :-)
 */

typedef struct	pq_thread {
	pthread_t		pq_tid;		/* thread ID */
	sem_t			pq_active;	/* new packet semaphore, yeah =) */
	pthread_mutex_t		pq_mutex;	/* mutex over this structure */

	unsigned long int	pq_count;	/* number of packets processed in this queue */
	unsigned long int	pq_curcount;	/* number of packets currently in this queue */
	pq_desc			*root;		/* root pointer of the linked list in this queue (NULL for empty) */
} pq_thread;

void		*pq_handle (pq_thread *pq);
pq_thread	*pq_create (void);
void		pq_destroy (pq_thread *pq);
pq_desc		*pq_get (pq_thread *pqt);
void		pq_grind (void *sinfov, struct pcap_pkthdr *pkthdr,
	unsigned char *pkt);
int		pq_add (unsigned char *p_data, unsigned long int p_size,
	struct timeval *rcv_time, pq_thread *pqt);
void		pq_notify (pq_thread *pqt);
void		pq_remove (pq_thread *pqt);
void		pq_free (pq_desc *packet);
int		pq_filter (unsigned char *p_data, unsigned long p_size);
void		pq_offset (unsigned char *data, ip_hdr **ip, udp_hdr **udp,
	dns_hdr **dns, unsigned char **dns_data);

#endif

