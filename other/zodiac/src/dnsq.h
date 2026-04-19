
/* zodiac - advanced dns spoofer
 *
 * by scut / teso
 *
 * dns queue routines include file
 */

#ifndef	Z_DNSQ_H
#define	Z_DNSQ_H

#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include "packet.h"

/* a maximum of 256 filters should be used
 * raise this on demand
 */
#define	DQ_MAX	256


/* dq_packet structure
 *
 * linked list,
 * used to pass an incoming matched packet to the waiting thread
 */

typedef struct	dq_packet {
	struct dq_packet	*next;		/* next in the linked list */
	unsigned char		*packet;	/* IP header starts */
	unsigned int		plen;		/* packet length (iphdr + udphdr + dnshdr + dnsdata) */
} dq_packet;


/* dq_filter structure
 *
 * this is a internal filter structure, which defines a complete dns packet
 * filter. a maximum of DQ_MAX filters may be active simultanously.
 */

typedef struct	dq_filter {
	pthread_mutex_t		dq_mutex;	/* mutex over this structure */
	int			dq_desc;	/* dq_filter descriptor */
	sem_t			dq_sem;		/* semaphore for this filter */
	int			dq_sem_real;	/* real semaphore or just timeout one */
	int			dq_wait_count;	/* counts the waiting threads on this filter */

	struct in_addr		ip_src;		/* ip or INADDR_ANY */
	struct in_addr		ip_dst;		/* ip or INADDR_ANY */
	unsigned short int	port_src;	/* source port or zero */
	unsigned short int	port_dst;	/* destination port or zero */

	int			id_watch;	/* 0 = don't care, 1 = watch */
	u_short			id_start;	/* dns id range start */
	u_short			id_end;		/* end */

	unsigned char		*query;		/* NULL or query domain (uncompressed, dotted) */
	unsigned char		*dns_packet;	/* start of a dns packet */

	dq_packet		*p_root;	/* packet list root */
} dq_filter;


/* dqtim_val structure
 *
 * passing structure for the timeouting thread
 */

typedef struct	dqtim_val {
	struct timeval	tv;		/* timeout interval */
	dq_filter	*df;		/* filter to trigger */
} dqtim_val;


/* dq_handle
 *
 * check wether an incoming dns packet matches the filter table, then
 * take the appropiate actions.
 *
 * return in any case
 */

void	dq_handle (ip_hdr *ip, udp_hdr *udp, dns_hdr *dns, unsigned int plen);


/* dq_p_get
 *
 * get the first packet stored in queue on filter associated with `desc'
 *
 * return a pointer to the unlinked first packet
 * return NULL on failure
 */

dq_packet	*dq_p_get (int desc);


/* dq_p_append
 *
 * append a packet to a filter queue, where `packet' contains
 * data consisting out of the ip header, udp header, dns header and dns data 
 */

void	dq_p_append (dq_filter *df, unsigned char *packet, unsigned int packetlength);


/* dq_p_free_all
 *
 * free's all resisting packets within one filter
 *
 * return in any case
 */

void	dq_p_free_all (dq_filter *dq);


/* dq_p_free
 *
 * free the packet pointed to by `dqp'
 *
 * return in any case
 */

void	dq_p_free (dq_packet *dqp);


/* dq_filter_install
 *
 * install a dns packet filter, which will filter any datagrams that may come
 * from `ip_src' and going to `ip_dst' from port `port_src' to port `port_dst'.
 * if `id_watch' is non-zero keep also watch of the dns id of the packet, which
 * has to be in between of `id_start' and `id_end', `query' is the dns query
 * content which has to be in the packet, or NULL if it doesn't have to match.
 *
 * return -1 on failure
 * return >=0 as a dq_filter descriptor
 */

int	dq_filter_install (struct in_addr ip_src, struct in_addr ip_dst,
		unsigned short int port_src, unsigned short int port_dst,
		int id_watch, u_short id_start, u_short id_end, char *query);


/* dq_filter_uninstall
 *
 * remove a dns packet filter with the descriptor `dq_desc' from the filter
 * queue.
 *
 * return 0 on success
 * return 1 on failure
 */

int	dq_filter_uninstall (int dq_desc);


/* dq_filter_wait
 *
 * 'select' for filter descriptors.
 * wait a maximum of time defined in `tv' to get packets for filter defined
 * by `dq_desc'. if `tv' is { 0, 0 }, don't block, if `tv' is NULL, wait
 * indefinitly.
 *
 * return 1 if packet was caught
 * return 0 on timeout
 */

int	dq_filter_wait (int dq_desc, struct timeval *tv);

/* dq_timer
 *
 * helper function for timeouting the filter_wait function
 */

void	*dq_timer (dqtim_val *paa);

/* internal functions
 */
int	dq_match (dq_filter *real, dq_filter *pseudo);
int	dq_findslot (dq_filter *df[], int dq_max);
void	dq_filter_free (dq_filter *dq);


#endif

