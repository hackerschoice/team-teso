/* zodiac - advanced dns spoofer
 *
 * by team teso
 *
 * dns tag routines include file
 */

#ifndef	_Z_DNS_TAG_H
#define	_Z_DNS_TAG_H


#include <netinet/in.h>


#ifndef	_Z_DNS_TAG_C_MAIN
extern int	dns_print_own_packets;
#endif

/* dns tag linked list element
 */

typedef struct	dns_tag {
	struct dns_tag		*next;		/* linked list pointer */

	struct in_addr		ip_src;		/* source ip */
	struct in_addr		ip_dst;		/* destination ip */
	unsigned short int	prt_src;	/* udp source port */
	unsigned short int	prt_dst;	/* udp destination port */
	unsigned short int	dns_id;		/* dns id of the frame */
	struct timeval		time_send;	/* time the frame was send */
} dns_tag;


/* dns_tag_add
 *
 * create a new linked list element with the given properties
 *
 * return in any case
 */

void
dns_tag_add (char *ip_src, char *ip_dst, unsigned short int prt_src,
	unsigned short int prt_dst, unsigned short int dns_id);


/* dns_tag_check_a
 *
 * check whether the packet frame is in the queue. `ip_*' can be `*' if no
 * address checking should be performed. `prt_*' and `dns_id' can be zero if
 * no comparison on them should be performed.
 *
 * return 1 if it is
 * return 0 if it is not
 */

int
dns_tag_check_a (char *ip_src, char *ip_dst, unsigned short int prt_src,
	unsigned short int prt_dst, unsigned short int dns_id);


/* dns_tag_check_n
 *
 * check whether the packet frame is in the queue. `ip_*' can be INADDR_ANY
 * if no address checking should be performed. `prt_*' and `dns_id' can be
 * zero if no comparison on them should be performed.
 *
 * return 1 if the packet frame was found
 * return 0 if the packet frame was not found
 */

int
dns_tag_check_n (struct in_addr *ip_src, struct in_addr *ip_dst,
	unsigned short int prt_src, unsigned short int prt_dst,
	unsigned short int dns_id);


#endif

