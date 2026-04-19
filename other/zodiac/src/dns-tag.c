/* zodiac - advanced dns spoofer
 *
 * by team teso
 *
 * dns tag routines
 */

#define	_Z_DNS_TAG_C_MAIN

#include <sys/time.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include "common.h"
#include "dns-tag.h"
#include "network.h"


/* dns tag linked list root pointer
 */

dns_tag			*dns_tag_root = NULL;
pthread_mutex_t		dns_tag_mutex = PTHREAD_MUTEX_INITIALIZER;
unsigned long int	dns_tag_time_expire = 5;	/* keep 5 seconds */
int			dns_print_own_packets = 1;


void
dns_tag_add (char *ip_src, char *ip_dst, unsigned short int prt_src,
	unsigned short int prt_dst, unsigned short int dns_id)
{
	dns_tag	*this;
	dns_tag	*new = xcalloc (1, sizeof (dns_tag));

	new->ip_src.s_addr = net_resolve (ip_src);
	new->ip_dst.s_addr = net_resolve (ip_dst);
	new->prt_src = prt_src;
	new->prt_dst = prt_dst;
	new->dns_id = dns_id;
	new->next = NULL;	/* last element */
	gettimeofday (&new->time_send, NULL);

	pthread_mutex_lock (&dns_tag_mutex);
	if (dns_tag_root == NULL) {
		dns_tag_root = new;
	} else {
		for (this = dns_tag_root ; this->next != NULL ;
			this = this->next)
		;
		this->next = new;
	}
	pthread_mutex_unlock (&dns_tag_mutex);

	return;
}


int
dns_tag_check_a (char *ip_src, char *ip_dst, unsigned short int prt_src,
	unsigned short int prt_dst, unsigned short int dns_id)
{
	struct in_addr	ip_src_n,
			ip_dst_n;

	ip_src_n.s_addr = net_resolve (ip_src);
	ip_dst_n.s_addr = net_resolve (ip_dst);

	return (dns_tag_check_n (&ip_src_n, &ip_dst_n, prt_src, prt_dst, dns_id));
}


/* quite optimized
 */

int
dns_tag_check_n (struct in_addr *ip_src, struct in_addr *ip_dst,
	unsigned short int prt_src, unsigned short int prt_dst,
	unsigned short int dns_id)
{
	int		found = 0;	/* found flag, flagged inside loop */
	dns_tag		*this, **last;	/* linked list step pointer */
	struct in_addr	any;
	struct timeval	tv_current;	/* check expired frames oh yeah */

	any.s_addr = net_resolve ("*");
	gettimeofday (&tv_current, NULL);

	pthread_mutex_lock (&dns_tag_mutex);

	last = &dns_tag_root;

	for (this = dns_tag_root ; found == 0 && this != NULL ; )
	{
		found = 1;	/* assume "yes", then squash it */

		/* check whether the frame has expired
		 */
		if (tdiff (&this->time_send, &tv_current) >= dns_tag_time_expire) {
			dns_tag	*old = this;

			*last = this->next;
			this = this->next;
			free (old);	/* fear the heap :> */
			found = 0;

			continue;
		} else {
			last = &this->next;
		}

		if (found == 1 && ip_src->s_addr != any.s_addr &&
			ip_src->s_addr != this->ip_src.s_addr)
		{
			found = 0;
		}

		if (found == 1 && ip_dst->s_addr != any.s_addr &&
			ip_dst->s_addr != this->ip_dst.s_addr)
		{
			found = 0;
		}

		if (found == 1 && prt_src != 0 && prt_src != this->prt_src)
			found = 0;
		if (found == 1 && prt_dst != 0 && prt_dst != this->prt_dst)
			found = 0;
		if (found == 1 && dns_id != 0 && dns_id != this->dns_id)
			found = 0;

		this = this->next;
	}

	pthread_mutex_unlock (&dns_tag_mutex);

	return (found);
}


