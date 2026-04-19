
/* zodiac - advanced dns spoofer
 *
 * by scut / teso
 *
 * dns queue routines
 */

#define	DNSQ_MAIN

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>
#include "common.h"
#include "dns.h"
#include "dnsq.h"
#include "packet.h"


/* a maximum of 256 filters should be used
 * raise this on demand
 */

#define	DQ_MAX	256
pthread_mutex_t	dqf_mutex = PTHREAD_MUTEX_INITIALIZER; /* mutex over this array */
dq_filter	*dqf[DQ_MAX];	/* filter descriptor array */
int		dq_count = 0;	/* total filter count */


/* dq_match
 *
 * compare two filters, `real' is a real filter from the filter table,
 * `pseudo' is a pseudo filter, that is just used for this comparing
 * purposes.
 *
 * return 1 if they match
 * return 0 if they don't match
 */

int
dq_match (dq_filter *real, dq_filter *pseudo)
{
	int		n;		/* temporary return value */
	dns_hdr		*dns;		/* dns header pointer */
	unsigned char	*query_data;	/* first query in dns packet */

	/* compare the ip's, skipping INADDR_ANY records
	 */
	if (real->ip_src.s_addr != htonl (INADDR_ANY)) {
		if (real->ip_src.s_addr != pseudo->ip_src.s_addr)
			return (0);
	}
	if (real->ip_dst.s_addr != htonl (INADDR_ANY)) {
		if (real->ip_dst.s_addr != pseudo->ip_dst.s_addr)
			return (0);
	}

	/* compare the source/destination ports, skipping zero ports
	 */
	if (real->port_src != 0) {
		if (real->port_src != pseudo->port_src)
			return (0);
	}
	if (real->port_dst != 0) {
		if (real->port_dst != pseudo->port_dst)
			return (0);
	}

	/* finally, check the dns id range
	 */
	if (real->id_watch == 1) {
		if (pseudo->id_start < real->id_start)
			return (0);
		if (pseudo->id_start > real->id_end)
			return (0);
	}


	/* query comparison
	 */

	if (real->query != NULL && pseudo->dns_packet != NULL) {
		dns = (dns_hdr *) pseudo->dns_packet;
		if (ntohs (dns->qdcount) >= 1) {
			char	label[256];

			/* decode query label from incoming packet and then compare
			 * with given query
			 */
			query_data = pseudo->dns_packet + sizeof (dns_hdr);
			memset (label, '\0', sizeof (label));

			n = dns_dcd_label (pseudo->dns_packet, &query_data, label, sizeof (label) - 1, 5);

			/* decoding failed
			 */
			if (n == 1)
				return (0);

			xstrupper (label);

			if (strcmp (label, real->query) != 0)
				return (0);
		} else {
			/* no query in the packet, but required by filter
			 */

			return (0);
		}
	}

	/* all aspects to check matched
	 */
	return (1);
}


/* dq_activate
 *
 * activate any dq_filter_wait () that may wait for filter activity from
 * the filter pointed to by `filt'.
 * assume that the calling function holds filt->dq_mutex.
 *
 * return in any case
 */

void
dq_activate (dq_filter *filt)
{
	sem_post (&filt->dq_sem);

	return;
}


/* dq_handle
 *
 * check wether an incoming dns packet matches the filter table, then
 * take the appropiate actions.
 *
 * return in any case
 */

void
dq_handle (ip_hdr *ip, udp_hdr *udp, dns_hdr *dns, unsigned int plen)
{
	int		slot, n;	/* temporary slot counter */
	dq_filter	*tflt;	/* temporary filter for matching purposes */

	/* create new pseudo filter
	 */
	tflt = xcalloc (1, sizeof (dq_filter));
	tflt->ip_src = ip->ip_src;
	tflt->ip_dst = ip->ip_dst;
	tflt->port_src = htons (udp->uh_sport);
	tflt->port_dst = htons (udp->uh_dport);
	tflt->id_watch = 0;
	tflt->id_start = htons (dns->id);
	tflt->id_end = 0;
	tflt->dns_packet = (unsigned char *) dns;

	/* go through all slots
	 */
	pthread_mutex_lock (&dqf_mutex);

	n = dq_count;

	for (slot = 0; n > 0 && slot < DQ_MAX; slot++) {
		if (dqf[slot] == NULL)
			continue;

		n--;

		/* check wether they match, then activate threads that may listen
		 * for activity on the descriptor
		 */
		if (dq_match (dqf[slot], tflt) == 1) {
			pthread_mutex_lock (&dqf[slot]->dq_mutex);

			dqf[slot]->dq_sem_real = 1;
			dq_p_append (dqf[slot], (unsigned char *) ip, plen);
			dq_activate (dqf[slot]);

			pthread_mutex_unlock (&dqf[slot]->dq_mutex);
		}

	}
	pthread_mutex_unlock (&dqf_mutex);

	/* free the pseudo filter
	 */
	free (tflt);


	return;
}


/* dq_p_get
 *
 * get the first packet stored in queue on filter associated with `desc'
 *
 * return a pointer to the unlinked first packet
 * return NULL on failure
 */

dq_packet *
dq_p_get (int desc)
{
	dq_filter	*df;
	dq_packet	*this;

	pthread_mutex_lock (&dqf_mutex);
	df = dqf[desc];
	if (df != NULL) {
		pthread_mutex_lock (&df->dq_mutex);
		if (df->p_root == NULL)
			return (NULL);

		this = df->p_root;
		df->p_root = this->next;
		pthread_mutex_unlock (&df->dq_mutex);
	}

	pthread_mutex_unlock (&dqf_mutex);

	return (this);
}


/* dq_p_append
 *
 * append a packet to a filter queue, where `packet' contains
 * data consisting out of the ip header, udp header, dns header and dns data 
 */

void
dq_p_append (dq_filter *df, unsigned char *packet, unsigned int packetlength)
{
	dq_packet	*this, *last;

	this = df->p_root;

	/* first packet
	 */
	if (this == NULL) {
		df->p_root = xcalloc (1, sizeof (dq_packet));
		this = df->p_root;
	} else {
		/* append to the list
		 */

		while (this != NULL) {
			last = this;
			this = this->next;
		}

		last->next = xcalloc (1, sizeof (dq_packet));
		this = last->next;

	}

	this->next = NULL;
	this->packet = xcalloc (1, packetlength);
	memcpy (this->packet, packet, packetlength);
	this->plen = packetlength;

	return;
}


/* dq_findslot
 *
 * find a free slot in the array `df', with a maximum array size of `dqmax'
 *
 * return -1 if no slot is free
 * return slot if slot is found
 */

int
dq_findslot (dq_filter *df[], int dq_max)
{
	int	n;

	for (n = 0; n < dq_max; n++) {
		if (df[n] == NULL)
			return (n);
	}
	return (-1);
}


/* dq_filter_install
 *
 * return -1 on failure
 * return >=0 as a dq_filter descriptor
 */

int
dq_filter_install (struct in_addr ip_src, struct in_addr ip_dst,
	unsigned short int port_src, unsigned short int port_dst,
	int id_watch, u_short id_start, u_short id_end, char *query)
{
	dq_filter	*nf;
	int		slot;	/* free slot */


	pthread_mutex_lock (&dqf_mutex);

	slot = dq_findslot (dqf, DQ_MAX);
	if (slot == -1)
		return (-1);

	nf = xcalloc (1, sizeof (dq_filter));

	/* initialize thread variables
	 */
	pthread_mutex_init (&nf->dq_mutex, NULL);
	pthread_mutex_lock (&nf->dq_mutex);
	sem_init (&nf->dq_sem, 0, 0);

	/* set up filter data
	 */
	nf->dq_sem_real = 0;
	nf->dq_desc = slot;	/* set descriptor */
	nf->ip_src = ip_src;
	nf->ip_dst = ip_dst;
	nf->port_src = port_src;
	nf->port_dst = port_dst;
	nf->id_watch = id_watch;
	nf->id_start = id_start;
	nf->id_end = id_end;
	nf->dns_packet = NULL;
	nf->p_root = NULL;

	if (query == NULL) {
		nf->query = NULL;
	} else {
		nf->query = xstrdup (query);
		xstrupper (nf->query);
	}

	dqf[slot] = nf;

	dq_count++;

	pthread_mutex_unlock (&nf->dq_mutex);
	pthread_mutex_unlock (&dqf_mutex);

	return (slot);
}


/* dq_filter_uninstall
 *
 * return 0 on success
 * return 1 on failure
 */

int
dq_filter_uninstall (int dq_desc)
{
	dq_filter	*this;
	int		n;

	pthread_mutex_lock (&dqf_mutex);

	for (n = 0; n < DQ_MAX; n++) {
		if (dqf[n] != NULL) {
			pthread_mutex_lock (&dqf[n]->dq_mutex);

			/* if filter matches, uninstall it
			 */
			if (dqf[n]->dq_desc == dq_desc) {

				this = dqf[n];
				dqf[n] = NULL;

				/* kill ALL waiting routines
				 */
				while (this->dq_wait_count > 0) {

					/* no real activation
					 */
					this->dq_sem_real = 0;
					sem_post (&this->dq_sem);

					/* and let one waiter die
					 */
					pthread_mutex_unlock (&dqf[n]->dq_mutex);
					pthread_mutex_lock (&dqf[n]->dq_mutex);
				}

				dq_p_free_all (this);
				dq_filter_free (this);

				dq_count--;

				/* `dq_desc' should be unique, so we don't care
				 */
				pthread_mutex_unlock (&dqf_mutex);
				return (0);
			}
			pthread_mutex_unlock (&dqf[n]->dq_mutex);
		}
	}
	pthread_mutex_unlock (&dqf_mutex);

	return (1);
}


/* dq_p_free_all
 *
 * free's all resisting packets within one filter
 *
 * return in any case
 */

void
dq_p_free_all (dq_filter *dq)
{
	dq_packet	*this, *last;

	for (this = dq->p_root; this != NULL;) {
		last = this;
		this = this->next;
		dq_p_free (last);
	}

	return;
}


/* dq_p_free
 *
 * free the packet pointed to by `dqp'
 *
 * return in any case
 */

void
dq_p_free (dq_packet *dqp)
{
	if (dqp != NULL) {
		if (dqp->packet != NULL)
			free (dqp->packet);
		free (dqp);
	}

	return;
}


/* dq_filter_free
 *
 * return in any case
 */

void
dq_filter_free (dq_filter *dq)
{
	if (dq == NULL)
		return;

	pthread_mutex_destroy (&dq->dq_mutex);
	sem_destroy (&dq->dq_sem);

	if (dq->query != NULL)
		free (dq->query);

	free (dq);

	return;
}


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

int
dq_filter_wait (int dq_desc, struct timeval *tv)
{
	int	rval = 0;	/* return value */
	int	n = 0;		/* temporary return value */


	/* first, register us as a filter waiter
	 */
	pthread_mutex_lock (&dqf[dq_desc]->dq_mutex);
	dqf[dq_desc]->dq_wait_count++;
	pthread_mutex_unlock (&dqf[dq_desc]->dq_mutex);

	/* if a timeout is required, fire up another subthread, that just
	 * will post the semaphore after a given timeout, but set dq_sem_real
	 * to zero, to tell us that it's just a timeout semaphore.
	 *
	 * in the other case, if a real packet intrudes, dq_activate will post
	 * the semaphore AND will notify us through dq_sem_real = 1 that it's
	 * a real packet.
	 *
	 * in the worst case, the filter is being uninstalled, and dq_sem_real
	 * will be "2", that means we should just return as if no packet has
	 * been caught.
	 *
	 * if no timeout is used it's just a sem_wait.
	 */

	/* check wether we have to wait indefinite
	 */
	if (tv != NULL) {

		/* check wether it is a timeouting wait request
		 */
		if (tv->tv_sec != 0 || tv->tv_usec != 0) {
			pthread_t	tout_tid;	/* timeout thread id */
			dqtim_val	*paa = xcalloc (1, sizeof (dqtim_val));

			/* build up a pseudo structure, just for parameter passing
			 */
			paa->tv.tv_sec = tv->tv_sec;
			paa->tv.tv_usec = tv->tv_usec;
			paa->df = dqf[dq_desc];

			/* start a timeouter thread
			 */
			n = pthread_create (&tout_tid, NULL, (void *) dq_timer, (void *) paa);

			if (n != -1) {
				sem_wait (&dqf[dq_desc]->dq_sem);

				/* destroy the timeouting thread on real packet
				 * added pthread_join () call - 990925.
				 */
				if (dqf[dq_desc]->dq_sem_real != 0) {
					pthread_cancel (tout_tid);
				}
				pthread_join (tout_tid, NULL);
			}

			/* clean the mess up and set the return value
			 */
			free (paa);
			rval = dqf[dq_desc]->dq_sem_real;

		} else {

			/* non blocking check
			 */
			n = sem_trywait (&dqf[dq_desc]->dq_sem);
			if (n == 0)
				rval = 1;
		}
	} else {
		/* wait indefinitly
		 */

		n = sem_wait (&dqf[dq_desc]->dq_sem);

		if (n == 0) {
			pthread_mutex_lock (&dqf[dq_desc]->dq_mutex);
			n = dqf[dq_desc]->dq_sem_real;
			if (n == 1)
				rval = 1;

			pthread_mutex_unlock (&dqf[dq_desc]->dq_mutex);
		}
	}

	/* decrease the listeners count
	 */
	pthread_mutex_lock (&dqf[dq_desc]->dq_mutex);
	dqf[dq_desc]->dq_wait_count--;
	pthread_mutex_unlock (&dqf[dq_desc]->dq_mutex);

	return (rval);
}


/* dq_timer
 *
 * timeout thread, that will just raise a semaphore after a given timeout
 * the thread has to be cancelled if the timeout is not necessary anymore.
 *
 * return nothing (threaded)
 */

void *
dq_timer (dqtim_val *paa)
{
	unsigned long long	usec;	/* microseconds to sleep */

	/* added to allow immediate interruption.
	 * -smiler 990925
 	 */
	pthread_setcancelstate (PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype (PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	/* calculate time to sleep, then sleep until either timeout
	 * or interruption
	 */
	usec = (paa->tv.tv_sec * 1000000) + paa->tv.tv_usec;
	usleep (usec);

	/* we survived, now be faster then the race condition ;-D
	 */

	paa->df->dq_sem_real = 0;	 /*0 = just a timeout*/
	sem_post (&paa->df->dq_sem);	/* post semaphore */

	return (NULL);
}

