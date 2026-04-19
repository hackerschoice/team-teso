/* zodiac - advanced dns spoofer
 *
 * by scut / teso
 *
 * dns id queue handling routines
 *
 */

#define	DNSID_MAIN

#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <ncurses.h>
#include <stdlib.h>
#include "common.h"
#include "dnsid.h"
#include "dns.h"
#include "network.h"
#include "zodiac.h"
#include "output.h"

id_q		*id_root = NULL;

/* id_qprint
 *
 * erase the window pointed to by `win' in `screen', then print all
 * ID's stored in queue pointed to by `root', which is protected by `rm'
 */

void
id_qprint (mscr *screen, WINDOW *win)
{
	id_q		*this;		/* list step-through pointer */

	/* clear window
	 */
	pthread_mutex_lock (&screen->outm);
	werase (win);
	pthread_mutex_unlock (&screen->outm);

	pthread_mutex_lock (&id_rmutex);
	this = id_root;

	while (this != NULL) {
		char			ip[64], *ipp;
		unsigned long int	age = 0;
		id_q			*next;

		pthread_mutex_lock (&this->id_mutex);

		ipp = ipv4_print (ip, this->ip, 2);	/* print ip in quad-dot, padded with spaces */
		age = id_tdiff (&this->mtime);		/* compute the age of the known id */

		m_printfnr (screen, win, "[%s] %04x = %8lu %s%s\n", ipp, this->id, age,
			((this->flags & IDF_SEQ) == IDF_SEQ) ? "SEQUENTIAL " : "",
			((this->flags & IDF_WINDUMB) == IDF_WINDUMB) ? "WINDOWS" : "");

		next = this->next;
		pthread_mutex_unlock (&this->id_mutex);
		this = next;
	}

	pthread_mutex_unlock (&id_rmutex);

	pthread_mutex_lock (&screen->outm);
	wrefresh (win);
	pthread_mutex_unlock (&screen->outm);

	return;
}


/* id_tdiff
 *
 * calculate the age in seconds from the given timeinterval and the current
 * time.
 *
 * return the age in seconds
 */

unsigned long int
id_tdiff (struct timeval *mtime)
{
	struct timeval	current;	/* current time */

	/* get current time
	 */
	gettimeofday (&current, NULL);

	return (tdiff (mtime, &current));
}


/* id_free
 *
 * free's an id_q structure, pointed to by `tofree'. this routine assumes that
 * the calling function hold the `id_mutex', and won't unlock it later, because
 * it gets destroyed.
 */

void
id_free (id_q *tofree)
{
	pthread_mutex_destroy (&tofree->id_mutex);
	free (tofree);

	return;
}


/* id_seq
 *
 * make assumptions wether a dns id is predictable and used sequentially.
 * use the time `o_time' of the old id `old_id' to compare with the new
 * id `new_id'. use limit `idps' to get id rate per second.
 *
 * return 1 if it is sequentially (rate below or equal to `idps'
 * return 0 if the id is not predictable or random (above the rate)
 * return -1 if `old_id' is same as `new_id'
 */

int
id_seq (u_short new_id, u_short old_id, struct timeval *o_time, int idps)
{
	unsigned long int	age;
	u_short			id_diff = 0;

	/* handle bigger/smaller cases signed, if equal it is most likely
	 * a second query approach, therefore id_diff stays zero
	 */
	if (new_id > old_id)
		id_diff = (new_id - old_id);
	else if (new_id < old_id)
		id_diff = (old_id - new_id);

	if (id_diff == 0)
		return (-1);

	/* make some calculations about predictability
	 * of the id's
	 */
	age = id_tdiff (o_time);
	if (age == 0)
		age = 1;

	/* less then 10 id's per second
	 */
	if ((id_diff / age) <= idps)
		return (1);

	return (0);
}


/* id_windows
 *
 * check if both id's, `id_new' and `id_old' may be send out by a windows
 * `operating system' dns resolver library.
 *
 * return 1 if it is most likely a windows box
 * return 0 if it is most likely not a windows box
 */

int
id_windows (u_short id_new, u_short id_old)
{
	if (id_new <= 20 && id_old <= 20)
		return (1);

	return (0);
}


/* id_add
 *
 * add/update a nameserver id entry for `ip' as the nameserver ip,
 * `id' as the measured nameserver id, and `mtime' as the time measured.
 *
 * return nothing (since the packet is mutexed)
 */

void
id_add (struct in_addr ip, u_short id, struct timeval *mtime)
{
	id_q	*n_idq;	/* new id queue element */

	/* get memory for new linked list element
	 */
	n_idq = xcalloc (1, sizeof (id_q));

	/* initialize structure
	 */
	pthread_mutex_init (&n_idq->id_mutex, NULL);
	memcpy (&n_idq->ip, &ip, sizeof (struct in_addr));
	n_idq->id = id;
	n_idq->flags = 0;
	memcpy (&n_idq->mtime, mtime, sizeof (struct timeval));
	n_idq->next = NULL;

	pthread_mutex_lock (&id_rmutex);

	if (id_root == NULL) {
		id_root = n_idq;
	} else {
		id_q	*this, *last;
		int	bc = 0;	/* for break condition */

		/* step through the linked list until either an old entry
		 * was found, or we have reached the end of the list
		 * quite scuttish code ;-)
		 *
		 * fixed, optimized and rewritten 990614, please don't mod here
		 */

		last = this = id_root;

		while (bc == 0) {
			pthread_mutex_lock (&this->id_mutex);

			/* if the id is already stored, unlink the old id_q,
			 * and put our one instead
			 */
			if (memcmp (&this->ip, &ip, sizeof (struct in_addr)) == 0) {
				id_q			*old;
				int			nr;	/* temp. return value */

				/* check wether the dns id is sequential
				 */
				nr = id_seq (id, this->id, &this->mtime, 40);
				if (nr == -1) {
					n_idq->flags = this->flags;
				} else if (nr == 1) {
					n_idq->flags |= IDF_SEQ;
				} else if (nr == 0) {
				/*	n_idq->flags &= ~IDF_SEQ;
				 */
					n_idq->flags = this->flags;
				}

				nr = id_windows (id, this->id);
				if (nr == 1)
					n_idq->flags |= IDF_WINDUMB;
				else
					n_idq->flags &= ~IDF_WINDUMB;

				/* if we have to replace the entry, we copy the link-
				 * data from it, then remove it from the linked list
				 */
				old = this;
				n_idq->next = old->next;

				/* if there were id_q's before, correct the last one
				 */
				if (old == id_root) {
					id_root = n_idq;
				} else {
					pthread_mutex_lock (&last->id_mutex);
					last->next = n_idq;
					pthread_mutex_unlock (&last->id_mutex);
				}
				pthread_mutex_unlock (&old->id_mutex);
				id_free (old);
				bc = 1;		/* break if entry already exists */

			/* else, when the end of the id queue is reached, without
			 * any matching entry, then just add our one to the end
			 */
			} else if (this->next == NULL) {
				this->next = n_idq;
				if (id_windows (0, this->id) == 1)
					this->flags |= IDF_WINDUMB;

				bc = 2;		/* break when end of list is reached */
			}

			if (bc != 1) {
				last = this;
				this = this->next;
				pthread_mutex_unlock (&last->id_mutex);
			}
		}
		/* bc == 2 is already carried out
		 */
	}

	pthread_mutex_unlock (&id_rmutex);

	return;
}


/* id_speed
 *
 * fetch the id increasing speed.
 *
 * return the dns id increasing speed (in id's per 10 seconds) of the
 * nameserver with ip `ip'.
 * return 0 on failure.
 */

unsigned long int
id_speed (char *ip_a)
{
	id_q		*this;	/* working pointer for queue */
	struct in_addr		ip_ad;
	unsigned long int	speed = 0;

	pthread_mutex_lock (&id_rmutex);
	ip_ad.s_addr = net_resolve (ip_a);

	for (this = id_root; this != NULL; this = this->next) {
		pthread_mutex_lock (&this->id_mutex);
		if (memcmp (&this->ip, &ip_ad, sizeof (struct in_addr)) == 0) {
			speed = this->id_speed;
		}
		pthread_mutex_unlock (&this->id_mutex);
	}
	pthread_mutex_unlock (&id_rmutex);

	return (speed);
}


/* id_get
 *
 * return the last dns ID measured, with time pointed to by `tv'
 * if `tv' is NULL, the timeval is not copied.
 *
 * return ID and copy timeval into *tv on success
 * return 0 on failure
 */

u_short
id_get (char *ip, struct timeval *tv, unsigned long int *flags)
{
	u_short		id;	/* id to return */
	id_q		*this;	/* working pointer for queue */
	int		bc = 1;	/* break condition */
	struct in_addr	ip_a;

	/* lock queue mutex to sync all queue functions
	 */
	pthread_mutex_lock (&id_rmutex);

	ip_a.s_addr = net_resolve (ip);

	/* step through queue
	 */
	for (this = id_root; this != NULL && bc; this = this->next) {
		pthread_mutex_lock (&this->id_mutex);

		if (memcmp (&this->ip, &ip_a, sizeof (struct in_addr)) == 0) {
			if (tv != NULL) {
				memcpy (tv, &this->mtime, sizeof (struct timeval));
			}
			id = this->id;
			*flags = this->flags;
			bc = 0;		/* break */
		}

		pthread_mutex_unlock (&this->id_mutex);
	}

	pthread_mutex_unlock (&id_rmutex);

	return (bc == 0 ? (id) : 0);
}


/* id_qcleanup
 *
 * cleans up the whole id queue pointed to by `root', protected by `rm'.
 */

void
id_qcleanup (pthread_mutex_t *rm, id_q **root)
{
	id_q	*this;

	pthread_mutex_lock (rm);
	this = *root;
	*root = NULL;

	while (this != NULL) {

		id_q	*next;

		/* lock, then destroy mutex
		 */
		pthread_mutex_lock (&this->id_mutex);
		pthread_mutex_destroy (&this->id_mutex);

		next = this->next;
		id_free (this);
		this = next;
	}

	pthread_mutex_unlock (rm);

	return;
}

