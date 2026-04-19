/* zodiac - advanced dns spoofer
 *
 * by scut / teso
 *
 * dns id queue handling header file
 */

#ifndef	Z_DNSID_H
#define	Z_DNSID_H

#include <pthread.h>
#include "output.h"

#define	IDF_SEQ		0x0001	/* sequential id's */
#define	IDF_WINDUMB	0x0002	/* windows dumb id's (just non-collision id's, starting at 0x0001) */

/* id_q
 *
 * linked list element that hold the last visible id of the nameserver with
 * ip `ip'. `mtime' is the time the id was measured. `next' is the pointer
 * to the next element of the linked list
 *
 * each element is protected by the `id_mutex' mutal exclusion variable
 */

typedef struct	id_q {
	pthread_mutex_t		id_mutex;	/* mutal exclusion over the structure */
	struct in_addr		ip;		/* ip of the nameserver */
	u_short			id;
	u_short			id_guess;	/* next guess range for id (= id + range) */
	unsigned long int	id_speed_c;	/* how many times the speed has been counted */
	unsigned long int	id_speed;	/* differential analysed dns id increasing
						 * speed in increases per 10 seconds
						 */
	unsigned long int	flags;		/* flags */

	struct timeval		mtime;
	struct id_q		*next;
} id_q;

void			id_qprint (mscr *screen, WINDOW *win);
unsigned long int	id_tdiff (struct timeval *mtime);
void			id_free (id_q *tofree);
int			id_seq (u_short new_id, u_short old_id, struct timeval *o_time, int idps);
int			id_windows (u_short id_new, u_short id_old);
void			id_add (struct in_addr ip, u_short id, struct timeval *mtime);
u_short			id_get (char *ip_a, struct timeval *tv, unsigned long int *flags);
unsigned long int	id_speed (char *ip_a);
void			id_qcleanup (pthread_mutex_t *rm, id_q **root);

#ifndef	DNSID_MAIN
extern id_q	*id_root;
#endif

extern pthread_mutex_t	id_rmutex;

#endif

