/* zylyx - file find ;-)
 *
 * by team teso
 */

#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <stdio.h>
#include <slang.h>
#include "common.h"
#include "screen.h"
#include "proxy.h"
#include "zylyx.h"

#define	MAX_PROC	16

int	win_y;

int
main (int argc, char **argv)
{
	proxy	**prx_list;
	int	proxy_count;

	if (argc != 2) {
		printf ("usage: %s <url>\n", argv[0]);
		exit (EXIT_FAILURE);
	}

	scr_init ();
	scr_prg_init ();

	prx_list = prx_load ("proxy-list", &proxy_count);
	if (prx_list == NULL) {
		scr_exit ();
		exit (EXIT_FAILURE);
	}

	zyl_assign_prx (prx_list);
	zyl_main (prx_list, proxy_count, argv[1]);

	scr_exit ();

	exit (EXIT_SUCCESS);
}


void
zyl_main (proxy **pl, int proxycount, char *file)
{
	int		n;
	struct timeval	last_conn = { 0, 0 };
	sem_t		permit_action,	/* permit a client response */
			client_action;	/* client responded */
	pthread_mutex_t	subcount_m;	/* subcounter mutex */
	int		subcount = 0;
	int		proxy_ptr = 0;
	pthread_mutex_t	result_m;	/* result data is locked hehe */
	result		result_r;	/* result data =) */

	sem_init (&permit_action, 0, 0);
	sem_init (&client_action, 0, 0);
	pthread_mutex_init (&subcount_m, NULL);
	pthread_mutex_init (&result_m, NULL);

	sem_post (&permit_action);

	/* fire clients and take events (event loop)
	 */

	while (proxy_ptr < proxycount) {
		pthread_mutex_lock (&subcount_m);
		if (subcount < MAX_PROC) {
			unsigned long int	tp;

			pl[proxy_ptr]->file = file;

			/* anti flood mechanism :)
			 */
			tp = t_passed (&last_conn);
			if (tp > 0 && tp < 500000) {
				/* race condition here (find it and you'll get a hug ;)
				 */
				usleep (500000 - tp);
			}
			gettimeofday (&last_conn, NULL);
			prx_fire (pl[proxy_ptr++], &result_r, &result_m, &permit_action, &client_action);
			subcount++;
		}
		pthread_mutex_unlock (&subcount_m);

#ifdef IPC_DEBUG
		printf ("zylyx.c:%d # sem_trywait (&client_action) = %d\n", __LINE__, sem_trywait (&client_action));
		printf ("zylyx.c:%d # subcount = %d\n", __LINE__, subcount);
#endif

		/* if we cannot fire out new clients because we reached the maximum number,
		 * or if a client wants our attention we enter the result processing
		 */

		n = 1;
		if (subcount >= MAX_PROC ||
			((n = sem_trywait (&client_action)) == 0))
		{

			/* wait for client action (queued)
			 */
			if (n == 1)
				sem_wait (&client_action);

			/* lock result data
			 */
			pthread_mutex_lock (&result_m);

			/* only be verbose if the file was found
			 */
			if (result_r.found == 1) {

				/* yeah, zylyx found the file, now tell the user <g>
				 */

				scr_rprint (1, win_y, ":01! - ");
				scr_rprintf (5, win_y++, "%s %hu\n",
					result_r.proxy_host, result_r.proxy_port);
			}

			/* unlock the result data for the clients to modify,
			 * then post the permission to act ;-)
			 */
			pthread_mutex_unlock (&result_m);
			sem_post (&permit_action);

			subcount--;	/* one client quitted */
		}
	}

	while (subcount > 0) {
		sem_wait (&client_action);
		pthread_mutex_lock (&result_m);

		if (result_r.found == 1) {
			/* yeah, zylyx found the file <g>
			 */

			scr_rprint (1, win_y, ":01! - ");
			scr_rprintf (5, win_y++, "%s %hu\n",
				result_r.proxy_host, result_r.proxy_port);
		}
		pthread_mutex_unlock (&result_m);
		sem_post (&permit_action);
		subcount--;	/* one client quitted */
	}

	return;
}


void
zyl_assign_prx (proxy **pl)
{
	int	x, y;
	int	n = 0;

	x = 1;
	y = 7;

	for (y = 7; y < SLtt_Screen_Rows - 2; ++y) {
		for (x = 1; x < SLtt_Screen_Cols - 1; ++x) {
			if (pl[n] == NULL) {
				scr_build_box (0, 6, SLtt_Screen_Cols - 1, y + 1);
				scr_build_box (0, y + 1, SLtt_Screen_Cols - 1, SLtt_Screen_Rows - 1);
				win_y = y + 2;
				SLsmg_refresh ();
				return;
			}
			pl[n]->x = x;
			pl[n]->y = y;
			scr_rprint (x, y, ":16.");
			n++;
		}
	}
 
	return;
}
