/* zylyx - file find
 *
 * proxy routines
 *
 * by team teso
 */

#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "common.h"
#include "network.h"
#include "screen.h"
#include "proxy.h"
#include "zylyx.h"


void
prx_fire (proxy *mp, result *result_r, pthread_mutex_t *result_m,
	sem_t *permit_action, sem_t *client_action)
{
	pthread_t	tid;
	scan_t		*new = xcalloc (1, sizeof (scan_t));
	int		n;

	new->proxy = mp;
	new->result_r = result_r;
	new->result_m = result_m;
	new->permit_action = permit_action;
	new->client_action = client_action;

	n = pthread_create (&tid, NULL, (void *) prx_scan, (void *) new);

	return;
}


int
prx_findfile (scan_t *sc)
{
	int			n, m, linecount;
	int			prx_fd;
	struct sockaddr_in	csa;
	char			*readline;

	prx_fd = net_connect (&csa, sc->proxy->host, sc->proxy->port, NULL, 0, 20);
	if (prx_fd == -1) {
		scr_rprint (sc->proxy->x, sc->proxy->y, ":04-");
		return (-1);
	}

	scr_rprint (sc->proxy->x, sc->proxy->y, ":02c");
	net_write (prx_fd, "GET %s HTTP/1.0\n\n", sc->proxy->file); 

	scr_rprint (sc->proxy->x, sc->proxy->y, ":02g");

	for (linecount = 0 ;
		(((n = net_rlineta (prx_fd, &readline, 30)) > 0) &&
		linecount < 10) ;
		linecount++)
	{
		int	p;

		scr_rprint (sc->proxy->x, sc->proxy->y, ":02r");

		m = sscanf (readline, "HTTP/1.0 %d", &p);
		free (readline);
		if (m != 1) {
			scr_rprint (sc->proxy->x, sc->proxy->y, ":03j");
		} else if (p < 200 || p >= 300) {
			scr_rprint (sc->proxy->x, sc->proxy->y, ":04f");
			close (prx_fd);
		} else {
			close (prx_fd);
			return (1);
		}
	}

	if (n <= 0)
		scr_rprint (sc->proxy->x, sc->proxy->y, ":04t");
	return (0);
}


void *
prx_scan (scan_t *sc)
{
	int		n;

	/* don't mess with the system resources, else we get stuck after like
	 * 1050's proxy fires =)
	 */
	pthread_detach (pthread_self ());
	scr_rprint (sc->proxy->x, sc->proxy->y, ":05o");

	/* scan the proxy for the file, oh yeah
	 */
	n = prx_findfile (sc);

	/* post the result to the main thread using shared process memory
	 * and semaphores for activation
	 */
	sem_wait (sc->permit_action);
	pthread_mutex_lock (sc->result_m);
	switch (n) {
	case (-1):
	case (0):
		/* file not found or connection / proxy error
		 */

		sc->result_r->found = 0;
		break;
	case (1):
		/* file successfully found
		 */

		sc->result_r->found = 1;
		sc->result_r->proxy_host = sc->proxy->host;
		sc->result_r->proxy_port = sc->proxy->port;
		sc->result_r->file = sc->proxy->file;
		scr_rprint (sc->proxy->x, sc->proxy->y, ":01!");
		break;

	default:
		break;
	}
	sem_post (sc->client_action);
	pthread_mutex_unlock (sc->result_m);

	free (sc);

	pthread_exit (NULL);

	return (NULL);	/* gcc eat that ;*/
}


proxy **
prx_load (char *filename, int *pc)
{
	FILE		*fp;
	proxy		**pl;
	long int	n, c;

	*pc = n = prx_count (filename);
	pl = xcalloc (n + 2, sizeof (proxy *));
	pl[n] = NULL;	/* EOA */

	fp = fopen (filename, "r");
	if (fp == NULL)
		exit (EXIT_FAILURE);

	for (c = 0; c < n; ++c) {
		pl[c] = prx_read (fp);
		if (pl[c] == NULL) {
			c--;
			n--;
		}
//		printf ("%s:%hu\n", pl[c]->host, pl[c]->port);
	}

	return (pl);
}


proxy *
prx_read (FILE *fp)
{
	proxy	*prx = xcalloc (1, sizeof (proxy));
	char	buf[1024];
	int	n;

	fgets (buf, sizeof (buf) - 1, fp);
	n = net_parseip (buf, &prx->host, &prx->port);
	if (n == 0) {
		free (prx);
		prx = NULL;
	}

	return (prx);
}


long int
prx_count (char *filename)
{
	FILE		*fp;
	long int	n;
	char		buf[1024];

	fp = fopen (filename, "r");
	if (fp == NULL)
		exit (EXIT_FAILURE);

	for (n = 0; fgets (buf, sizeof (buf), fp) != NULL; ++n)
		;

	fclose (fp);

	return (n);
}


