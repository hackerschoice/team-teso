/* zylyx - file find
 *
 * proxy routines include file
 *
 * by team teso
 */

#ifndef	_ZYL_PROXY_H
#define	_ZYL_PROXY_H

#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include "zylyx.h"

typedef struct	scan_t {
	proxy		*proxy;
	result		*result_r;
	pthread_mutex_t	*result_m;
	sem_t		*permit_action;
	sem_t		*client_action;
} scan_t;

proxy		**prx_load (char *filename, int *pc);
void		prx_fire (proxy *mp, result *result_r, pthread_mutex_t *result_m,
			sem_t *permit_action, sem_t *client_action);
void		*prx_scan (scan_t *sc);
proxy		*prx_read (FILE *fp);
long int	prx_count (char *filename);

#endif

