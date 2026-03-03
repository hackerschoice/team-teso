
#include <netinet/in.h>
#include <pthread.h>

#ifndef	FIZZ_CLIENT_H
#define	FIZZ_CLIENT_H

typedef struct	client {
	pthread_t		tid;		/* thread id */
	pthread_mutex_t		cl_mutex;	/* client mutex */
	int			cs;		/* client socket */
	struct sockaddr_in	csa;

	char			*connip;
	unsigned short		connport;
	char			*ircip, *ircport;
	int			ss;		/* control connection socket to server */
	struct sockaddr_in	css;		/* server socket address */
} client;

/* cl_handle
 *
 * thread that handles one client. once a new client connects this thread
 * is started and handles anything the client wants.
 * client *cl is a new client structure, which has to be initialized already
 *
 * returns nothing
 */

void	*cl_handle (client *cl);

/* cl_add
 *
 * adds a new client and returns
 * NULL on failure
 * client * to new client if succes
 */
client	*cl_add (void);

/* cl_init
 *
 * initializes a fresh client structure =)
 */
void	cl_init (client *cl);

#endif

