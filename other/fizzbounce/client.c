
/* bounce 4 all
 * 1999 (c) scut
 *
 * client routines
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "client.h"
#include "network.h"
#include "relay.h"

extern int	vuln;

void *
cl_handle (client *cl)
{
	int		n;
	char		buff[1024];

	pthread_mutex_lock (&cl->cl_mutex);
	printf ("new client from %s port %d\n", inet_ntoa (cl->csa.sin_addr), cl->csa.sin_port);
	pthread_mutex_unlock (&cl->cl_mutex);

	/* now, since we have a client that want's to get relayed, and passed all checks,
	 * establish a connection to the remote server by choosing a bounceip / siteip
	 */

	printf ("control connection to %s:%d\n", cl->connip, cl->connport);

	pthread_mutex_lock (&cl->cl_mutex);
	cl->ss = net_connect (&cl->css, cl->connip, cl->connport, 45);
	if (cl->ss == -1) {
		printf ("failed to relay client from %s:%d to %s:%d\n",
			inet_ntoa (cl->csa.sin_addr), cl->csa.sin_port, cl->connip, cl->connport);
		pthread_mutex_unlock (&cl->cl_mutex);
		return (NULL);
	} else {
		printf ("successfully relayed client from %s:%d to %s:%d\n",
			inet_ntoa (cl->csa.sin_addr), cl->csa.sin_port, cl->connip, cl->connport);
	}
	pthread_mutex_unlock (&cl->cl_mutex);

	/* now since we have both, a connection from the client to us,
	 * and a connection from us to the real server we call the main relay handler
	 */

	if (vuln == 1) {
		net_write (cl->ss, "CONNECT %s:%s HTTP/1.0\n\n", cl->ircip, cl->ircport);
	} else if (vuln == 2) {
		net_write (cl->ss, "POST http://%s:%s/ HTTP/1.0\n\n", cl->ircip, cl->ircport);
	}
//	memset (buff, '\0', sizeof (buff));
//	n = net_rlinet (cl->ss, buff, sizeof (buff), 45);

//	if (n <= 0)
//		goto clerror;

//	printf ("READ: %s\n", buff);
//	if (strncmp (buff, "HTTP/1.0 200", 12) != 0)
//		goto clerror;

	sleep (5);
	memset (buff, '\0', sizeof (buff));
	rly_client (cl);

clerror:
	close (cl->ss);
	close (cl->cs);

	/* the relay handler only exits on failure or connection close request,
	 * either from the remote server or our little client
	 * in any case, we have to terminate the client
	 */

	/* should never happen */
	return (NULL);
}

client *
cl_add (void)
{
	int	n;
	client	*cl;

	cl = (client *) calloc (1, sizeof (client));
	if (cl)
		cl_init (cl);

	return (cl);
}

void
cl_init (client *cl)
{
	pthread_mutex_init (&cl->cl_mutex, NULL);
	return;
}

