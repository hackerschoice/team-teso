
/* bounce 4 all
 * 1999 (c) scut
 *
 * main routines
 */

#define	B4A_MAIN_C

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "relay.h"
#include "client.h"
#include "main.h"
#include "network.h"

bound	*b;
int	vuln = 0;	/* 1 = connect, 2 = post */

int
main (int argc, char **argv)
{
	int	n;

	banner ();

	if (argc != 8) {
		usage ();
	}

/*	if (fork () != 0)
		exit (0);
*/
	if (argv[1][0] == 'c')
		vuln = 1;
	if (argv[1][0] == 'p')
		vuln = 2;
	if (vuln == 0)
		usage ();


	b = net_bind (argv[2], atoi (argv[3]));
	if (b == NULL) {
		printf ("cannot bind to %s:%u\n", argv[2], atoi (argv[3]));
		quit ();
	}
	printf ("bound to %s, port %u\n", argv[2], atoi (argv[3]));

	srv_main (argv[4], argv[5], argv[6], argv[7]);

	/* should never happen */
	return (0);
}

void
srv_main (char *connip, char *connport, char *ircip, char *ircport)
{
	struct sockaddr_in	csa;
	client			*cnew;
	int			cs, n;

	while (1) {
		cs = net_accept (b->bs, &csa, 20);
		if (cs == -1) {
			quit();
		}

		/* if we actually experience a new connection start a new client thread */
		if (cs) {
			cnew = cl_add ();
			if (cnew == NULL) {
				printf ("cannot add new client\n");
			} else {
				pthread_mutex_lock (&cnew->cl_mutex);
				cnew->cs = cs;
				cnew->connip = strdup (connip);
				cnew->connport = atoi (connport);
				cnew->ircip = strdup (ircip);
				cnew->ircport = strdup (ircport);
				memcpy (&cnew->csa, &csa, sizeof (struct sockaddr_in));
				pthread_mutex_unlock (&cnew->cl_mutex);

				n = pthread_create (&cnew->tid, NULL, (void *) cl_handle, (void *) cnew);
				if (n == -1) {
					printf ("cannot create new client thread: %s\n", strerror (errno));
				}
			}
		}
	}

	quit ();
}

void
usage (void)
{
	printf ("usage: fizzbnc <c|p> <local-ip | *> <local-port> <squid-proxy>\n"
                "             <proxy-port> <irc-host> <irc-port>\n");
	exit (EXIT_FAILURE);
	return;
}

void
banner (void)
{
	printf ("fizzbounce "VERSION" by "AUTHORS"\n");
	return;
}

void
quit (void)
{
	printf ("shutting fizzbounce down.\n");

	/* terminate main thread */
	exit (0);
}

