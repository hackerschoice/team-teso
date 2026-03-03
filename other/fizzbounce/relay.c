
/* bounce 4 all
 * 1999 (c) scut
 *
 * relay routines
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "client.h"
#include "network.h"
#include "relay.h"

void
rly_client (client *cl)
{
	int		n, i = 0, maxfd;
	int		bc = 1;
	char		cbuff[4096], sbuff[4096];
	fd_set		chainset;
	struct timeval	tval;

	pthread_mutex_lock (&cl->cl_mutex);

	/* now, since we authorized us, we should just chain every control
	 * connection command except it is in our parser array, in this case
	 * we should call the parser function :)
	 */

	pthread_mutex_unlock (&cl->cl_mutex);

	memset (cbuff, '\0', sizeof (cbuff));
	memset (sbuff, '\0', sizeof (sbuff));

	while (bc) {
		pthread_mutex_lock (&cl->cl_mutex);

		FD_ZERO (&chainset);
		FD_SET (cl->cs, &chainset);
		FD_SET (cl->ss, &chainset);
		maxfd = ((cl->cs > cl->ss) ? cl->cs : cl->ss) + 1;
		tval.tv_sec = 1;
		tval.tv_usec = 0;

		/* choose a dual approach, a bit polling (once per second, but also
		 * select, to let the mutex live
		 */
		n = select (maxfd, &chainset, NULL, NULL, &tval);
		switch (n) {
		case (0):	break;
		case (-1):	return;
		default:	if (FD_ISSET (cl->cs, &chainset)) {
					i = rly_rb (cl->cs, cbuff, sizeof (cbuff));
					if (i <= 0) {
						bc = 0;
					} else {
						rly_clparse (cl, cbuff, sizeof (cbuff));
					}
				} else if (FD_ISSET (cl->ss, &chainset)) {
					i = rly_rb (cl->ss, sbuff, sizeof (sbuff));
					if (i <= 0) {
						bc = 0;
					} else {
						rly_srvparse (cl, sbuff, sizeof (sbuff));
					}
				}
				break;
		}

		pthread_mutex_unlock (&cl->cl_mutex);
	}

	switch (i) {
	case (0):	printf ("connection close\n");
			break;
	case (-1):	printf ("system error (%d)\n", errno);
			break;
	case (-2):	printf ("buffer too short to hold all recv data\n");
			break;
	default:	printf ("weird i = %d\n", i);
			break;
	}

	return;
}

int
rly_clparse (client *cl, char *buffer, int buflen)
{
	int	r, n, llen, prslen;

	while ((llen = net_tline (buffer, buflen)) != -1) {

/*		if (strncmp (buffer, "USER", 4) == 0) {
			char	*a, *b;
			int	n;

			n = sscanf (buffer, "USER %a[^ ] \"%*[^\"]\" \"%*[^\"]\"%*[^:]:%as\n",
				&a, &b);
			if (n != 2) {
				printf ("wrong user command: %s\n", buffer);
				goto pfft;
			}
			net_write (cl->ss, "USER %s \"%s\" \"%s\" :%s", a, cl->connip, cl->ircip, b);
			goto mhhh;
		}
*/
		/* if line was terminated, replace \n with \0 */
pfft:		buffer[llen-1] = '\0';
		net_write (cl->ss, "%s\n", buffer);

mhhh:		memmove (buffer, buffer + llen, buflen - llen);

		memset (buffer + (buflen - llen), '\0', llen);
	}

	return (1);
}

int
rly_srvparse (client *cl, char *buffer, int buflen)
{
	int	code, r, n, llen;

	while ((llen = net_tline (buffer, buflen)) != -1) {
		buffer[llen-1] = '\0';
		net_write (cl->cs, "%s\n", buffer);
		memmove (buffer, buffer + llen, buflen - llen);
		memset (buffer + (buflen - llen), '\0', llen);
	}
	return (1);
}

int
rly_rb (int fd, char *buffer, int buflen)
{
	int	n, csize;

	/* assume asciiz buffer, line based,
	 * now append the read data to this buffer
	 */

	csize = strlen (buffer);
	if (csize >= (buflen - 1))
		return (-2);		/* buffer size exceeded, lame script kiddie */

	n = read (fd, buffer + csize, buflen - csize - 1);
	switch (n) {
	case (0):	return (0);
	case (-1):	return (-1);
	default:	return (strlen (buffer));
	}

	/* should never happen */
	return (0);
}

