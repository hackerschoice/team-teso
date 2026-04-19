
/* reverb - connection relay utility
 *
 * use it to bounce a connection (datapipe), chat with your friends,
 * interactivly use a active service, tunnel a firewall, bridge a proxy
 * from a protected net together with httptunnel, playing around,
 * ... use it for whatever you want :)
 *
 * 1999-2000 (c) scut of amazing team teso
 *
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if !defined(__FreeBSD__)
#  include <getopt.h>
#endif
#include "network.h"


#define	VERSION	"0.1.0"
#define	AUTHORS	"scut of team teso"

void	usage (void);
void	banner (void);
void	quit (void);
void	relay (int s1, int s2);
int	rly_buff (int srcsock, int dstsock);
long int	timestr_parse (char *timestr);
void	go_daemon (void);
pid_t	z_fork (void);

#define	ACTIVE	1
#define	PASSIVE	2
#define	RELAY	3

int	do_daemon = 0,
	do_quiet = 0,
	do_respawn = 0;
int	o_mode;

/* active data
 */
char *			pair_one;
char *			pair_two;
char			*a_ip1, *a_ip2;
unsigned short int	a_p1, a_p2;
int			s_1, s_2;
struct sockaddr_in	sa_1, sa_2;

long int		timeout_connection = 30;
long int		timeout_listening = 0;

long int		time_instancing = 0;

/* passive data
 */
bound			*b1, *b2;

int
main (int argc, char **argv)
{
	char	c;
	pid_t	pid_inst;
	int	n;	/* temporary return value */

	banner ();

	if (argc < 3)
		usage ();


	while ((c = getopt (argc, argv, "c:l:dqi:r")) != EOF) {
		switch (c) {
		case 'c':
			timeout_connection = timestr_parse (optarg);
			break;
		case 'l':
			timeout_listening = timestr_parse (optarg);
			break;
		case 'd':
			do_daemon = 1;
			/* FALLTHROUGH */
		case 'q':
			do_quiet = 1;
			break;
		case 'i':
			time_instancing = timestr_parse (optarg);
			if (time_instancing <= 0)
				usage ();
			break;
		case 'r':
			do_respawn = 1;
			break;
		default:
			usage ();
			break;
		}
	}

	if (argc - optind != 2)
		usage ();

	pair_one = argv[optind];
	pair_two = argv[optind + 1];

	if (strchr (pair_one, ':') != NULL && strchr (pair_two, ':') != NULL) {
		o_mode = ACTIVE;
	} else if (strchr (pair_one, ':') == NULL && strchr (pair_two, ':') == NULL) {
		o_mode = PASSIVE;
	} else if (strchr (pair_one, ':') == NULL && strchr (pair_two, ':') != NULL) {
		o_mode = RELAY;
	} else {
		usage ();
	}


	/* instancing only possible in active (ie connecting) modes
	 */
	if (o_mode != ACTIVE && time_instancing != 0) {
		fprintf (stderr, "instancing only possible in active (connecting) modes\n");
		exit (EXIT_FAILURE);
	}

	/* silence, please
	 */
	if (do_quiet) {
		stdout = freopen ("/dev/null", "w", stdin);
		stderr = freopen ("/dev/null", "w", stderr);
	}

	/* go daemon if we should
	 */
	if (do_daemon)
	    go_daemon ();

	if (time_instancing != 0) {
		for (;;) {
			pid_inst = z_fork ();
			if (pid_inst < 0) {
				perror ("fork");
				exit (EXIT_FAILURE);
			}

			if (pid_inst == 0)
				goto instance_entry;	/* XXX: valid use of goto ? */

			sleep (time_instancing);
		}
	}

instance_entry:


	/* build to connected sockets, then pass them to relay function
	 */

	if (o_mode == ACTIVE) {
		if (net_parseip (pair_one, &a_ip1, &a_p1) == 0 ||
			net_parseip (pair_two, &a_ip2, &a_p2) == 0)
			usage ();

		printf ("connecting to %s:%hu\n", a_ip1, a_p1);
		s_1 = net_connect (&sa_1, a_ip1, a_p1, timeout_connection);

		if (s_1 != -1) {
			printf ("connecting to %s:%hu\n", a_ip2, a_p2);
			s_2 = net_connect (&sa_2, a_ip2, a_p2, timeout_connection);
		}

		if (s_1 == -1 || s_2 == -1)
			perror ("connections failed: ");

	} else if (o_mode == PASSIVE) {

		fd_set		ac_s;
		int		acp_sock, rj_sock;

		struct timeval *	tv_p = NULL;
		struct timeval		tv_list;

		if (timeout_listening != 0) {
			tv_p = &tv_list;

			memset (&tv_list, '\x00', sizeof (tv_list));
			tv_list.tv_sec = timeout_listening;
			tv_list.tv_usec = 0;
		}

		b1 = net_bind (NULL, atoi (pair_one));
		if (b1 != NULL)
			b2 = net_bind (NULL, atoi (pair_two));

		if (b1 == NULL || b2 == NULL)
			perror ("binding failed: ");

		FD_ZERO (&ac_s);
		FD_SET (b1->bs, &ac_s);
		FD_SET (b2->bs, &ac_s);

		n = select ((b1->bs > b2->bs) ? (b1->bs + 1) : (b2->bs + 1),
			&ac_s, NULL, NULL, tv_p);

		if (n == 0) {
			fprintf (stderr, "passive sleeping timeouted\n");
			exit (EXIT_FAILURE);
		} else if (n < 0) {
			perror ("passive sleeping failed: ");
			exit (EXIT_FAILURE);
		}
		acp_sock = FD_ISSET (b1->bs, &ac_s) ? b1->bs : b2->bs;
		rj_sock = acp_sock == b1->bs ? b2->bs : b1->bs;

		printf ("waiting for connection [%d] on port %hu\n", b1->bs, atoi (pair_one));
		s_1 = net_accept (acp_sock, &sa_1, timeout_listening);
		printf ("connection 1 established\n");
		if (s_1 > 0) {
			printf ("waiting for connection [%d] on port %hu\n", b2->bs, atoi (pair_two));
			s_2 = net_accept (rj_sock, &sa_2, timeout_listening);
			printf ("connection 2 established\n");
		}

		if (s_1 <= 0 || s_2 <= 0)
			perror ("failed to accept connection: ");

	} else {
		if (net_parseip (pair_two, &a_ip1, &a_p1) == 0)
			usage ();

		b1 = net_bind (NULL, atoi (pair_one));
		if (b1 == NULL)
			perror ("binding failed: ");
		printf ("waiting for connection [%d] on port %hu\n", b1->bs, atoi (pair_one));

respawn_lbl:
		s_1 = net_accept (b1->bs, &sa_1, timeout_listening);
		if (s_1 <= 0) {
			if (s_1 == 0) {
				fprintf (stderr, "accepting timeouted\n");
			} else {
				perror ("accepting of an incoming connection failed: ");
			}
			exit (EXIT_FAILURE);
		}
		printf ("connection 1 established\n");

		if (do_respawn) {
			pid_t	cpid = z_fork ();

			if (cpid == -1) {
				perror ("fork");
				exit (EXIT_FAILURE);
			} else if (cpid > 0) {
				close (s_1);
				goto respawn_lbl;
			}
		}

		s_2 = net_connect (&sa_2, a_ip1, a_p1, timeout_connection);
		if (s_2 == -1)
			perror ("connection failed: ");
	}

	printf ("connections successfully established\n");
	printf ("relaying initiated\n");

	relay (s_1, s_2);

	/* should never happen */
	return (0);
}


void
usage (void)
{
	printf ("usage: reverb [options] [ip1:]<port1> [ip2:]<port2>\n\n"
		"options\n"
		"        -c time    connecting timeout (default: 30 seconds)\n"
		"        -l time    listening timeout (default: infinite)\n"
		"        -d         daemon mode, detach and be quiet ;)\n"
		"        -q         quiet operation\n"
		"\n"
		"only in \"active <-> active\" mode\n"
		"        -i time    initiate an instance every once a time, must be > 0s\n"
		"\n"
		"only in \"active -> listening\" mode\n"
		"        -r         respawning mode, fork off once a connection comes in\n"
		"\n"
		"1. case: create a connection between ip1:port and ip2:port\n"
		"2. case: accept a connection from port1 and from port2 and relay\n"
		"3. case: accept a connection from port1 and relay it to ip2 on port2 (datapipe)\n"
		"\n"
		"times are given like this \"40m\" (40 minutes), \"10\" (10 seconds),\n"
		"\"2m30s\" (150 seconds). available are d(ays), h(ours), m(inutes), s(econds).\n"
		"\n");

	exit (EXIT_FAILURE);
}

void
banner (void)
{
	printf("reverb v"VERSION" by "AUTHORS"\n\n");

	return;
}


void
relay (int s_1, int s_2)
{
	int		n, i = 0, maxfd;
	int		bc = 1;
	fd_set		chainset;

	if (s_1 < 0 || s_2 < 0) {
		fprintf (stderr, "relay received: s_1 = %d, s_2 = %d, aborting.\n",
			s_1, s_2);
		exit (EXIT_FAILURE);
	}

	while (bc) {
		FD_ZERO (&chainset);
		FD_SET (s_1, &chainset);
		FD_SET (s_2, &chainset);
		maxfd = ((s_1 > s_2) ? s_1 : s_2) + 1;

		n = select (maxfd, &chainset, NULL, NULL, NULL);
		switch (n) {
		case (0):	break;
		case (-1):	goto bncclss;
		default:	if (FD_ISSET (s_1, &chainset)) {
					i = rly_buff (s_1, s_2);
					if (i <= 0)
						bc = 0;
				} else if (FD_ISSET (s_2, &chainset)) {
					i = rly_buff (s_2, s_1);
					if (i <= 0)
						bc = 0;
				}
				break;
		}
	}

bncclss:
	close (s_1);
	close (s_2);
	return;
}


int
rly_buff (int srcsock, int dstsock)
{
	int		n = 1;
	unsigned char	tbuff[1024];


	n = read (srcsock, tbuff, sizeof (tbuff));

	if (n == 0) {
		return (0);
	} if (n == -1) {
		exit (EXIT_FAILURE);
	}

	write (dstsock, tbuff, n);

	return (n);
}


/* timestr_parse
 *
 * parse the string passed through `timestr' according to this rules:
 *
 * (<number><type>)+
 * number: 0-MAX_INT
 * type: d (days), h (hours), m (minutes), s (seconds)
 *
 * convert all data to seconds and return the sum.
 * print usage in case of failure
 */

long int
timestr_parse (char *timestr)
{
	long int	cur_nr = 0;
	long int	sum_sec = 0;


	if (timestr == NULL || strlen (timestr) == 0)
		return (0);

	while (*timestr != '\x00') {
		if (*timestr >= '0' && *timestr <= '9') {
			cur_nr *= 10;
			cur_nr += *timestr - '0';
		} else {
			switch (*timestr) {
			case 'd':
				sum_sec += cur_nr * (24 * 60 * 60);
				break;
			case 'h':
				sum_sec += cur_nr * (60 * 60);
				break;
			case 'm':
				sum_sec += cur_nr * 60;
				break;
			case 's':
				sum_sec += cur_nr;
				break;
			default:
				usage ();
				break;
			}
			cur_nr = 0;
		}

		timestr += 1;
	}

	/* a type was missing -> seconds
	 */
	if (cur_nr != 0)
		sum_sec += cur_nr;

	return (sum_sec);
}


void
go_daemon (void)
{
	pid_t	pid;


	pid = z_fork ();

	if (pid < 0) {
		perror ("fork");
		exit (EXIT_FAILURE);
	}

	if (pid != 0)
		exit (EXIT_SUCCESS);

	/* in child only */
	return;
}


pid_t
z_fork (void)
{
	pid_t	pid;

	pid = fork ();
	if (pid < 0) {
		return (pid);
	} else if (pid == 0) {
		/* let the child fork again
		 */

		pid = fork ();
		if (pid < 0) {
			return (pid);
		} else if (pid > 0) {
			/* let the child and parent of the second child
			 * exit
			 */
			exit (EXIT_SUCCESS);
		}

		return (0);
	}

	waitpid (pid, NULL, 0);

	return (pid);
}
