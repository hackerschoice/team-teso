/* grabbb - elite banner scanner
 *
 * by scut of teso (http://teso.scene.at/)
 *
 * nearly all of this code wouldn't have been possible without w. richard stevens
 * excellent network coding book. if you are interested in network coding,
 * there is no way around it. wherever you are now, you showed me how to aquire one
 * of my best skills, and my programs are the result of your teaching abilities.
 *
 * oh yeah, special greetz for this one go to random, who will once be a great
 * socket warrior, promised. :)
 *
 * compilation (successfully tested on any listed platform):
 *
 * OSF1 Tru64 Unix V4.0/V5.0 ...: cc -o grabbb grabbb.c
 * Linux 2.x.x .................: gcc -o grabbb grabbb.c -Wall
 * Free-, Open-, NetBSD, BSDI ..: gcc -o grabbb grabbb.c -Wall
 * SunOS, Solaris ..............: cc -o grabbb grabbb.c -lsocket -lnsl
 * generic .....................: cc -o grabbb grabbb.c
 */


#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define	VERSION	"0.1.0"
#define	AUTHORS	"scut of teso"

#define	NET_CONNTIMEOUT 	30


int	net_conntimeout = NET_CONNTIMEOUT;
int	sb_timeout = 30;


typedef struct {
	struct timeval		tv;	/* first time the socket was used */
	struct in_addr		ip;	/* ip we're connecting to */
	int			already;
	int			portcount;
	unsigned short int	*port;	/* remote port */
	int			socket;	/* phear */
	int			state;
	int			printed;
#define	ST_CONNECTING	1
#define	ST_CONNECTED	2
#define	ST_CONNECTME	3

} sock_buck;


/* for accessibility we go for a struct array, instead of a pointer array or a
 * linked list. if we want to be even faster, we'd have to do fd_set
 * multiplexing, which can be done with threads and jields in unportable code,
 * sorry. mhh... (later) thinking about doing fd_set multiplexing with fork()
 * and fpipe.
 */

#define	GRABBB_OPEN_MAX	250	/* hehe, don't mess with the mighty fdset's limits */
int		open_max = GRABBB_OPEN_MAX;
int		sock_free = GRABBB_OPEN_MAX;
sock_buck	sockets[GRABBB_OPEN_MAX];

/* in_addr structures needed for scanning
 */
struct in_addr	ip_src,
		ip_dst_s,
		ip_dst_e,
		ip_dst_cur;


unsigned long int	ip_list_count = 0;
unsigned long int	ip_list_step = 0;
struct in_addr		*ip_list = NULL;


unsigned short int	port = 21;
unsigned long int	stat_hostcount = 0;
unsigned long int	stat_hosts = 0;
unsigned long int	stat_conn = 0;
unsigned long int	hostcount = 0;
int			verbose = 0;
int			rangemode = 0;

unsigned char		*netmsg = NULL;
unsigned long int	netmsg_s = 0;
int			multiline = 0;

unsigned short int	*portrange = NULL;
int			portcount = 0;


void			usage (char *prg_name);
unsigned short int	*portrange_do (char *portlist);
void			sb_mainloop (void);
void			sb_check (sock_buck *sb_r, int sb_count, fd_set *readset,
	fd_set *writeset);
void			sb_timecheck (sock_buck *sb);
void			sb_print (sock_buck *sb, unsigned char *buf);
void			sb_cfree (sock_buck *sb);
void			sb_free (sock_buck *sb);
int			sb_assign (int sb_count);
sock_buck		*sb_ip_new_g (struct in_addr *ip, unsigned short int *port);
sock_buck		*sb_ip_new (sock_buck *sb, struct in_addr *ip,
	unsigned short int *port);
sock_buck		*sb_fd_findactive (sock_buck *sb_r, int sb_count, fd_set *fds);
sock_buck		*sb_getnew (sock_buck *sb_r, int sb_count);
fd_set			*sb_trigger (sock_buck *sb_r, int sb_count, int *max_fd, int wr);
fd_set			*sb_prepare (fd_set *fds, sock_buck *sb, int *max_fd, int wr);
void			sb_init (sock_buck *sb);
char			*net_getlocalip (void);
/* char			*net_peername (int socket); */
unsigned long int	net_resolve (char *host);
int			net_rtimeout (int fd, int sec);
int			net_printip (struct in_addr *ia, char *str);
void			*xcalloc (int factor, size_t size);
void			*xrealloc (void *mem, size_t newsize);

int
main (int argc, char **argv)
{
	int	summary = 0;
	char	chr;
	FILE	*ip_file = NULL;
	int	ip_start_flag = 0,
		ip_end_flag = 0;

	if (argc < 4)
		usage (argv[0]);

	while ((chr = getopt (argc - 1, argv, "x:t:i:a:b:mvs")) != EOF) {
		switch (chr) {
		case 'x':	open_max = atoi (optarg);
				sock_free = open_max;
				break;
		case 't':	sb_timeout = atoi (optarg);
				break;
		case 'i':	ip_file = fopen (optarg, "r");
				break;
		case 'a':	ip_dst_s.s_addr = net_resolve (optarg);
				ip_start_flag = 1;
				break;
		case 'b':	ip_dst_e.s_addr = net_resolve (optarg);
				ip_end_flag = 1;
				break;
		case 'm':	multiline = 1;
				break;
		case 'v':	verbose = 1;
				break;
		case 's':	summary = 1;
				break;
		default:	break;
		}
	}

	if (net_rtimeout (STDIN_FILENO, 1) == 1) {
		unsigned char	*fooptr;
		int		foolen = 1;

		for (netmsg_s = 128 ; foolen != 0 ; netmsg_s += 128) {
			netmsg = xrealloc (netmsg, netmsg_s);
			fooptr = netmsg + netmsg_s - 128;
			foolen = read (STDIN_FILENO, fooptr, 127);
			if (foolen == -1) {
				fprintf (stderr, "failed to read from stdin\n");
				exit (EXIT_FAILURE);
			}
			netmsg_s -= (128 - foolen);
		}
		netmsg_s -= 128;
		if (verbose)
			printf ("printing to sockets (size = %li):\n%s\n", netmsg_s, netmsg);
	}

	/* sanity checking
	 */
	if (ip_start_flag ^ ip_end_flag) {
		printf ("you must supply either an iprange through using both options,\n"
			"-a and -b, or you should supply an iprange file through -i.\n\n");
		exit (EXIT_FAILURE);
	}
	if (ip_start_flag == 1 && ip_end_flag == 1 &&
		(ip_dst_s.s_addr == 0 || ip_dst_e.s_addr == 0))
	{
		printf ("when using the range mode you should supply valid ip ranges, lamer\n\n");
		exit (EXIT_FAILURE);
	}
	if (ip_start_flag == 1 && ip_end_flag == 1) {
		rangemode = 1;
	} else if (ip_file == NULL) {
		printf ("supply a valid ip file if you don't use the range mode, lamer\n\n");
		exit (EXIT_FAILURE);
	} else {
		char	line[128];

		memset (line, '\0', sizeof (line));
		for (ip_list_count = 1 ;
			fgets (line, sizeof (line) - 1, ip_file) != NULL ; )
		{
			while (strlen (line) && (line[strlen (line) - 1] == '\n' || line[strlen (line) - 1] == '\r'))
				line[strlen (line) - 1] = '\0';

			ip_list = xrealloc (ip_list, ip_list_count * sizeof (struct in_addr));
			if (verbose) {
				printf ("(%8li) adding %s\n", ip_list_count, line);
			}

			ip_list[ip_list_count - 1].s_addr = net_resolve (line);
#ifdef DEBUG
			printf ("ip_list[ip_list_count - 1].s_addr = %08x\n", ip_list[ip_list_count - 1].s_addr);
#endif
			if (ip_list[ip_list_count - 1].s_addr != 0)
				++ip_list_count;
			memset (line, '\0', sizeof (line));
		}

		ip_list_count--;
		rangemode = 0;
	}

	if (rangemode) {
		hostcount = (ntohl (ip_dst_e.s_addr) - ntohl (ip_dst_s.s_addr)) + 1;
	} else {
		hostcount = ip_list_count;
	}

	if (hostcount < open_max) {
		sock_free = open_max = hostcount;
		if (verbose)
			printf ("truncated maximum number of open sockets to %d\n", open_max);
	}

	portrange = portrange_do (argv[optind]);
	if (verbose)
		printf ("%d ports to scan per host, thats %lu connects\n", portcount, portcount * hostcount);

	if (rangemode)
		ip_dst_cur.s_addr = ip_dst_s.s_addr;

	sb_mainloop ();

	if (summary) {
		printf ("finished scanning %lu hosts.\ngot %lu response%s from %lu host%s.\n",
			stat_hosts, stat_conn, (stat_conn > 1) ? "s" : "", stat_hostcount,
			(stat_hostcount > 1) ? "s" : "");
	}

	exit (EXIT_SUCCESS);
}



unsigned short int *
portrange_do (char *portlist)
{
	char			*parse_ptr = portlist;
	unsigned short int	*new = NULL;

	for (portcount = 1 ;
		(new = realloc (new, (portcount + 1) * sizeof (unsigned short int))) != NULL ;
		++portcount)
	{
		unsigned short int	port = 0;

		new[portcount - 1] = new[portcount] = 0;

		while (isdigit (*parse_ptr)) {
			port *= 10;
			port += (*parse_ptr - '0');
			parse_ptr++;
		}

		if (*parse_ptr == ':') {
			new[portcount - 1] = port;
			parse_ptr++;
		} else if (*parse_ptr == '\0') {
			new[portcount - 1] = port;
			return (new);
		} else {
			printf ("illegal portlist supplied, check your eyes, lamer\n\n");
			exit (EXIT_FAILURE);
		}
	}

	printf ("generic error on portlist parsing\n\n");

	exit (EXIT_FAILURE);
}


void
usage (char *prg_name)
{
	printf ("grabbb "VERSION" by "AUTHORS"\n\n"
		"usage: %s [options] <port>[:port2[:port3[...]]]\n\n"
		"__options\n"
		"\t-x <maxsock>     maximum number of sockets to use (default 250)\n"
		"\t-t <seconds>     connection timeout\n"
		"\t-i <file>        file to get ip's from (ip's, not names)\n"
		"\t-a <startip>     range scanning (startip)\n"
		"\t-b <endip>       range scanning (endip)\n"
		"\t-m               multiline mode (grab not just the first line)\n"
		"\t-v               be more verbose\n"
		"\t-s               print summary information after scan\n\n"
		"you can also pipe something to the program, which will be printed to any\n"
		"successful connection the program experiences\n\n", prg_name);

	exit (EXIT_SUCCESS);
}


void
sb_mainloop (void)
{
	int		n;
	fd_set		*fds_r, *fds_w;
	int		max_fd;
	struct timeval	tv = { 2, 0 };		/* 2 seconds timeout */
	int		eoscan;

	while (1) {
		eoscan = sb_assign (open_max);
#ifdef DEBUG
		printf ("eoscan = %d -- sock_free = %d -- open_max = %d\n", eoscan, sock_free, open_max);
#endif
		if (eoscan == -1 && sock_free == open_max) {
			return;
		}

		fds_r = fds_w = NULL;
		fds_r = sb_trigger (sockets, open_max, &max_fd, 0);
		fds_w = sb_trigger (sockets, open_max, &max_fd, 1);

#ifdef DEBUG
		printf ("fds_r = %08x -- fds_w = %08x -- eoscan = %d\n", fds_r, fds_w, eoscan);
#endif
		if (fds_r == NULL && fds_w == NULL && eoscan == -1)
			return;
		n = select (max_fd, fds_r, fds_w, NULL, &tv);
#ifdef DEBUG
		printf ("select() = %d\n", n);
#endif
		if (n == -1) {
			perror ("select failed");
			exit (EXIT_FAILURE);
		}

		sb_check (sockets, open_max, fds_r, fds_w);

		free (fds_r);
		free (fds_w);
	}

}


/* please ignore the bad style exposed here
 */

void
sb_check (sock_buck *sb_r, int sb_count, fd_set *readset, fd_set *writeset)
{
	int		i,
			error,
			len = sizeof (error);
	sock_buck	*sb;

	for (i = 0 ; i < sb_count ; ++i) {
		sb = &(sb_r[i]);
		if (sb->socket != 0 && sb->state == ST_CONNECTING) {
			if (FD_ISSET (sb->socket, readset) || FD_ISSET (sb->socket, writeset)) {
				if (FD_ISSET (sb->socket, readset) && FD_ISSET (sb->socket, writeset)) {
					if (getsockopt (sb->socket, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
						sb_cfree (sb);
					} else if (error == 0) {
						/* we experienced a successful connection
						 */
						sb->state = ST_CONNECTED;
						if (sb->already == 0)
							stat_hostcount++;
						sb->already = 1;
						sb->printed = 0;
						if (netmsg != NULL)
							write (sb->socket, netmsg, netmsg_s);
					} else {
						sb_cfree (sb);
					}
				} else if (FD_ISSET (sb->socket, readset) == 0 && FD_ISSET (sb->socket, writeset) != 0) {
					sb->state = ST_CONNECTED;
					if (sb->already == 0)
						stat_hostcount++;
					sb->already = 1;
					sb->printed = 0;
					if (netmsg != NULL)
						write (sb->socket, netmsg, netmsg_s);
				}
			}
		} else if (sb->socket != 0 && sb->state == ST_CONNECTED && FD_ISSET (sb->socket, readset)) {
			int		n;
			unsigned char	buf[256];

			memset (buf, '\0', sizeof (buf));
			n = read (sb->socket, buf, sizeof (buf) - 1);
			if (n <= 0) {
				sb_cfree (sb);
			} else {
				sb_print (sb, buf);
			}
		}

		sb_timecheck (sb);
	}

	return;
}


void
sb_cfree (sock_buck *sb)
{
	sb->portcount++;
	if (sb->portcount >= portcount) {
		sb_free (sb);
	} else {
		if (sb->socket != 0)
			close (sb->socket);
		sb->socket = 0;
		sb->state = ST_CONNECTME;
	}

	return;
}


void
sb_timecheck (sock_buck *sb)
{
	unsigned long	seconds,
			microseconds;
	struct timeval	tv_cur;

	gettimeofday (&tv_cur, NULL);

	seconds = tv_cur.tv_sec - sb->tv.tv_sec;
	if (tv_cur.tv_usec >= sb->tv.tv_usec) {
		microseconds = tv_cur.tv_usec - sb->tv.tv_usec;
	} else {
		microseconds = sb->tv.tv_usec + tv_cur.tv_usec;
		seconds--;	/* seconds must be at least one, sapienta sat */
	}

	if (microseconds >= 500000)
		seconds++;

	if (seconds >= sb_timeout) {
		if (sb->state == ST_CONNECTED) {
			sb_print (sb, NULL);
		}
		sb_cfree (sb);
	}

	return;
}


void
sb_print (sock_buck *sb, unsigned char *buf)
{
	unsigned char	*foo;
	char		ip[64];

	net_printip (&sb->ip, ip);

	if (buf != NULL && multiline == 0 && strlen ((const char *) buf) > 0) {
		for (foo = buf ;
			((unsigned long)((unsigned long)foo -
			(unsigned long)buf) < strlen ((const char *) buf)) &&
			*foo != '\r' && *foo != '\n' &&
			*foo != '\x00'; ++foo)
			;
		*foo = '\x00';
	}

	if (sb->printed == 0) {
		sb->printed = 1;
		stat_conn++;
		if (buf != NULL) {
			printf ("%s:%hu:%c%s%s", ip, sb->port[sb->portcount],
				(multiline == 0) ? ' ' : '\n', buf,
				(multiline == 0) ? "\n" : "");
		} else {
			printf ("%s:%hu:\n", ip, sb->port[sb->portcount]);
		}
	} else if (buf != NULL) {
		printf ("%s", buf);
	}


	return;
}


void
sb_free (sock_buck *sb)
{
	if (sb->socket != 0)
		close (sb->socket);

	sb_init (sb);

	sock_free++;

	return;
}


int
sb_assign (int sb_count)
{
	int		cnx = 0;	/* number of connects issued */
	sock_buck	*sb;
	int		i;


	for (i = 0 ; i < sb_count ; ++i) {
		sb = &(sockets[i]);

		if (sb->state == ST_CONNECTME) {
			sb_ip_new (sb, &sb->ip, portrange);
		}
	}

	while (sock_free > 0) {
		sock_buck	*sb;

		if (ip_list_count > 0) {
			if (ip_list_step >= ip_list_count)
				return (-1);

			sb = sb_ip_new_g (&(ip_list[ip_list_step]), portrange);
			ip_list_step++;
		} else {
			if (ntohl (ip_dst_cur.s_addr) > ntohl (ip_dst_e.s_addr))
				return (-1);

			sb = sb_ip_new_g (&ip_dst_cur, portrange);
			ip_dst_cur.s_addr = ntohl (ntohl (ip_dst_cur.s_addr) + 1);
		}

		stat_hosts++;
		cnx++;
		--sock_free;
	} 

	return (cnx);
}


sock_buck *
sb_ip_new_g (struct in_addr *ip, unsigned short int *port)
{
	sock_buck		*new;

	new = sb_getnew (sockets, open_max);
	sb_init (new);
	new->port = port;
	new->portcount = 0;

	return (sb_ip_new (new, ip, port));
}


sock_buck *
sb_ip_new (sock_buck *sb, struct in_addr *ip, unsigned short int *port)
{
	int			n;
	sock_buck		*new = sb;
	struct sockaddr_in	sa;

	if (new == NULL)
		return (NULL);

	if (&new->ip != ip)
		memcpy (&new->ip, ip, sizeof (struct in_addr));
	memset (&sa, '\0', sizeof (struct sockaddr_in));
        sa.sin_family = AF_INET;
        sa.sin_port = htons (new->port[new->portcount]);

        new->socket = socket (sa.sin_family, SOCK_STREAM, 0);

	sa.sin_addr.s_addr = ip->s_addr;

	/* fear this lame socket coding style =) (didn't learned this from stevens
	 * though :)
	 */
	fcntl (new->socket, F_SETFL, (fcntl (new->socket, F_GETFL, 0) | O_NONBLOCK));

        n = connect (new->socket, (struct sockaddr *) &sa, sizeof (struct sockaddr_in));
	gettimeofday (&new->tv, NULL);
        if (n < 0 && errno != EINPROGRESS) {
		sb_cfree (new);
		return (new);
        } else if (n == 0) {
                new->state = ST_CONNECTED;
		if (new->already == 0)
			stat_hostcount++;
		new->already = 1;
		return (new);
	}

	new->state = ST_CONNECTING;

	return (new);
}


sock_buck *
sb_fd_findactive (sock_buck *sb_r, int sb_count, fd_set *fds)
{
	int	i;

	for (i = 0 ; i < sb_count ; ++i) {
		int	socket = sb_r[i].socket;

		if (socket != 0 && FD_ISSET (socket, fds) != 0)
			return (&sb_r[i]);
	}

	return (NULL);
}


sock_buck *
sb_getnew (sock_buck *sb_r, int sb_count)
{
	int	i;

	for (i = 0 ; i < sb_count ; ++i) {
		if (sb_r[i].state == 0)
			return (&sb_r[i]);
	}

	return (NULL);
}


fd_set *
sb_trigger (sock_buck *sb_r, int sb_count, int *max_fd, int wr)
{
	int	i;
	fd_set	*fds = NULL;

	for (i = 0 ; i < sb_count ; ++i) {
		fds = sb_prepare (fds, &sb_r[i], max_fd, wr);
	}

	*max_fd = *max_fd + 1;

	return (fds);
}


fd_set *
sb_prepare (fd_set *fds, sock_buck *sb, int *max_fd, int wr)
{
	/* if socket is empty or socket is already part of fd_set,
	 * which means we fucked the structs somehow, then skip
	 */
	if (sb->socket == 0)
		return (fds);

	if (sb->state == ST_CONNECTED && wr == 1)
		return (fds);

	if (fds == NULL) {
		fds = xcalloc (1, sizeof (fd_set));
		FD_ZERO (fds);
		*max_fd = 0;
	}

	if (FD_ISSET (sb->socket, fds) != 0)
		return (fds);

	FD_SET (sb->socket, fds);
	if (sb->socket > *max_fd)
		*max_fd = sb->socket;

	return (fds);
}


void
sb_init (sock_buck *sb)
{
	memset (&sb->ip, '\0', sizeof (struct in_addr));
	sb->port = NULL;
	sb->socket = 0;
	sb->state = 0;
	sb->already = 0;
	sb->printed = 0;

	return;
}


char *
net_getlocalip (void)
{
	struct sockaddr_in	pf;
	char			name[255];

	memset (name, '\0', sizeof (name));

	if (gethostname (name, sizeof (name) - 1) == -1) {
		return (NULL);
	}

	pf.sin_addr.s_addr = net_resolve (name);

	return (strdup (inet_ntoa (pf.sin_addr)));;
}


unsigned long int
net_resolve (char *host)
{
	long		i;
	struct hostent	*he;

	i = inet_addr (host);
	if (i == -1) {
		he = gethostbyname (host);
		if (he == NULL) {
			return (0);
		} else {
			return (*(unsigned long *) he->h_addr);
		}
	}
	return (i);
}


int
net_rtimeout (int fd, int sec)
{
	fd_set		rset;
	struct timeval	tv;
	int		n, error, flags;

	error = 0;
	flags = fcntl(fd, F_GETFL, 0);
	n = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (n == -1)
		return (-1);

	FD_ZERO(&rset);
	FD_SET(fd, &rset);
	tv.tv_sec = sec;
	tv.tv_usec = 0;

	/* now we wait until more data is received then the tcp low level watermark,
	 * which should be setted to 1 in this case (1 is default)
	 */

	n = select(fd + 1, &rset, NULL, NULL, &tv);
	if (n == 0) {
		n = fcntl(fd, F_SETFL, flags);
		if (n == -1)
			return (-1);
		errno = ETIMEDOUT;
		return (-1);
	}
	if (n == -1) {
		return (-1);
	}
	/* socket readable ? */
	if (FD_ISSET(fd, &rset)) {
		n = fcntl(fd, F_SETFL, flags);
		if (n == -1)
			return (-1);
		return (1);
	} else {
		n = fcntl(fd, F_SETFL, flags);
		if (n == -1)
			return (-1);
		errno = ETIMEDOUT;
		return (-1);
	}
}


int
net_printip (struct in_addr *ia, char *str)
{
        unsigned char   *ipp;

        ipp = (unsigned char *) &ia->s_addr;
	sprintf (str, "%d.%d.%d.%d", ipp[0], ipp[1], ipp[2], ipp[3]);

	return (0);
}


void *
xcalloc (int factor, size_t size)
{
	void	*bla;

	bla = calloc (factor, size);

	if (bla == NULL) {
		fprintf (stderr, "no memory left\n");
		exit (EXIT_FAILURE);
	}

	return (bla);
}


void *
xrealloc (void *mem, size_t newsize)
{
	void	*bla;

	bla = realloc (mem, newsize);

	if (bla == NULL) {
		fprintf (stderr, "no memory left\n");
		exit (EXIT_FAILURE);
	}

	return (bla);
}


