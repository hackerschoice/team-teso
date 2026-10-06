/* rpctest
 *
 * simple user interface to the rpc functions.
 * only supports counted strings, integers and opaque data atm.
 * todo: fixed and variable length arrays, hyper-integers, floating points,
 *   discriminated unions.
 *
 * smiler / teso
 */
#include "rpc.h"
#include "pmap.h"

static void
get_line (char *s, char *line, int len)
{
	fputs (s, stdout);
	fflush (stdout);
	fgets (line, len, stdin);
	strip_crlf (line);
	return;
}

int
my_ceil (int a)
{
	int	b = 0;

	b = a % 4;

	if (b) {
		b = 4 - b;
	}
	return (b + a);
}

int
counted_str (char *buf, int len)
{
	int	totlen;

	totlen = my_ceil (len);	
	*(unsigned int *) buf = htonl (totlen);
	memset (buf + 4, 'A', totlen);
	return (totlen + 4);
}

void
build_help (void)
{
	printf ("help\t\t- get help\n" \
		"string\t\t- add a counted string\n" \
		"opaque\t\t- add opaque data\n" \
		"vopaque\t\t- add variable length opaque data\n" \
		"integer\t\t- add an integer\n" \
		"done\t\t- finish building and send the packet\n");
	return;
}

/* careful not to overflow the buffer passed as *pkt.
 */
static int
build_rpc_pkt (char *pkt)
{
	int     argcount,
	        n;
	char    line[20],
	       *args[15],
	       *ptr = pkt;

	printf ("\nStart building the packet now\n\n");
	for (;;) {
		get_line ("[datatype] > ", line, sizeof (line) - 1);
		argcount = parse_args (line, args);

		if (!argcount)
			continue;

		if (!strcasecmp (args[0], "help")) {
			build_help ();
		} else if (!strcasecmp (args[0], "string")) {
			get_line ("[string length] > ", line, sizeof (line) - 1);
			n = atol (line);
			if (!n)
				continue;

			printf ("filling it with %d 'A's\n", my_ceil (n));
			ptr += counted_str (ptr, n);
		} else if (!strcasecmp (args[0], "integer")) {
			get_line ("[number] > ", line, sizeof (line) - 1);
			n = atol (line);
			printf ("adding 4 byte integer %d\n", n);
			*(unsigned int *)ptr = n;
			ptr += 4;
		} else if (!strcasecmp (args[0], "opaque")) {
			get_line ("[length] > ", line, sizeof (line) - 1);
			n = atol (line);

			printf ("filling it with %d 'A's\n", my_ceil (n));
			memset (ptr, 'A', my_ceil (n));
			ptr += my_ceil (n);
		} else if (!strcasecmp (args[0], "vopaque")) {
			get_line ("[length] > ", line, sizeof (line) - 1);
			n = atol (line);

			/* variable opaque is just liked a counted str! */
			ptr += counted_str (ptr, n);
		} else if (!strcasecmp (args[0], "done")) {
			break;
		}
	}
	printf ("finished building packet\n");
	printf ("has length of %d\n", ptr - pkt);
	return (ptr - pkt);
}

int
rpc_send (struct in_addr addr, u_short port, char *buf, int len, int prot)
{
	struct sockaddr_in sa;
	int	fd,
		n;

	if (prot == IPPROTO_UDP)
		fd = socket (AF_INET, SOCK_DGRAM, 0);
	else
		fd = socket (AF_INET, SOCK_STREAM, 0);

	if (fd < 0)
		return (-1);

	bzero (&sa, sizeof (sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons (port);
	sa.sin_addr.s_addr = addr.s_addr;

	if (connect (fd , (struct sockaddr *)&sa, sizeof (sa)) < 0) {
		close (fd);
		return (-1);
	}

	/* I wish the rfc fuqn said you had to do this for tcp... */
	if (prot == IPPROTO_TCP)
		send (fd, &len, sizeof (len), 0);
	n = send (fd, buf, len, 0);
	close (fd);

	return (n);
}

void
build_rpc (void)
{
	mapping *cache;
	char    line[200],
	        packet[4098],
	       *ptr;
	u_int   prog,
	        proc,
		prot,
	        vers;

	if (cached_host.s_addr == 0) {
		printf ("no host cached\n");
		return;
	}
	bzero (line, sizeof (line));

	get_line ("[rpc program] > ", line, sizeof (line) - 1);
	prog = atoi (line);
	if (!prog) {
		printf ("bad program\n");
		return;
	}

	get_line ("[rpc version] > ", line, sizeof (line) - 1);
	vers = atoi (line);
	if (!vers) {
		printf ("bad version\n");
		return;
	}

	get_line ("[protocol] > ", line, sizeof (line) - 1);
	if (!strcasecmp (line, "udp")) {
		prot = IPPROTO_UDP;
	} else if (!strcasecmp (line, "tcp")) {
		prot = IPPROTO_TCP;
	} else {
		printf ("bad proto\n");
		return;
	}


	if ((cache = pmap_find (0, prog, vers, prot)) == NULL) {
		printf ("couldn't find port in pmap cache\n");
		return;
	}


	get_line ("[procedure] > ", line, sizeof (line) - 1);
	if ((proc = atol (line)) == 0) {
		printf ("bad procedure\n");
		return;
	}
	/* now start building the packet... */
	ptr = packet;
	ptr += rpc_make_hdr (cache->prog, proc, cache->vers, ptr);
	ptr += rpc_null_auth (ptr);
	ptr += build_rpc_pkt (ptr);

	printf ("sending rpc packet...\n");

	if (rpc_send (cached_host, cache->port, packet, ptr-packet, prot) < 0) {
		perror ("rpc_send");
	}
	return;
}
