
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "common.h"

#ifdef	DEBUG
void
debugp (char *filename, const char *str, ...)
{
	FILE		*fp;	/* temporary file pointer */
	va_list		vl;

	fp = fopen (filename, "a");
	if (fp == NULL)
		return;

	va_start (vl, str);
	vfprintf (fp, str, vl);
	va_end (vl);

	fclose (fp);

	return;
}

void
hexdump (char *filename, unsigned char *data, unsigned int amount)
{
	FILE		*fp;	/* temporary file pointer */
	unsigned int	dp, p;	/* data pointer */
	const char	trans[] = "................................ !\"#$%&'()*+,-./0123456789"
					":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
					"nopqrstuvwxyz{|}~...................................."
					"....................................................."
					"........................................";

	fp = fopen (filename, "a");
	if (fp == NULL)
		return;

	fprintf (fp, "\n-packet-\n");

	for (dp = 1; dp <= amount; dp++) {
		fprintf (fp, "%02x ", data[dp-1]);
		if ((dp % 8) == 0)
			fprintf (fp, " ");
		if ((dp % 16) == 0) {
			fprintf (fp, "| ");
			p = dp;
			for (dp -= 16; dp < p; dp++)
				fprintf (fp, "%c", trans[data[dp]]);
			fflush (fp);
			fprintf (fp, "\n");
		}
		fflush (fp);
	}
	if ((amount % 16) != 0) {
		p = dp = 16 - (amount % 16);
		for (dp = p; dp > 0; dp--) {
			fprintf (fp, "   ");
			if (((dp % 8) == 0) && (p != 8))
				fprintf (fp, " ");
			fflush (fp);
		}
		fprintf (fp, " | ");
		for (dp = (amount - (16 - p)); dp < amount; dp++)
			fprintf (fp, "%c", trans[data[dp]]);
		fflush (fp);
	}
	fprintf (fp, "\n");

	fclose (fp);
	return;
}

#endif


/* m_random
 *
 * return a random number between `lowmark' and `highmark'
 */

int
m_random (int lowmark, int highmark)
{
	long int	rnd;

	/* flip/swap them in case user messed up
	 */
	if (lowmark > highmark) {
		lowmark ^= highmark;
		highmark ^= lowmark;
		lowmark ^= highmark;
	}
	rnd = lowmark;

	srandom ((unsigned int) time (NULL));
	rnd += (random () % (highmark - lowmark));

	/* this is lame, i know :)
	 */
	return (rnd);
}


/* set_tv
 *
 * initializes a struct timeval pointed to by `tv' to a second value of
 * `seconds'
 *
 * return in any case
 */

void
set_tv (struct timeval *tv, int seconds)
{
	tv->tv_sec = seconds;
	tv->tv_usec = 0;

	return;
}


/* xstrupper
 *
 * uppercase a string `str'
 *
 * return in any case
 */

void
xstrupper (char *str)
{
	for (; *str != '\0'; ++str) {
		if (*str >= 'a' && *str <= 'z') {
			*str -= ('a' - 'A');
		}
	}

	return;
}


/* concating snprintf
 *
 * determines the length of the string pointed to by `os', appending formatted
 * string to a maximium length of `len'.
 *
 */

void
scnprintf (char *os, size_t len, const char *str, ...)
{
	va_list	vl;
	char	*ostmp = os + strlen (os);

	va_start (vl, str);
	vsnprintf (ostmp, len - strlen (os) - 1, str, vl);
	va_end (vl);

	return;
}

unsigned long int
tdiff (struct timeval *old, struct timeval *new)
{
	unsigned long int	time1;

	if (new->tv_sec >= old->tv_sec) {
		time1 = new->tv_sec - old->tv_sec;
		if ((new->tv_usec - 500000) >= old->tv_usec)
			time1++;
	} else {
		time1 = old->tv_sec - new->tv_sec;
		if ((old->tv_usec - 500000) >= new->tv_usec)
			time1++;
	}

	return (time1);
}


/* ipv4_print
 *
 * padding = 0 -> don't padd
 * padding = 1 -> padd with zeros
 * padding = 2 -> padd with spaces
 */

char *
ipv4_print (char *dest, struct in_addr in, int padding)
{
	unsigned char	*ipp;

	ipp = (unsigned char *) &in.s_addr;

	strcpy (dest, "");

	switch (padding) {
	case (0):
		sprintf (dest, "%d.%d.%d.%d", ipp[0], ipp[1], ipp[2], ipp[3]);
		break;
	case (1):
		sprintf (dest, "%03d.%03d.%03d.%03d", ipp[0], ipp[1], ipp[2], ipp[3]);
		break;
	case (2):
		sprintf (dest, "%3d.%3d.%3d.%3d", ipp[0], ipp[1], ipp[2], ipp[3]);
		break;
	default:
		break;
	}

	return (dest);
}


void *
xrealloc (void *m_ptr, size_t newsize)
{
	void	*n_ptr;

	n_ptr = realloc (m_ptr, newsize);
	if (n_ptr == NULL) {
		fprintf (stderr, "realloc failed\n");
		exit (EXIT_FAILURE);
	}

	return (n_ptr);
}


char *
xstrdup (char *str)
{
	char	*b;

	b = strdup (str);
	if (b == NULL) {
		fprintf (stderr, "strdup failed\n");
		exit (EXIT_FAILURE);
	}

	return (b);
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

/* source by dk
 */

char *
allocncat (char **to, char *from, size_t len)
{
	int rlen = strlen (from);
	int null = *to == NULL;

	len = rlen < len ? rlen : len;
	*to = realloc (*to, (null ? 0 : strlen (*to)) + len + 1);
	if (null)
		**to = '\0';

	if (*to == NULL)
		perror ("no memory: ");

	return (strncat (*to, from, len));
}

char *
alloccat (char **to, char *from)
{
   return (allocncat (to, from, strlen (from)));
}

