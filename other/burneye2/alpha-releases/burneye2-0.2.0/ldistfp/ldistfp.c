/* ldistfp - linux distribution fingerprinting
 *
 * by scut / teso
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "network.h"

#define	AUTHORS	"-sc/teso"
#define	VERSION	"0.1.4"

#define	FP_URL		"http://www.team-teso.net/data/ldistfp-auth-fingerprints"
#define	SUBMIT_URL	"http://www.team-teso.net/ldistfp.php"

typedef struct	fingerprint {
	char *	distname;
	char *	distversion;
	char *	substring;
	char *	auth_version;
	int	exact;
} fingerprint;

fingerprint **	fp_list = NULL;
char *		fp_filename = "ldistfp-auth-fingerprints";
char *		fp_url = FP_URL;
int		fp_count = 0;

int		strictsure = 0;
int		machineoutput = 0;
FILE *		newfile = NULL;	/* file to save new fingerprints to */


void	usage (char *prog);
void	host_print (char *host, char *bogus, fingerprint *fp);
void	fp_det (char *host, char *buf);
void	fp_list_read (char *filename);
void	fp_update (char *fname, char *url);


void
usage (char *prog)
{
	fprintf (stderr, "usage: %s [-rsmu] [-n <file>] [-U <url>] <host|ip>\n\n", prog);
	fprintf (stderr, " -r        rawmode, read from stdin in format [^ ] (buf$)\n");
	fprintf (stderr, " -n <file> output new fingerprint information to this file\n");
	fprintf (stderr, " -s        only print host information if properly identified\n");
	fprintf (stderr, " -m        machine output\n");
	fprintf (stderr, "\nupdate options\n");
	fprintf (stderr, " -u        update from " FP_URL "\n");
	fprintf (stderr, " -U <url>  update from given URL (http://<host>[:<port>]/<file>)\n\n");

	exit (EXIT_FAILURE);
}

int
main (int argc, char *argv[])
{
	int	sock,
		n;
	int	rawmode = 0;
	int	update_only = 0;
	char	c;
	char *	rbuf;
	char *	target;


	fprintf (stderr, "ldistfp "VERSION" - remote identd fingerprinting tool. "AUTHORS"\n\n");

	if (argc < 2)
		usage (argv[0]);

	while ((c = getopt (argc, argv, "rn:smf:uU:")) != EOF) {
		switch (c) {
		case 'r':
			rawmode = 1;
			break;
		case 'n':
			newfile = fopen (optarg, "a");
			if (newfile == NULL) {
				perror ("fopen");
				exit (EXIT_FAILURE);
			}
			break;
		case 's':
			strictsure = 1;
			break;
		case 'm':
			machineoutput = 1;
			break;
		case 'f':
			fp_filename = optarg;
			break;
		case 'u':
			update_only = 1;
			break;
		case 'U':
			update_only = 1;
			fp_url = optarg;
			break;
		default:
			usage ("ldistfp");
			break;
		}
	}

	if (update_only == 1) {
		fp_update (fp_filename, fp_url);
		exit (EXIT_SUCCESS);
	}

	target = argv[argc - 1];
	if (target[0] == '-')
		usage ("ldistfp");

	fp_list_read (fp_filename);
	fprintf (stderr, "read %d fingerprints\n", fp_count);

	if (rawmode) {
		unsigned char	tgt[200];
		unsigned char	ibuf[1024];

		while (fgets (ibuf, sizeof (ibuf), stdin) != NULL) {
			memset (tgt, '\0', sizeof (tgt));
			sscanf (ibuf, "%199[^ :]", tgt);
			tgt[sizeof (tgt) - 1] = '\0';
			fp_det (tgt, ibuf);
		}
	} else {

		sock = net_connect (NULL, target, 113, NULL, 0, 30);
		if (sock == -1) {
			perror ("net_connect");
			exit (EXIT_FAILURE);
		}

		net_write (sock, "VERSION\n");
		n = net_rlineta (sock, &rbuf, 15);
		if (n < 0 && strictsure == 0) {
			printf ("%s: failed to determine remote version\n", argv[1]);
		} else {
			fp_det (target, rbuf);
		}

		fprintf (stderr, "\n");
		close (sock);
	}

	if (newfile != NULL)
		fclose (newfile);


	exit (EXIT_SUCCESS);
}


void
fp_det (char *host, char *buf)
{
	int	i;


	for (i = 0 ; fp_list[i] != NULL ; ++i) {
		if (strstr (buf, fp_list[i]->substring) != NULL) {

			/* if it is an exact hit, then we print it and return,
			 * since there cannot be any other hit
			 */
			if (fp_list[i]->exact != 0) {
				host_print (host, "", fp_list[i]);
				return;
			} else if (strictsure == 0) {
				host_print (host, "possible ", fp_list[i]);
			}
		}
	}

	if (machineoutput == 0 && newfile == NULL) {
		printf ("\nunknown, if you know it write down the following line and submit it\n"
			"at " SUBMIT_URL ", thanks.\n\n%s\n", buf);
		return;
	}

	if (newfile == NULL)
		return;

	/* write new fingerprint to newfile */
	fprintf (newfile, "%s: %s", host, buf);

	return;
}


void
host_print (char *host, char *bogus, fingerprint *fp)
{
	if (machineoutput == 1) {
		printf ("%s/%s/%s/%s/%s\n",
		host,
		bogus,
		fp->distname,
		fp->distversion,
		fp->auth_version);
	} else {
		printf ("%s: %s%s %s running %s\n",
		host,
		bogus,
		fp->distname,
		fp->distversion,
		fp->auth_version);
	}

	return;
}

void
fp_list_read (char *filename)
{
	int		n,
			fpc = 1;
	FILE *		fpl;
	unsigned char *	fpl_fg;

	fpl = fopen (filename, "r");
	if (fpl == NULL) {
		perror ("finger print file");
		exit (EXIT_FAILURE);
	}

	do {
		fingerprint *	new = xcalloc (1, sizeof (fingerprint));

		fpc += 1;
		fp_list = xrealloc (fp_list, fpc * sizeof (fingerprint *));
		fp_list[fpc - 1] = NULL;
		fp_list[fpc - 2] = new;

		new->distname = xcalloc (1, 128);
		new->distversion = xcalloc (1, 128);
		new->substring = xcalloc (1, 128);
		new->auth_version = xcalloc (1, 128);

		/* format: "substring" "dist name" "dist version" "identd version" 0|1
		 */
		do {
			unsigned char	buf[256];

			n = 1;
			fpl_fg = fgets (buf, sizeof (buf), fpl);
			if (fpl_fg != NULL && strlen (buf) > 1 && buf[0] != '#') {
				n = sscanf (buf, "\"%127[^\"]\"%*[\t ]\"%127[^\"]\"%*[\t ]"
					"\"%127[^\"]\"%*[\t ]\"%127[^\"]\"%*[\t ]%d\n",
					new->distname, new->distversion, new->substring,
					new->auth_version, &new->exact);
			}
		} while (n != 5 && fpl_fg != NULL);

		if (fpl_fg == NULL) {
			free (new->distname);
			free (new->distversion);
			free (new->substring);
			free (new->auth_version);
			free (new);
			fp_list[fpc - 2] = NULL;
		} else {
			fp_count++;
		}
	} while (fpl_fg != NULL);

	fclose (fpl);
}


/* mini http/1.0 client, assume non-chunked transfer oh my.
 * who invented chunking anyway ?
 */
void
fp_update (char *fname, char *url)
{
	int			fp_dataflag = 2;
	int			fp_updated_size = 0;
	FILE *			fp_updated;
	char			line_buf[2048];

	int			cs;
	char			host[128];
	char			hostfile[128];
	unsigned short int	port;


	/* first open file, else we may not need to get the file if we can't
	 * open the file at all
	 */
	fp_updated = fopen (fname, "w");
	if (fp_updated == NULL) {
		perror ("fp_update:fopen");
		exit (EXIT_FAILURE);
	}

	memset (host, '\0', sizeof (host));
	memset (hostfile, '\0', sizeof (hostfile));

	if (sscanf (url, "http://%127[^/]%127s", host, hostfile) != 2) {
		fprintf (stderr, "invalid URL: %s\n", url);
		exit (EXIT_FAILURE);
	}
	host[sizeof (host) - 1] = '\0';
	hostfile[sizeof (hostfile) - 1] = '\0';


	/* find possible port suffix */
	if (sscanf (host, "%*[^:]:%hu", &port) != 1)
		port = 80;
	if (strchr (host, ':') != NULL)
		*(strchr (host, ':')) = '\0';

	printf ("fetching:\n");
	printf ("%s [%hu]: %s\n", host, port, hostfile);
	cs = net_connect (NULL, host, port, NULL, 0, 15);
	if (cs <= 0) {
		perror ("fp_update:net_connect");
		exit (EXIT_FAILURE);
	}
	printf ("GET [%s]\n", hostfile);

	/* send request with special User-Agent (to track ldistfp versions
	 * that are used (and for possible ldistfp fingerprint file format
	 * updates, so that new format could be send for new clients, and
	 * old for old ones :-)
	 */
	net_write (cs, "GET %s HTTP/1.1\n", hostfile);
	net_write (cs, "User-Agent: ldistfp/"VERSION"\n");
	net_write (cs, "Host: %s\n", host);
	net_write (cs, "Connection: close\n");
	net_write (cs, "\n");

	do {
		int	n;

		memset (line_buf, '\0', sizeof (line_buf));
		n = net_rlinet (cs, line_buf, sizeof (line_buf), 15);
		if (n <= 0)
			break;

		line_buf[sizeof (line_buf) - 1] = '\0';

		if (fp_dataflag != 0) {
			while (strlen (line_buf) > 0 &&
				(line_buf[strlen (line_buf) - 1] == '\r' ||
				line_buf[strlen (line_buf) - 1] == '\n'))
				line_buf[strlen (line_buf) - 1] = '\0';
		}

		if (fp_dataflag == 2 && strstr (line_buf, " 200 OK") != NULL)
			fp_dataflag = 1;
		else if (fp_dataflag == 1 && strcmp (line_buf, "") == 0)
			fp_dataflag = 0;
		else if (fp_dataflag == 0 && n > 0) {
			fp_updated_size += n;
			fprintf (fp_updated, "%s", line_buf);
		}
	} while (1);

	fclose (fp_updated);
}

