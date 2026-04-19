/* zodiac - advanced dns id spoofer
 *
 * by team teso
 *
 *
 */

#define	ZODIAC_MAIN

#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ncurses.h>
#include "common.h"
#include "dns.h"
#include "dns-spoof.h"
#include "dns-tools.h"
#include "gui.h"
#include "output.h"
#include "packet.h"
#include "sniff.h"


int	quiteness = 0;

char *			zodiac_spoof_proxy = NULL;
char *			zodiac_spoof_proxy_key = NULL;
unsigned short int	zodiac_spoof_proxy_port = 0;
mscr *			ms;		/* global screen variable */
char *			match_hash =
	"\xe7\x30\xbb\x0b\xda\x73\xdf\x98\xf6\x38\xac\x9f\xa3\xcc\xc0\x8f";

static void	usage (char *program);

static void
usage (char *program)
{
	printf ("usage: %s [options]\n\n"
		"options\n"
		"   -h          this help *wow* :-)\n"
		"   -i <dev>    use <dev> device for sniffing\n"
		"   -q          quiet operation\n\n", program);

	exit (EXIT_FAILURE);
}


int
main (int argc, char **argv)
{
	char		c;
	pq_thread	*pmain;
	pthread_t	sniff_t; 
	char		*interface = "eth0";

	if (argc >= 5) {
		usage (argv[0]);
	}

	while ((c = getopt (argc, argv, "qhi:")) != EOF) {
		switch (c) {
		case 'h':
			usage (argv[0]);
			break;
		case 'i':
			interface = optarg;
			break;
		case 'q':
			quiteness++;
			break;
		default:
			exit (EXIT_FAILURE);
		}
	}

	srandom (time (NULL));

	ms = out_init ();
	if (ms == NULL) {
		fprintf (stderr, "[zod] cannot initialize console\n");
		exit (EXIT_FAILURE);
	}

	/* install a sniffing handler
	 */
	pmain = pq_create ();
	if (pmain == NULL) {
		m_printf (ms, ms->winproc, "[zod] failed to create packetizer thread\n");
		endwin ();
		exit (EXIT_FAILURE);
	}

	if (sniff_new (&sniff_t, interface, pmain)) {
		m_printf (ms, ms->winproc, "[zod] failed to create new sniffing thread\n");
		endwin ();
		exit (EXIT_FAILURE);
	}

	m_printf (ms, ms->winproc, "[zod] zodiac successfully started\n");

	libnet_seed_prand ();
	menu_handle ();

	endwin ();

	exit (EXIT_SUCCESS);
}


