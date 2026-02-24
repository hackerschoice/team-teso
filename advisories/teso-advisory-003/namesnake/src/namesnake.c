/* namesnake - dns path discovery and measurement tool
 *
 * by scut of teso
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


typedef struct {
	char *	ip;
	int	count_resp;
} ns;

char *	ns_domain;

int	usage (char *program);
ns **	ns_hop_trace (char *ip_snake, char *domain_our);
void	snakeprint (ns **list, int indent);
int	snakequick (char *ip_snake, char *domain_our);
int	snake (char *ip_snake, char *domain_our);

char *		mode = "trace";
char *		ip_local = NULL;
udp_listen *	ul;


int
usage (char *program)
{
	printf ("usage: %s <ourdomain> <nameserver> [mode]\n\n"
		"ourdomain   the domain that references to our current ip\n"
		"nameserver  the startpoint for the nameserver chain to trace\n"
		"mode        either \"quick\" or \"trace\"\n\n",
		program);

	exit (EXIT_FAILURE);
}


int
main (int argc, char **argv)
{
	char *		ip_bind = NULL;

	printf ("namesnake "VERSION" by "AUTHORS"\n\n");

	if (argc < 3)
		usage (argv[0]);

	if (argc == 4 && strcmp (argv[3], "quick") == 0)
		mode = argv[3];

	ip_local = net_getlocalip ();
	ul = udp_setup (ip_bind, 53);
	if (ul == NULL) {
		fprintf (stderr, "failed to bind to port 53, try specifying a local ip to bind to\n");
		exit (EXIT_FAILURE);
	}

	printf ("[ns] listener bound to %s:53\n", (ip_bind == NULL) ? "*" : ip_bind);
	printf ("[ns] tracing %s through the help of our domain %s\n", argv[2], argv[1]);
	printf ("===============================================================================\n");

	srandom (time (NULL));

	if (strcmp (mode, "quick") == 0)
		snakequick (argv[2], argv[1]);
	else
		snake (argv[2], argv[1]);

	udp_listen_free (ul);
	exit (EXIT_SUCCESS);
}


ns **
ns_hop_trace (char *ip_snake, char *domain_our)
{
	ns **		ns_ret = NULL;
	int		ns_entry_count = 0;
	char *		ip;
	int		i,m;
	dns_pdata *	dp;
	char *		querydomain;
	int		count = 0;
	udp_rcv *	ur;
	struct timeval	tv_start;
	struct timeval	tv;
	int		bc = 0;

	gettimeofday (&tv_start, NULL);

	/* construct and send dns query
	 */
	dp = dns_build_new ();
	querydomain = dns_build_random (domain_our, 0);
	dns_build_q (dp, querydomain, T_A, C_IN);
	dns_packet_send (ip_local, ip_snake, m_random (1024, 65535), 53,
		m_random (1, 65535), DF_RD, 1, 0, 0, 0, dp);
	dns_build_destroy (dp);

	while (bc == 0) {
		struct timeval	tv_now;

		gettimeofday (&tv_now, NULL);
		tv.tv_sec = 140 - (tv_now.tv_sec - tv_start.tv_sec);
		tv.tv_usec = 0;

		ur = NULL;
		if ((tv_now.tv_sec - tv_start.tv_sec) >= 0)
			ur = udp_receive (ul, &tv);

		if (ur != NULL) {
			dns_handle ((dns_hdr *) ur->udp_data, ur->udp_data + sizeof (dns_hdr), ur->udp_len, 0);
			if (strcmp (querydomain, ns_domain) == 0) {
				count++;

				net_printipa ((struct in_addr *) & ur->addr_client.sin_addr, &ip);
				m = 0;
				for (i = 0 ; ns_ret != NULL && ns_ret[i] != NULL ; ++i) {
					if (strcmp (ns_ret[i]->ip, ip) == 0) {
						ns_ret[i]->count_resp += 1;
						m = 1;
					}
				}
				if (m == 0) {
					ns_entry_count += 1;
					ns_ret = xrealloc (ns_ret, (ns_entry_count + 1) * sizeof (ns *));
					ns_ret[ns_entry_count] = NULL;
					ns_ret[ns_entry_count - 1] = xcalloc (1, sizeof (ns));

					ns_ret[ns_entry_count - 1]->ip = ip;
					ns_ret[ns_entry_count - 1]->count_resp = 1;
				}
			} else {
				printf ("*!* received unrelated packet\n");
			}
			udp_rcv_free (ur);
			free (ns_domain);
		}

		if (ur == NULL)
			bc = 1;
	}

	free (querydomain);

	return (ns_ret);

}


int
snakequick (char *ip_snake, char *domain_our)
{
	char *		ip;
	dns_pdata *	dp;
	char *		querydomain;
	int		count = 0;
	udp_rcv *	ur;
	struct timeval	tv_start;
	struct timeval	tv;
	int		bc = 0;

	gettimeofday (&tv_start, NULL);

	/* construct and send dns query
	 */
	dp = dns_build_new ();
	querydomain = dns_build_random (domain_our, 0);
	dns_build_q (dp, querydomain, T_A, C_IN);
	dns_packet_send (ip_local, ip_snake, m_random (1024, 65535), 53,
		m_random (1, 65535), DF_RD, 1, 0, 0, 0, dp);
	dns_build_destroy (dp);
	printf ("asking for %s\n", querydomain);
	free (querydomain);

	while (bc == 0) {
		struct timeval	tv_now;

		gettimeofday (&tv_now, NULL);
		tv.tv_sec = 90 - (tv_now.tv_sec - tv_start.tv_sec);
		tv.tv_usec = 0;

		ur = NULL;
		if ((tv_now.tv_sec - tv_start.tv_sec) >= 0)
			ur = udp_receive (ul, &tv);

		if (ur != NULL) {
			count++;
			net_printipa ((struct in_addr *) & ur->addr_client.sin_addr, &ip);
			printf ("%s\t== ", ip);
			dns_handle ((dns_hdr *) ur->udp_data, ur->udp_data + sizeof (dns_hdr), ur->udp_len, 1);
			udp_rcv_free (ur);
		}

		if (ur == NULL)
			bc = 1;
	}

	fprintf (stderr, "%s %d\n", ip_snake, count);

	return (1);
}


void
snakeprint (ns **list, int indent)
{
	int	walker,
		indent_tmp;

	if (list == NULL)
		return;

	for (walker = 0 ; list[walker] != NULL ; ++walker) {
		for (indent_tmp = indent ; indent_tmp > 0 ; --indent_tmp) {
			printf ("\t");
		}
		printf ("%3d %s\n", list[walker]->count_resp, list[walker]->ip);
	}

	return;
}


int
snake (char *ip_snake, char *domain_our)
{
	ns ***		pathway;
	ns **		base;
	int		walker;
	int		ns_count;


	base = ns_hop_trace (ip_snake, domain_our);
	if (base == NULL || base[0] == NULL)
		return (0);

	printf ("%s\n", ip_snake);
	snakeprint (base, 1);
	for (ns_count = 0 ; base[ns_count] != NULL ; ++ns_count)
		;
	printf ("======== tracing pathway of %d servers ========\n", ns_count);

	ns_count += 1;
	pathway = xcalloc (1, sizeof (ns **) * (ns_count));
	for (walker = 0 ; base[walker] != NULL ; ++walker) {
		printf ("=== %s\n", base[walker]->ip);
		pathway[walker] = ns_hop_trace (base[walker]->ip, domain_our);
		snakeprint (pathway[walker], 1);
	}

	return (1);
}


