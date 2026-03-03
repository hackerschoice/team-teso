/* zodiac - advanced dns spoofer
 *
 * sniffing functions
 *
 * by scut
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>
#include "common.h"
#include "network.h"
#include "packet.h"
#include "sniff.h"
#include "3wahas.h"

/* sniff_new
 *
 * the only function that should be called from outside. set up sniffing
 * device, create a new thread, then return.
 * open `interface' device for sniffing, tell sniffing thread to use
 * `pq_size' packet queues, available through `pq_list'.
 * store thread id of new thread in `tid'.
 *
 * return 0 if thread creation was successful
 * return 1 if thread creation failed
 */

void
sniff_new (char *interface, char *ip_dst)
{
	sniff_info	*sinfo;		/* sniff information structure */

	sinfo = xcalloc (1, sizeof (sniff_info));

	sinfo->ip_dst.s_addr = net_resolve (ip_dst);

	/* open interface
	 */
	sinfo->device = sniff_open (interface);
	if (sinfo->device == NULL) {
		free (sinfo);
		return;
	}

	sniff_handle (sinfo);
	/* successfully created sniffer thread
	 */
	return;
}

/* sniff_handle
 *
 * the main sniffing thread, fetching packets from the device, then calling
 * the packet grinder `pq_grind' to process the packets
 *
 * should never return except on error or program exit
 */ 

void *
sniff_handle (sniff_info *sinfo)
{
	int		n;		/* temporary return value */
	pcap_handler	grinder;	/* pcap handler for the packet grinding function */

	printf ("[phx] hello world from sniff handler\n\n");
	grinder = (pcap_handler) pq_grind;
	n = pcap_loop (sinfo->device->pd, -1, grinder, (void *) sinfo);

	if (n == -1) {
		printf ("[phx] sniff_handle (pcap_loop): %s\n", pcap_geterr (sinfo->device->pd));
	}

	return (NULL);
}

/* sniff_open
 *
 * open `dev' for sniffing, or just the first sniffable one, if
 * dev is NULL.
 *
 * return NULL on failure
 * return pointer sniffing device structure on success
 */

s_dev *
sniff_open (char *devname)
{
	int	n;				/* temporary return value */
	s_dev	*device;			/* sniffing device structure to create */
	char	errorbuf[PCAP_ERRBUF_SIZE];	/* error buffer for pcap message */

	/* create new sniffing device structure in s_dev
	 */
	device = xcalloc (1, sizeof (s_dev));

	/* check wether to use the first device or a specified device
	 */
	if (devname == NULL) {
		/* due to lame pcap manpage, you should not know that it's static *doh* */
		device->interface = pcap_lookupdev (errorbuf);
		if (device->interface == NULL) {
			printf ("[phx] sniff_open (pcap_lookupdev): %s\n", errorbuf);
			device->error = 1;
			return (device);
		}
	} else {
		/* if the interface we have to use is already known just copy it
		 */
		device->interface = xstrdup (devname);
	}

	/* try to open the device found
	 */
	device->pd = sniff_pcap_open (device->interface);
	if (device->pd == NULL) {
		device->error = 1;
		return (device);
	}

	/* now query some information about the device and store them into our struct
	 */
	n = pcap_lookupnet (device->interface, &device->localnet,
		&device->netmask, errorbuf);
	if (n == -1) {
		device->error = 1;
		return (device);
	}

	device->linktype = pcap_datalink (device->pd);
	if (device->linktype == -1) {
		device->error = 1;
		return (device);
	}

	return (device);
}

/* sniff_pcap_open
 *
 * securely wraps the pcap_open_live call to catch any errors
 *
 * return NULL on failure
 * return capture descriptor on succes
 */

pcap_t *
sniff_pcap_open (char *device)
{
	char	errorbuf[PCAP_ERRBUF_SIZE];	/* error buffer */
	pcap_t	*pdes = NULL;			/* packet capture descriptor */

	pdes = pcap_open_live (device, SNAPLEN, PROMISC, READ_TIMEOUT, errorbuf);

	if (pdes == NULL) {
		printf ("[phx] sniff_pcap_open (pcap_open_live): %s\n", errorbuf);
		return (NULL);
	}

	return (pdes);
}

/* sniff_dev_free
 *
 * close and free a sniffing device
 */

void
sniff_dev_free (s_dev *device)
{
	pcap_close (device->pd);
	if (device->interface)
		free (device->interface);

	free (device);

	return;
}

