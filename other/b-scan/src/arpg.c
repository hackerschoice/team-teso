/*
 * bscan arp routine
 */
#include <bscan/arpg.h>
#include <bscan/snarf.h>
#include <libnet.h>



void
prepare_libnet (struct _libnet *lnet)
{

    if (lnet->device == NULL)
    {
	struct sockaddr_in sin;
	if (libnet_select_device (&sin, &lnet->device, lnet->err_buf) == -1)
	    libnet_error (LIBNET_ERR_FATAL,
			  "libnet_select_device failed: %s\n", lnet->err_buf);
    }

    if (
	(lnet->network =
	 libnet_open_link_interface (lnet->device, lnet->err_buf)) == NULL)
	libnet_error (LIBNET_ERR_FATAL,
		      "libnet_open_link_interface '%s': %s\n", lnet->device,
		      lnet->err_buf);


    lnet->packet_size = 60;	/* min ethernet frame length -4 CRC */
    if (libnet_init_packet (lnet->packet_size, &lnet->packet) == -1)
	libnet_error (LIBNET_ERR_FATAL, "libnet_init_packet failed\n");

}

/*
 * play arp-god: sends out arp-reply
 * return: same as libnet_write_link_layer
 * -1 on failure or bytes written 
 */
int
play_arpg (struct _libnet *lnet, u_char spf_sip[4], u_char spf_smac[6],
	   u_char spf_dip[4], u_char spf_dmac[6])
{
    int c;

#ifdef DEBUG
    printf ("sending out arp\n");
#endif
    libnet_build_ethernet (spf_dmac,
			   spf_smac, ETHERTYPE_ARP, NULL, 0, lnet->packet);

    libnet_build_arp (ARPHRD_ETHER, ETHERTYPE_IP,	/* arp for which protocol ? */
		      6,	/* hardware addr. length */
		      4,	/* protocol addr. length */
		      ARPOP_REPLY, spf_smac, spf_sip, spf_dmac, spf_dip, NULL,	/* packet payload */
		      0,	/* length of payload */
		      lnet->packet + LIBNET_ETH_H);

    c =
	libnet_write_link_layer (lnet->network, lnet->device, lnet->packet,
				 lnet->packet_size);
    if (c < lnet->packet_size)
    {
	libnet_error (LN_ERR_WARNING,
		      "libnet_write_link_layer only wrote %d bytes\n", c);
    }
#ifdef DEBUG
    else
    {
	printf ("construction and injection completed, wrote all %d bytes\n",
		c);
    }
#endif

    return (c);
}

