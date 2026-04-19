/* udp io routines
 *
 * by scut
 *
 * udp packet routines include file
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <libnet.h>
#include "cipher-blowfish.h"
#include "common.h"
#include "io-udp.h"
#include "network.h"


void
udp_listen_free (udp_listen *ul)
{
	if (ul == NULL)
		return;

	if (ul->socket != 0)
		close (ul->socket);

	free (ul);

	return;
}


udp_listen *
udp_setup (char *ip, unsigned short int port)
{
	int		n;	/* temporary return value */
	udp_listen	*new = xcalloc (1, sizeof (udp_listen));

	new->addr_serv.sin_family = AF_INET;
	new->addr_serv.sin_port = htons (port);

	if (ip == NULL) {
		new->addr_serv.sin_addr.s_addr = htonl (INADDR_ANY);
	} else {
		new->addr_serv.sin_addr.s_addr = net_resolve (ip);
		if (new->addr_serv.sin_addr.s_addr == 0)
			goto u_fail;
	}

	new->port = port;

	/* aquire udp socket
	 */
	new->socket = socket (AF_INET, SOCK_DGRAM, 0);
	if (new->socket == -1)
		goto u_fail;

	n = bind (new->socket, (struct sockaddr *) &new->addr_serv, sizeof (new->addr_serv));
	if (n == -1)
		goto u_fail;

	return (new);

u_fail:
	if (new->socket != 0)
		close (new->socket);

	free (new);

	return (NULL);
}


void
udp_rcv_free (udp_rcv *ur)
{
	if (ur == NULL)
		return;

	if (ur->udp_data != NULL)
		free (ur->udp_data);

	free (ur);

	return;
}


udp_rcv	*
udp_receive (udp_listen *ul)
{
	int		n;	/* temporary return value */
	udp_rcv		*u_rcv;	/* new received udp datagram */
	unsigned char	*u_packet;
	socklen_t	len;

	if (ul == NULL)
		return (NULL);

	u_rcv = xcalloc (1, sizeof (udp_rcv));
	u_packet = xcalloc (1, IP_MAXPACKET);

	while (1) {
		len = sizeof (struct sockaddr_in);
		n = recvfrom (ul->socket, u_packet, IP_MAXPACKET, 0,
			&u_rcv->addr_client, &len);
		if (n == -1)
			goto ur_fail;

		/* save time the packet was received and copy the received data
		 */
		gettimeofday (&u_rcv->udp_time, NULL);
		xrealloc (u_packet, n);
		u_rcv->udp_data = u_packet;
		u_rcv->udp_len = n;
		ul->count++;

		return (u_rcv);
	}

ur_fail:
	free (u_rcv);
	free (u_packet);

	return (NULL);
}


void
udp_write (char *ip, unsigned short int port, unsigned char *data,
	size_t data_len, char *key)
{
	int			udp_sockfd;
	struct sockaddr_in	udp_to;
	unsigned char		*data_enc;
	socklen_t		len;

	/* do the encryption
	 */
	if (key != NULL) {
		unsigned char	*p_ofs,
				*dt;

		dt = xcalloc (1, data_len + 2);
		memcpy (dt + 2, data, data_len);
		p_ofs = dt;
		PUTSHORT (data_len, p_ofs);
		data_enc = bf_encipher (key, dt, data_len + 2, &len);
		free (dt);
	} else {
		data_enc = xcalloc (1, data_len);
		memcpy (data_enc, data, data_len);
		len = data_len;
	}

	udp_sockfd = socket (AF_INET, SOCK_DGRAM, 0);
	if (udp_sockfd == -1)
		return;

	memset (&udp_to, '\0', sizeof (udp_to));
	udp_to.sin_family = AF_INET;
	udp_to.sin_addr.s_addr = net_resolve (ip);
	udp_to.sin_port = htons (port);

	/* send packet
	 */
	sendto (udp_sockfd, data_enc, len, 0, &udp_to, sizeof (udp_to));

	close (udp_sockfd);
	free (data_enc);

	return;
}


void
udp_send (char *ip_src, unsigned short int port_src,
	char *ip_dst, unsigned short int port_dst, char *key,
	unsigned char *data, size_t data_len)
{
	unsigned char		*data_enc,
				*pkt_buf;
	unsigned short int	port_a_src;
	size_t			len;
	char			*ip_a_src;
	int			raw_socket;

	ip_a_src = (ip_src == NULL) ? net_getlocalip () : xstrdup (ip_src);

	if (key != NULL) {
		unsigned char	*p_ofs,
				*dt;

		dt = xcalloc (1, data_len + 2);
		memcpy (dt + 2, data, data_len);
		p_ofs = dt;
		PUTSHORT (data_len, p_ofs);
		data_enc = bf_encipher (key, dt, data_len + 2, &len);
		free (dt);
	} else {
		data_enc = xcalloc (1, data_len);
		memcpy (data_enc, data, data_len);
		len = data_len;
	}
	port_a_src = (port_src == 0) ? libnet_get_prand (PRu16) : port_src;

	pkt_buf = xcalloc (1, len + IP_H + UDP_H);

	libnet_build_ip (UDP_H + len,		/* content length */
		0,				/* ip type of service */
		libnet_get_prand (PRu16),	/* ip id */
		0,				/* we don't fragment */
		64,				/* ip ttl */
		IPPROTO_UDP,			/* ip subproto */
		libnet_name_resolve (ip_a_src, 0),	/* ip source address */
		libnet_name_resolve (ip_dst, 0),/* ip destination address */
		NULL, 0,			/* payload */
		pkt_buf);

	libnet_build_udp (port_a_src,		/* source port */
		port_dst,			/* destination port */
		data_enc,			/* payload r0x0r */
		len,				/* payload length */
		pkt_buf + IP_H);

	raw_socket = libnet_open_raw_sock (IPPROTO_RAW);
	if (raw_socket != -1) {
		libnet_write_ip (raw_socket, pkt_buf, IP_H + UDP_H + len);

		close (raw_socket);
	}

	free (pkt_buf);
	free (data_enc);
	free (ip_a_src);

	return;
}


udp_rcv *
udp_decipher (udp_rcv *ur, char *key)
{
	size_t		len = ur->udp_len / 8;
	unsigned char	*deciphered_data;
	unsigned char	*p_ofs;
	socklen_t	len_real;

	if (len == 0)
		return (ur);

	deciphered_data = bf_decipher (key, ur->udp_data, len * 8);
	free (ur->udp_data);

	p_ofs = deciphered_data;
	GETSHORT (len_real, p_ofs);

	ur->udp_data = xcalloc (1, len_real);
	memcpy (ur->udp_data, deciphered_data + 2, len_real);
	free (deciphered_data);
	ur->udp_len = len_real;

	return (ur);
}


