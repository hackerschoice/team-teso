/* namesnake
 *
 * by scut
 *
 * udp packet routines include file
 */

#ifndef	_FNX_IO_UDP_H
#define	_FNX_IO_UDP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>


/* udp receival entity
 */

typedef struct	udp_listen {
	unsigned long int	count;	/* number of packets received */
	struct in_addr		ip;	/* ip to receive data on */
	unsigned short int	port;	/* port to receive data on */
	int			socket;	/* listening socket */
	struct sockaddr_in	addr_serv;
} udp_listen;


/* udp datagram structure
 */

typedef struct	udp_rcv {
	struct sockaddr_in	addr_client;	/* source address */
	struct timeval		udp_time;	/* time of receival */
	socklen_t		udp_len;	/* length of the udp datagramm */
	unsigned char		*udp_data;	/* received udp datagramm */
} udp_rcv;


/* udp_listen_free
 *
 * free a udp_listen structure pointed to by `ul'
 *
 * return in any case
 */

void	udp_listen_free (udp_listen *ul);


/* udp_setup
 *
 * start a new listening udp service with the bound ip `ip', which can be
 * either a numeric ip address or "*" (or NULL) for all locally available
 * ip addresses. the listening port is `port'.
 *
 * return NULL on failure
 * return a pointer to a udp_listen structure on success
 */

udp_listen	*udp_setup (char *ip, unsigned short int port);


/* udp_rcv_free
 *
 * free a udp_rcv structure pointed to by `ur'
 *
 * return in any case
 */

void	udp_rcv_free (udp_rcv *ur);


/* udp_receive
 *
 * receive an udp datagramm on the network entity specified by the `ul'
 * structure
 *
 * return NULL on failure
 * return a pointer to a new udp_rcv structure on success
 */

udp_rcv	*udp_receive (udp_listen *ul, struct timeval *tv);


/* udp_write
 *
 * send an udp datagram using the system level datagram sockets. send
 * `data_len' bytes from `data' to the host with the ip `ip' on port
 * `port'
 *
 * return in any case
 */

void
udp_write (char *ip, unsigned short int port, unsigned char *data,
	size_t data_len);


/* udp_send
 *
 * send an udp datagram using raw socket. the datagram will be assigned the
 * source ip address of the local host if `ip_src' is NULL and the source IP
 * address `ip_src' if it is not. the source port will be random if `port_src'
 * equals zero, else it is assigned the value of it.
 * the destination ip address is `ip_dst', the destination port is `port_dst'..
 * the payload is `data', which is `data_len' bytes long. the data will be
 * encrypted with `key' if it is not NULL.
 *
 * return in any case
 */

void	udp_send (char *ip_src, unsigned short int port_src,
	char *ip_dst, unsigned short int port_dst,
	unsigned char *data, size_t data_len);


#endif

