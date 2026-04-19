/* zodiac spoof proxy
 *
 * by team teso
 *
 * main program
 */


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include "../io-udp.h"
#include "../network.h"


#define	VERSION	"0.0.3"
#define	AUTHORS	"team teso"


/* nah, no snakeoil here, this is just a packet marker (straight from
 * /dev/random), which is used to avoid bouncing of messed up packets.
 * you usually don't have to modify it. tho if you do it, modify the
 * one in ./src/dns-build.c too to match this one. :-)
 * -sc
 */
char	match_hash[] =
	"\xe7\x30\xbb\x0b\xda\x73\xdf\x98\xf6\x38\xac\x9f\xa3\xcc\xc0\x8f";


char			*relay_ip = NULL;
unsigned short int	relay_port = 0;
int			relay_encrypt = 0;
unsigned char		relay_key[32];


int	key_read (char *key, size_t keylen, char *text);
void	usage (void);
void	zsp_process (udp_rcv *packet);


int
main (int argc, char **argv)
{
	pid_t			pid;
	int			daemon = 0;
	char			c;		/* option character */
	unsigned short int	port = 17852;	/* listening port */
	char			*ip = NULL;	/* local ip to bind to */
	udp_listen		*listener;
	udp_rcv			*packet;
	char			key[32];


	printf ("zodiac spoof proxy v" VERSION " by " AUTHORS "\n\n");

	while ((c = getopt (argc, argv, "di:r:xp:h")) != EOF) {
		switch (c) {
		case 'd':
			daemon = 1;
			break;
		case 'i':
			ip = optarg;
			break;
		case 'r':
			if (net_parseip (optarg, &relay_ip, &relay_port) != 1) {
				fprintf (stderr, "failed to parse ip:port string %s\n", optarg);
				exit (EXIT_FAILURE);
			}
			break;
		case 'x':
			relay_encrypt = 1;
			break;
		case 'p':
			port = atoi (optarg);
			break;
		case 'h':
			usage ();
			break;
		default:
			fprintf (stderr, "invalid option: %c\n", c);
			usage ();
			break;
		}
	}

	if (port == 0 || (relay_ip == NULL && relay_encrypt == 1))
		usage ();

	if (key_read (key, sizeof (key), "enter incoming encryption key: ") == 0 ||
		(relay_encrypt == 1 &&
		key_read (relay_key, sizeof (relay_key), "enter outgoing encryption key: ") == 0))
	{
		fprintf (stderr, "failed to read required keys... aborting.\n");

		exit (EXIT_FAILURE);
	}

	printf ("\n");


	if (daemon == 1) {
		printf ("going daemon...\n");
		pid = fork ();
		if (pid == -1)
			exit (EXIT_FAILURE);
		else if (pid != 0)
			exit (EXIT_SUCCESS);
		printf ("daemon (pid: %d)\n", getpid ());
	}

	listener = udp_setup (ip, port);
	if (listener == NULL) {
		perror ("failed to aquire udp listener");
		exit (EXIT_FAILURE);
	}

	while (1) {
		packet = udp_receive (listener);

		if (packet == NULL) {
			fprintf (stderr, "udp_receive: NULL packet\n");
			exit (EXIT_FAILURE);
		}

		if (packet->udp_len >= (16 + IP_H + UDP_H)) {
			packet = udp_decipher (packet, key);
			if (memcmp (packet->udp_data, match_hash, 16) == 0) {
				zsp_process (packet);
			} else {
				fprintf (stderr, "!ERROR! received invalid packet, failed at decryption\n");
			}
		} else {
			fprintf (stderr, "!ERROR! received packet size is too short (%d), skipping\n",
				packet->udp_len);
		}

		udp_rcv_free (packet);
	}

}


int
key_read (char *key, size_t keylen, char *text)
{
	char	r_str[16];

	memset (key, '\x00', keylen);
	printf ("%s", text);	/* avoid wuftpd like misusage here haha :-) -sc */
	fflush (stdout);

	memset (r_str, '\x00', sizeof (r_str));
	sprintf (r_str, "%%%ds", keylen - 1);
	if (scanf (r_str, key) != 1)
		return (0);

	while (isspace (key[strlen (key)]))
		key[strlen (key)] = '\x00';

	return (1);
}


void
zsp_process (udp_rcv *packet)
{
	int		sock;		/* raw socket, yeah :) */
	int		n;		/* temporary return value */
	socklen_t	pkt_len = packet->udp_len - 16;


	/* see whether we just have to relay the frame to another spoof proxy
	 */
	if (relay_ip != NULL) {
		char	*key = NULL;

		if (relay_encrypt == 1)
			key = relay_key;

		udp_write (relay_ip, relay_port, packet->udp_data,
			packet->udp_len, key);
		printf ("[pkt] relayed %5d bytes (%d+16) from %s to zsp\n", packet->udp_len,
			pkt_len, inet_ntoa (packet->addr_client.sin_addr));

		return;
	}


	sock = libnet_open_raw_sock (IPPROTO_RAW);
	if (sock == -1) {
		fprintf (stderr, "!ERROR! failed to aquire raw socket, aborting\n");
		exit (EXIT_FAILURE);
	}

	/* kick the packet hard
	 */
	n = libnet_write_ip (sock, packet->udp_data + 16,
		pkt_len);
	close (sock);

	if (n < pkt_len) {
		fprintf (stderr, "!ERROR! send too less bytes (%d/%d) in packet\n",
			n, pkt_len);
	} else {
		printf ("[pkt] relayed %5d bytes from %s\n", pkt_len,
			inet_ntoa (packet->addr_client.sin_addr));
	}

	return;
}


void
usage (void)
{
	printf ("usage: zsp [-i <local listen ip>] [-r <ip>:<port>[ -x]] [-p <port>] [-d]\n\n"
		"-i  specifies the local ip to bind to\n"
		"-r  relay to another zodiac spoof proxy\n"
		"-x  reencrypt received frames before sending (2nd key will be asked)\n"
		"-p  specifies the local port to take packets from (default: 17852)\n"
		"-d  sets the program into daemon mode\n\n");

	exit (EXIT_FAILURE);

	return;
}

