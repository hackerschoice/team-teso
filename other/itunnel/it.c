/*
 * itunnel - an ICMP tunnel by edi / teso
 * usage: it [-i id] [-s packetsize] host
 * establishes   a   bidirectional   ICMP 
 * 'connection' with 'host'  by listening 
 * to  ICMP  packets with  a  specific id
 * (default: 7530). uses stdin and stdout
 * and needs to run as root.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>

struct icmp
{
	u_int8_t	type;
	u_int8_t	code;
	u_int16_t	cksum;
	u_int16_t	id;
	u_int16_t	seq;
};

u_short in_cksum(u_short *, int);

/* icmp_tunnel - does the ICMP tunneling :-)
int sock - ICMP socket used to communicate
struct sockaddr_in *target - other side
int infd - input
int outfd - output
int packetsize - ...
u_int16_t id - ...
*/

int icmp_tunnel(int sock, struct sockaddr_in *target, int infd, int outfd, int packetsize, u_int16_t id) {

	char* packet;
	struct icmp *icmp, *icmpr;
	int len;
	int result;
	fd_set fs;

	struct sockaddr_in from;
	int fromlen;
	int num;

	len = sizeof (struct icmp);

	packet = malloc (len+packetsize);
	memset (packet, 0, len+packetsize);

	icmp = (struct icmp*)(packet);
	icmpr = (struct icmp*)(packet+sizeof(struct ip));

	while (1) {
		FD_ZERO (&fs);
		FD_SET (infd, &fs);
		FD_SET (sock, &fs);

		select (infd>sock?infd+1:sock+1, &fs, NULL, NULL, NULL);

		if (FD_ISSET (infd, &fs)) {
			result = read (infd, packet+len, packetsize);
			if (!result) {
				return 0;
			} else if (result==-1) {
				perror ("read");
				return -1;
			}
			icmp->type = 0;
			icmp->code = 0;
			icmp->id = id;
			icmp->seq = 0;
			icmp->cksum = 0;
			icmp->cksum = in_cksum((u_short*)packet, len+result);
			result = sendto (sock, (char*)packet, len+result, 0, (struct sockaddr*)target, sizeof (struct sockaddr_in));
			if (result==-1) {
				perror ("sendto");
				return -1;
			}
		}
		if (FD_ISSET (sock, &fs)) {
			fromlen = sizeof (struct sockaddr_in);
			num = recvfrom (sock, packet, len+packetsize, 0, (struct sockaddr*)&from, &fromlen);
			if (icmpr->id == id) {
				write (outfd, packet+sizeof(struct ip)+sizeof(struct icmp), num-sizeof(struct ip)-sizeof(struct icmp));
			}
		}
	}


	return 0;
}

int main (int argc, char** argv) {
	struct sockaddr_in target;
	int s;

	int packetsize = 100;
	char* desthost = NULL;
	u_int16_t id = 7530;

	argv++;
	argc--;

	while (argc--) {
		if (!strcmp(*argv, "-i")) {
			if (!argc--) {
				fprintf (stderr, "need argument\n");
				return -1;
			}
			argv++;
			id = atoi(*argv++);
		} else if (!strcmp(*argv, "-s")) {
			if (!argc--) {
				fprintf (stderr, "need argument\n");
				return -1;
			}
			argv++;
			packetsize = atoi(*argv++);
		} else desthost = *argv++;
	}

	if (!desthost) {
		fprintf (stderr, "no destination\n");
		return -1;
	}

	if ((target.sin_addr.s_addr = inet_addr (desthost)) == -1) {
		struct hostent* he;
		if (!(he = gethostbyname (desthost))) {
			herror ("gethostbyname");
			return -1;
		}
		memcpy (&target.sin_addr.s_addr, he->h_addr, he->h_length);
	}
	target.sin_family = AF_INET;

	if ( (s = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
		perror ("socket");
		return -1;
	}

	icmp_tunnel(s, &target, STDIN_FILENO, STDOUT_FILENO, packetsize, id);

	close(s);

	return 0;
}

unsigned short
in_cksum (addr, len)
     u_short *addr;
     int len;
{
  register int nleft = len;
  register u_short *w = addr;
  register int sum = 0;
  u_short answer = 0;
  while (nleft > 1) { sum += *w++; nleft -= 2; }
  if (nleft == 1) { *(u_char *) (&answer) = *(u_char *) w; sum += answer; }
  sum = (sum >> 16) + (sum & 0xffff);   /* add hi 16 to low 16 */
  sum += (sum >> 16);           /* add carry */
  answer = ~sum;                /* truncate to 16 bits */
  return (answer);
}
