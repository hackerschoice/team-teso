/*
 this is by zap^teso
 thanks to kra.
*/

#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include "net.h"

int linksock;

char device[] = "eth0";
char *eth_device = device;

char src_mac[] = { 0x00, 0x00, 0x21, 0x6b, 0x4d, 0x12 };
unsigned int src_ip = 0xfe00000a;

//char dst_mac[] = { 0x00, 0x00, 0xca, 0x06, 0x6d, 0xf4 };
char dst_mac[] = { 0x00, 0x4F, 0x49, 0x04, 0xA2, 0x67 };
unsigned int dst_ip = 0x2b00000a;

struct icmp_spec icmp;

main()
{
	int val=1, tlen;
	struct ifreq ifr;


	if( ( linksock = socket( AF_INET, SOCK_PACKET, ETH_P_ALL ) ) < 0 ) {
		perror( "socket()" );
		exit( 1 );
	}


	if( ( ioctl( linksock, SIOCGIFFLAGS, &ifr ) ) < 0 ) {
		perror("ioctl()");
	}
	
	ifr.ifr_flags |= IFF_PROMISC;

	if( ( ioctl( linksock, SIOCSIFFLAGS, &ifr ) ) < 0 ) {
		perror( "ioctl()" );
	}


/*
	if( setsockopt( linksock, IPPROTO_IP, IP_HDRINCL, &val, sizeof( val ) ) < 0 ) {
		perror( "setsockopt()" );
		exit( 1 );
	}
*/
	icmp.src_addr = src_ip;
	icmp.src_mac = src_mac;
	icmp.dst_addr = dst_ip;
	icmp.dst_mac = dst_mac;
	
	icmp.type = ICMP_ECHO;
	icmp.code = 0;
	icmp.un.idseq.id = 123;
	icmp.un.idseq.seq = 321;
	icmp.data_len = 0;
	icmp.data = NULL;

	send_icmp_packet( &icmp );

	close( linksock );		

}
