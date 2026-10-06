/*
 this is by zap^teso
 thanks to kra.
*/

#include "net.h"

int linksock;

char device[] = "eth0";
char *eth_device = device;

char from_mac[] = { 0x00, 0x4f, 0x4e, 0x03, 0x12, 0x5b };
char some_mac[] = { 0x4f, 0x12, 0x03, 0x83, 0xab, 0xba };
char zero_mac[] = { 0, 0, 0, 0, 0, 0 };

unsigned int src_ip = 0xfe1030ba;
unsigned int dst_ip = 0x12123aea;

struct arp_spec arp;

main()
{
	int val=1, tlen;

	if( ( linksock = socket( AF_INET, SOCK_PACKET, ETH_P_ALL ) ) < 0 ) {
		perror( "socket()" );
		exit( 1 );
	}


	arp.src_mac = from_mac;
	arp.dst_mac = some_mac;
	arp.oper = htons( ARPOP_REQUEST );
	arp.sender_mac = from_mac;
	arp.target_mac = zero_mac;
	arp.sender_addr = src_ip;
	arp.target_addr = dst_ip;
	
	send_arp_packet( &arp );

	close( linksock );		

}
