
#define int_ntoa(x)   inet_ntoa(*((struct in_addr *)&(x)))

#define ETH_ALEN	6
#define PCAP_FILTER	"arp or tcp or icmp or udp"

struct Ether_header
{
    uint8_t ether_dhost[ETH_ALEN];
    uint8_t ether_shost[ETH_ALEN];
    uint16_t ether_type;
};

struct Arphdr
{
    unsigned short int ar_hrd;	/* Format of hardware address.  */
    unsigned short int ar_pro;	/* Format of protocol address.  */
    unsigned char ar_hln;	/* Length of hardware address.  */
    unsigned char ar_pln;	/* Length of protocol address.  */
    unsigned short int ar_op;	/* ARP opcode (command).  */
    /* Ethernet looks like this : This bit is variable sized
       however...  */
    unsigned char ar_sha[ETH_ALEN];	/* Sender hardware address.  */
    unsigned char ar_sip[4];	/* Sender IP address.  */
    unsigned char ar_tha[ETH_ALEN];	/* Target hardware address.  */
    unsigned char ar_tip[4];	/* Target IP address.  */
};


void *do_snarf (void *);
void undo_snarf ();
