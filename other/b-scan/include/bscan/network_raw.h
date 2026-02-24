
/*
 * network_raw.h, depends on libnet.h
 */


#define ETH_SIZE        14
#define IP_SIZE         20
#define TCP_SIZE        20
#define ICMP_SIZE	8
#define UDP_SIZE	8

/*
 *  Checksum stuff
 */
#define CKSUM_CARRY(x) \
    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))
#define int_ntoa(x)   inet_ntoa(*((struct in_addr *)&(x)))


/*
 * leet net tuple
 */
struct net_tuple
{
    uint32_t src;
    unsigned short int sport;
    uint32_t dst;
    unsigned short int dport;
};


/*
 * pseudo TCP header for calculating the chksum
 */
struct _fakehead
{
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tot_len;
};

int init_network_raw (void);
int in_cksum (unsigned short *, int);
int send_ipv4 (int, u_char *, size_t);
void add_udphdr (unsigned char *, struct net_tuple *, int);
void add_tcphdr (unsigned char *, struct net_tuple *, uint8_t, int,
		 tcp_seq *, tcp_seq *);
void add_icmpping (unsigned char *, int, int);
void add_iphdr (unsigned char *, uint8_t ip_p, struct net_tuple *, int);
int answer_tcp (int, struct ip *, struct tcphdr *, uint8_t, u_char *, uint);
int vrfy_ip (struct ip *, uint32_t, u_short *);
int vrfy_tcp (struct tcphdr *, uint32_t, u_short *);
int decode_nvt(u_char *, uint, u_char *, uint *, u_char *, uint *);

