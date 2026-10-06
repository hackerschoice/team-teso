#ifndef PORTSCAN_H
#define PORTSCAN_H
#include <pthread.h>
#include <sys/types.h>
#include <libnet.h>
#include <pcap.h>

#define DEBUG

/* maximum number of packets allowed to be "unanswered" at any one time.
 * Change if you have more bandwidth - this value seems to work best for
 * my 28.8 dialup :-)
 */
#define MAXPACKETS 30

/* How many times portscan should resend unanswered packets, a higher
 * value will slow it down some what.
 */
#define MAXSENDS 3

#define P_NOCHECK 0
#define P_OPEN 1
#define P_CLOSED 2
#define P_CHECKING 3
#define P_DONE 4

#define SYN 1
#define FIN 2
#define XMAS 3
#define RPC 4
#define P_PING 5
#define P_SYN 6
#define P_LINUX 7
#define P_RPC 8

#define RESENDS 3

#define SA struct sockaddr

#define TIMEVAL_SUBTRACT(a1,a2) ((a1.tv_sec-a2.tv_sec)*1e6 \
				 -a2.tv_usec+a1.tv_usec)

typedef struct {
	u_int16_t 	port;
	unsigned char 	result;
	struct timeval 	send;
	unsigned char 	numsends;
} port;

/* global vars */

#ifndef PORTSCAN_MAIN
#define EXTERN extern
#else
#define EXTERN
#endif

EXTERN port 		*ports;
EXTERN int 		portcount;

EXTERN struct in_addr 	dest,
			last_dest,
			local;
EXTERN FILE 		*infile,
			*logfile;

EXTERN u_int32_t	rpc_prog;
EXTERN int32_t		rtt;
EXTERN int		rawfd,
			icmpfd,
			dlt_len;
EXTERN struct pcap	*pcap_d;
EXTERN unsigned char	errbuf[255];

typedef struct libnet_ip_hdr	ip_hdr;
typedef struct libnet_udp_hdr	udp_hdr;
typedef struct libnet_tcp_hdr	tcp_hdr;
typedef struct libnet_icmp_hdr  icmp_hdr;

struct _options {
	char randomize;
	char scandead;
	char aeroscan;
	char scanstyle;
	char frag;
	char verbose;
	unsigned char *interface;
};

EXTERN struct _options opts;

/* main.c */
int nextip(void);

/* pingscan.c */
int start_parallel_scan(void);

/* portscan.c */
int port_scan(void);
int rpc_scan(void);

/* parse.c */
int parse_args(char *string,char **args,const char *delimiters,int maxargs);

/* stuff.c */
int Socket(int domain, int type, int protocol);
int Print(char *fmt,...);
int Sendto(int s,const void *msg,int len,unsigned int flags,\
		const struct sockaddr *to,int tolen);
void *xmalloc(size_t size);
char *get_interface(struct in_addr addr);
int unblock(int fd);

/* aeroscan.c */
int aeroscan(void);
#endif /* PORTSCAN_H */
