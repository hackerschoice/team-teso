/*
 * bscan, lame (and hopefully fast) banner scanner [port 21,25,110,...]
 *
 * "<es> skyper its a cool idea"
 * "<es> i'd like to see the k0ad when ur finished"
 * HI ES :) 
 * greetings to all my !el8 brothers :))
 */

#include <stdio.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <pthread.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef __USE_BSD
#define __USE_BSD
#endif
#ifndef __BSD_SOURCE
#define __BSD_SOURCE
#endif
#include "arpg.h"
#include "network_raw.h"


#define SPF_SMAC	"\x00\x20\xAF\xA3\x13\x37"

#define OPT_VERB	0x1
#define OPT_RESERV1	0x2
#define OPT_SETARP	0x4
#define OPT_SPREADSCAN	0x8
#define OPT_OUTONLY	0x10

#define OPT_ABRT	0x20
#define OPT_REST	0x40
#define OPT_HOSTFILE	0x80
#define OPT_W8SEMA	0x100


struct _opt
{
    int (*getnextip) ();
    int sox;
    u_char *packet;
    int pkg_maxlen;
    int pkg_len;		/* actual length of contructed packet */
    char *hostfile;
    char **argvlist;
    FILE *ffd;			/* e.g. input file */
    char *target;
    unsigned long netmask;	/* depricated */
    unsigned long network;	/* depricated */
    unsigned int limit;
    unsigned short flags;
    unsigned long random_maxcount;
    u_int delay;		/* w8 for outstanding packets */
    u_int pscanstat;		/* scan stats every x pkts, default NEVER */
    u_long start_ip;		/* in HBO */
    u_long end_ip;		/* in HBO */
    u_long ipscan_count;	/* scanned ip's of a SPECIFIC range [temp!] */
    u_long iptotscan_count;	/* total scan_count over all ranges */
				/* used for flood protection */
    u_long bsent_count;		/* byte-sent counter. TMP (!) variable */
    u_long ip_offset;		/* spread scan offset */
    u_long ip_blklen;		/* block-length for spread-scan */
    u_long ip_pos;		/* position for SPREAD scan, non-linear */
    struct timeval scan_start;	/* scan start for ALL  ranges */
				/* the real beginning */
    struct timeval tv2;		/* flood protection timer 2 + restore */
			 	/* must be the last gettimeofday() from scan */
    float sec;			/* flood protection distance time */
    struct _libnet lnet;
    u_char spf_smac[6];		/* spoofed ethernet sender mac */
    pthread_t bscantid;		/* 'parent' thread id */
    pthread_t snarftid;		/* snarf thread id */
    struct _snarf
    {
	u_long icmp_c;
	u_long close_c;
	u_long open_c;
	u_long refused_c;
    }
    snarf;
    struct net_tuple nt;
};


void make_iprange (u_long *, u_long *, u_long *, u_long *, char *);
void init_spreadscan (u_long diff);
void sigdriver (int);
void print_scanstat (FILE *);
void die (int);
