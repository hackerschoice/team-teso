/*
 * ping-module for bscan.
 * IDEA: add record-route and source-route feature
 *       and -p pattern [where can we save our time-struct then ?
 */

#include <bscan/bscan.h>
#include <bscan/module.h>
#include <bscan/system.h>
#include <stdio.h>


#ifndef MOD_NAME
#define MOD_NAME	"mod_ping"
#endif

static int process_rcv(struct _opt *);

static int isinit=0;
/*
 * some variables from the binary-process
 */
extern int dlt_len;
extern u_char *align_buf;
extern unsigned short ip_options;
extern struct ip *ip;
extern struct Ether_header *eth;
extern u_int plen, pcaplen;
extern struct timeval *pts;

struct _mopt
{
   int type;
   int size;
} static mopt;

/*
 * static functions prototypes
 */
static int mdo_opt(int, char **, struct _opt *);
static void init_vars(struct _opt *);

/*
 * print out usage informations
 */
void
musage()
{
    printf ("\n"MOD_NAME"\n");
    printf (" -t (echo|time) -s <size>, size of ping-data [default 56].\n");
}


/*
 * return 0 on success, != 0 on failure
 */
int
init(char **modname, int argc, char *argv[], struct _opt *opt)
{
#ifdef DEBUG
	printf("MODULE INIT\n");
#endif
	if (isinit)
		return(-1);

	*modname = MOD_NAME;
	isinit = 1;
  	init_vars(opt);

	if (mdo_opt(argc, argv, opt) != 0)
		return(-1);

	return(0);
}

/*
 * fini-routine. called on cleanup 
 */
int
fini()
{
#ifdef DEBUG
	printf("MODULE FINI\n");
#endif
	return(0);
}


/*
 * Module entry point [entry]
 * RMOD_OK: everything allright. send  the packet out [if first]
 *          or do nothing [MOD_RCV].
 * RMOD_SKIP: proceed with next IP without sending out the packet.
 */
int
callmdl(int entry, struct _opt *opt)
{
#ifdef DEBUG
	printf("MODULE CALLMDL\n");
#endif
	if (entry == MOD_FIRSTPKG)
	{
                add_icmpping (opt->packet + ETH_SIZE + IP_SIZE,	mopt.size, mopt.type);
		add_iphdr (opt->packet + ETH_SIZE, IPPROTO_ICMP, &opt->nt, ICMP_SIZE + mopt.size);
		opt->pkg_len = IP_SIZE + ICMP_SIZE + mopt.size;
		return(RMOD_OK);
	}

	if (entry == MOD_RCV)
		process_rcv(opt);

	return(RMOD_OK);
}


/*
 ***********************************************************
 *  Our OWN/static functions for THIS module               *
 ***********************************************************
 */

/*
 * initialize all local variables.
 * We use some 'unused' variables of the masterprogramm
 */
static void
init_vars(struct _opt *opt)
{
    mopt.size = ICMP_ECHO;
    mopt.size = 56;
}


/*
 * LOCAL/STATIC function, only available in the module
 * return 0 on success, != 0 on failure
 */
static int
mdo_opt(int argc, char *argv[], struct _opt *opt)
{
    extern char *optarg;
    /*extern int optind, opterr, optopt;*/
    int c;

    while ((c = getopt (argc, argv, "t:s:")) != -1)
    {
	switch (c)
	{
	case 't':
	   if (strcasecmp (optarg, "echo") == 0)
	     mopt.type = ICMP_ECHO;
	   else if (strcasecmp (optarg, "time") == 0)
	     mopt.type = ICMP_TSTAMP;
	   else
	     return (-1);
	   break;
	case 's':
	   mopt.size = atoi(optarg);	
	   break;
        case ':':
	    fprintf(stderr, "missing parameter\n");
	    return(-1);
        default:
	    return(-1);
	}
    }
    return(0);
}


/*
 * handle incoming icmp ECHO_REPLY packages
 */
static int
process_rcv(struct _opt *opt)
{
    struct icmp *icmp;
    struct timeval now;
    double rrt;

    if (ip->ip_p != IPPROTO_ICMP)
	return(0);

    if (plen < dlt_len + IP_SIZE + ip_options + sizeof(*icmp))
	return(0);	/* invalid size */

   icmp = (struct icmp *) (align_buf + IP_SIZE + ip_options);

//   if ((icmp->icmp_type != 0) || (icmp->icmp_code != 0))
//	return(0);
	
   memcpy(&now, pts, sizeof(now));
   time_diff((struct timeval *)icmp->icmp_dun.id_data, &now);
   rrt = now.tv_sec * 1000.0 + now.tv_usec / 1000.0;

   printf("%d bytes from %s: icmp_seq=%u ttl=%d time=%.3f ms\n",
	(int)(plen - dlt_len - IP_SIZE - ip_options),
	int_ntoa(ip->ip_src.s_addr), icmp->icmp_hun.ih_idseq.icd_seq,
	ip->ip_ttl, rrt);

   return(0);
   
}


