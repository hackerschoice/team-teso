/*
 * mod_example.c
 * Example module for bscan.
 */

#include <bscan/bscan.h>
#include <bscan/module.h>
#include <stdio.h>


#ifndef MOD_NAME
#define MOD_NAME	"mod_httpd"
#endif

#define HEADREQ		"HEAD / HTTP/1.0\r\n\r\n"


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

struct _mopt
{
    unsigned short int dport;	/* dport in NBO */
    char *request;	/* the http-request */
} static mopt;

/*
 * static functions prototypes
 */
static int mdo_opt(int, char **, struct _opt *);
static void init_vars(struct _opt *);
static int process_rcv(struct _opt *);

/*
 * print out usage informations
 */
void
musage()
{
    printf ("\n"MOD_NAME"\n");
    printf (" -p <port>, default 80\n");
    printf (" -r <request>, default 'HEAD / HTTP/1.0'\n");
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
 * 
 */
int
callmdl(int entry, struct _opt *opt)
{
#ifdef DEBUG
	printf("MODULE CALLMDL\n");
#endif
	if (entry == MOD_FIRSTPKG)
		return(RMOD_SKIP);

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
    mopt.dport = htons(80);
    mopt.request = HEADREQ;
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

    while ((c = getopt (argc, argv, "p:r:")) != -1)
    {
	switch (c)
	{
	case 'p':
	   mopt.dport = htons(strtoul (optarg, (char **) NULL, 10));
           break;
	case 'r':
	   mopt.request = optarg;
	   fprintf(stderr, MOD_NAME ": requesting \"%s\"\n", optarg);
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
 * process incoming packets 
 * IP-packet is verified and variables valid (ip_options, *ip)
 */
static int
process_rcv(struct _opt *opt)
{
    struct tcphdr *tcp;
    unsigned short tcp_options = 0;
    uint iphdr_len = 0;


    if (ip->ip_p != IPPROTO_TCP)
        return(0);

    iphdr_len = sizeof(*ip) + ip_options;
    tcp = (struct tcphdr *) (align_buf + iphdr_len);

    if (vrfy_tcp(tcp, plen - dlt_len - iphdr_len, &tcp_options) != 0)
	return(0);

    if (tcp->th_sport != mopt.dport)
	return(0);

    if ((tcp->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
        answer_tcp (opt->sox, ip, tcp, TH_ACK | TH_PUSH, mopt.request, strlen(mopt.request));

   return(0);
}

