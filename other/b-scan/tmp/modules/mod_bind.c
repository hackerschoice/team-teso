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
#define MOD_NAME	"mod_bind"
#endif

/*
 * this is our query. This is a DNS-formated string
 * <length1><string1><length2><string2><0>
 */
#define DNSTXTREQ	"\007version\004bind"

static int process_rcv(struct _opt *);
static void add_dnshdr(unsigned char *);
static void add_dnstxthdr(unsigned char *, char *, u_int *);

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


struct _dnshdr
{
    u_short id;             /* DNS packet ID */
    u_short flags;          /* DNS flags */
    u_short num_q;          /* Number of questions */
    u_short num_answ_rr;    /* Number of answer resource records */
    u_short num_auth_rr;    /* Number of authority resource records */
    u_short num_addi_rr;    /* Number of additional resource records */
};

struct _dnsanswr
{
    u_short type;
    u_short class;
    u_short ttl1;
    u_short ttl2;
    u_short len;
};



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
    printf ("verson.bind chaos txt module\n");
    printf (" -p <port>, destination port, default 53\n");
    printf (" -o <port>, source port, default 53\n");
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
 		add_dnstxthdr (opt->packet + ETH_SIZE + IP_SIZE + UDP_SIZE + sizeof(struct _dnshdr), DNSTXTREQ, &opt->pkg_len);
		add_dnshdr (opt->packet + ETH_SIZE + IP_SIZE + UDP_SIZE);
                add_udphdr (opt->packet + ETH_SIZE + IP_SIZE, &opt->nt, opt->pkg_len + sizeof(struct _dnshdr));
		add_iphdr (opt->packet + ETH_SIZE, IPPROTO_UDP, &opt->nt, opt->pkg_len + UDP_SIZE + sizeof(struct _dnshdr));
		opt->pkg_len += IP_SIZE + UDP_SIZE + sizeof(struct _dnshdr);
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
    opt->nt.sport = htons(53);
    opt->nt.dport = htons(53);
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

    while ((c = getopt (argc, argv, "p:o:")) != -1)
    {
	switch (c)
	{
	case 'p':
	   opt->nt.dport = htons(atoi(optarg));	
	   break;
	case 'o':
	   opt->nt.sport = htons(atoi(optarg));	
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
 * add a DNS header
 */
static void
add_dnshdr(unsigned char *pkt)
{
    struct _dnshdr *dnshdr = (struct _dnshdr *)pkt;

    dnshdr->id = htons(6);	/* could be random */
    dnshdr->flags = htons(0x0100);	/* do query recursivly */
    dnshdr->num_q = htons(1);
    dnshdr->num_answ_rr = 0;
    dnshdr->num_auth_rr = 0;
    dnshdr->num_addi_rr = 0; 
/* add request here. class TXT etc */
}

/*
 * add DNS-TXT header here
 * returns length in *len
 */
static void
add_dnstxthdr(unsigned char *pkt, char *name, u_int *len)
{
    u_short *type;
    u_short *class;

    if (name == NULL)
	return;		/* nah! specifiy "". we need \0 termination */

    memcpy(pkt, name, strlen(name)+1);
    type = (u_short *)(pkt + strlen(name) + 1);
    class = (u_short *)(pkt + strlen(name) + 1 + sizeof(*class));
    
    *type = htons(0x10); 	/* TEXT string */
    *class = htons(0x03);	/* chaos */
    *len = strlen(name) + 1 + sizeof(*type) + sizeof(*class);
}


/*
 * handle incoming DNS udp answers
 */
static int
process_rcv(struct _opt *opt)
{
    struct _dnshdr *dns;
    struct _dnsanswr *dnsanswr;
    struct udphdr *udp;
    char *ptr;
    char buf[128];
    int len, dnstxtlen;
    uint iphdr_len = 0;

    if (ip->ip_p != IPPROTO_UDP)
	return(0);

    iphdr_len = IP_SIZE + ip_options;
    if (plen < dlt_len + iphdr_len + sizeof(*udp) + sizeof(*dns))
	return(-1);	/* invalid size */
    
    dns = (struct _dnshdr *) (align_buf + iphdr_len + sizeof(*udp));
    if (ntohs(dns->flags) & 0x000F)	/* dns-error? query refused ? */
        return(-1);

    ptr = (char *) (align_buf + iphdr_len + sizeof(*udp) + sizeof(*dns));
    len = dlt_len + iphdr_len + sizeof(*udp) + sizeof(*dns);

    while (len++ < plen)
        if (*ptr++ == '\0')
	    break;

    if (len >= plen)
        return(-1);

    len += 4;
    ptr += 4;
 
    while (len++ < plen)		/* skip VERSION.BIND answer string */
        if (*ptr++ == '\0')
            break;

    len += sizeof(*dnsanswr);
    if (len >= plen)
        return(-1);

    dnsanswr = (struct _dnsanswr *) (ptr);
    dnstxtlen = ntohs(dnsanswr->len);
    if (len + dnstxtlen > plen)	
	return(0); 

    if ((dnstxtlen == 0) || (dnstxtlen > 128))
	return(-1);

    memcpy(buf, ptr + sizeof(*dnsanswr) +1, dnstxtlen - 1); 
    buf[dnstxtlen - 1] = '\0';

    ptr = buf;		/* evil hax0rs sending messed up strings ? */
    while (*++ptr != '\0')
	if (!isprint((int)*ptr))
		*ptr = '_';

    printf("%s VERSION.BIND. \"%s\"\n", int_ntoa(ip->ip_src.s_addr), buf);

    return(0);
   
}


