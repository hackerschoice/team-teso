/*
 * mod_example.c
 * Example module for bscan.
 */

#include <bscan/bscan.h>
#include <bscan/module.h>
#include <bscan/dcd_icmp.h>
#include <bscan/system.h>
#include <stdio.h>
#include <unistd.h>


#ifndef MOD_NAME
#define MOD_NAME	"mod_banner"
#endif

#define SCN_NVT         0x00000001
#define SCN_HALFOPEN    0x00000002
#define SCN_XMAS        0x00000004
#define SCN_FIN         0x00000008
#define SCN_NULL        0x00000010
#define SCN_PUSH        0x00000020
#define SCN_LETOPEN	0x00000040
#define SCN_NOSCAN	0x00000080
#define SCN_NOICMP	0x00000100


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
    u_int scanflags;
    uint8_t th_flags;
} static mopt;
	

/*
 * static functions prototypes
 */
static int mdo_opt(int, char **, struct _opt *);
static void init_vars(struct _opt *);
static int process_rcv(struct _opt *);
static void handle_icmp ();



/*
 * print out usage informations
 */
void
musage()
{
    printf ("\n"MOD_NAME"\n");
    printf (" -o <source port>, default 20\n");
    printf (" -p <port to scan>, default 21\n");
    printf (" -a grab all data and let the connecten established\n");
    printf (" -n NVT terminal support (use this for telnetd-scans)\n");
    printf (" -I dont report ICMP-errors\n");
    printf (" -q quite, dont send out any initial packages [first-pkg]\n");
    printf ("    "MOD_NAME" only reports ICMP errors and doesn't start\n");
    printf ("    scanning. It will still simulate the tcp-stack.\n");
    printf 
	(" -sS,-sF,-sX,-sN,-sP TCP SYN stealth, Fin, Xmas, Null, !Push scan\n");

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
	{
		if (mopt.scanflags & SCN_NOSCAN)
			return(RMOD_SKIP);

		add_tcphdr(opt->packet + ETH_SIZE + IP_SIZE, &opt->nt, mopt.th_flags, 0, NULL, NULL);
		add_iphdr (opt->packet + ETH_SIZE, IPPROTO_TCP, &opt->nt, TCP_SIZE);
		opt->pkg_len = TCP_SIZE + IP_SIZE;
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
    opt->nt.sport = htons(20);	/* not used by master programm */
    opt->nt.dport = htons(21);  /* not used by master programm */

    mopt.scanflags = 0;
    mopt.th_flags = TH_SYN;
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

    while ((c = getopt (argc, argv, "Iqans:p:o:")) != -1)
    {
	switch (c)
	{
	case 'I':
	   mopt.scanflags |= SCN_NOICMP;
	   break;
	case 'q':
	   mopt.scanflags |= SCN_NOSCAN; 
	   break;
	case 'p':
	   opt->nt.dport = htons(strtoul (optarg, (char **) NULL, 10));
	   break;
	case 'o':
	   opt->nt.sport = htons(strtoul (optarg, (char **) NULL, 10));
	   break;
	case 'a':
           mopt.scanflags |= SCN_LETOPEN;
	   break;
	case 'n':
	   mopt.scanflags |= SCN_NVT;	/* NVT parsing */
	   break;
        case 's':
            switch (optarg[0])
            {
            case 'S':
                mopt.scanflags |= SCN_HALFOPEN;
                mopt.th_flags = TH_SYN;
                break;
            case 'X':
                mopt.scanflags |= SCN_XMAS;
                mopt.th_flags = (TH_FIN | TH_PUSH | TH_URG);
                break;
            case 'F':
                mopt.scanflags |= SCN_FIN;
                mopt.th_flags = TH_FIN;
                break;
            case 'N':
                mopt.scanflags |= SCN_NULL;
                mopt.th_flags = 0;
                break;
            case 'P':
                mopt.scanflags |= SCN_PUSH;
                break;
	    default:
		fprintf(stderr, "unrecognized option -s%c\n", optarg[0]);
		return(-1);
            }
            break;
        case ':':
	    fprintf(stderr, "missing parameter\n");
	    return(-1);
        default:
	    return(-1);
	}
    }

    if ((mopt.scanflags & SCN_NVT) && !(mopt.scanflags & SCN_LETOPEN))
	fprintf(stderr, "WARNING: NVT used without -a. This is probably not what you want!\n");

    return(0);
}


/*
 * vrfy the icmp packet and print out 'human readable'-icmp code
 * dest-unreachable packages only!
 */
static void
handle_icmp (int offset)
{
    struct icmp *icmp = (struct icmp *) (align_buf + offset);
    struct ip *icmpip;

    if (plen < offset + sizeof (*icmp) + dlt_len)
        return;

    icmpip = (struct ip *) (align_buf + offset + ICMP_HDRSIZE);

    printf ("%s (%d/%d) %s", int_ntoa (icmpip->ip_dst.s_addr),
            icmp->icmp_type, icmp->icmp_code,
            icmp_str (icmp->icmp_type, icmp->icmp_code));
    printf ("(from %s)\n", int_ntoa (ip->ip_src.s_addr));
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
    u_char *data = NULL;
    u_char *ans = NULL; 	/* tcpdata answer */
    u_char prefix[32];
    int data_len = 0;
    uint ans_len = 0;
    uint res_len = 0;
    uint tcphdr_len = 0;
    uint iphdr_len = 0;


    if (ip->ip_p == IPPROTO_ICMP)
    {
        opt->snarf.icmp_c++;			/* for statistics	*/
	if (!(mopt.scanflags & SCN_NOICMP))
        	handle_icmp (sizeof (*ip) + ip_options);

        return(0);
    }

    if (ip->ip_p != IPPROTO_TCP)
        return(0);

    iphdr_len = sizeof(*ip) + ip_options;
    tcp = (struct tcphdr *) (align_buf + iphdr_len);

    if (vrfy_tcp(tcp, plen - dlt_len - iphdr_len , &tcp_options) != 0)
	return(0);

    if (tcp->th_flags & TH_RST)
    {
        opt->snarf.refused_c++;
        printf ("%s:%d refused\n", int_ntoa (ip->ip_src.s_addr),
                ntohs (tcp->th_sport));
    }
    else if (tcp->th_flags & TH_FIN)
    {
        opt->snarf.close_c++;
        answer_tcp (opt->sox, ip, tcp, TH_FIN | TH_ACK, NULL, 0);
        printf ("%s:%d connection closed by foreig host\n",
                int_ntoa (ip->ip_src.s_addr), ntohs (tcp->th_sport));
    }
    else if ((tcp->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
    {

        if (mopt.scanflags & SCN_HALFOPEN)
        {
            if (!(mopt.scanflags & SCN_LETOPEN))
                answer_tcp (opt->sox, ip, tcp, TH_ACK | TH_RST, NULL, 0);
            return(0);
        }
        else
            answer_tcp (opt->sox, ip, tcp, TH_ACK, NULL, 0);

        opt->snarf.open_c++;
        printf ("%s:%d open\n", int_ntoa (ip->ip_src.s_addr),
                ntohs (tcp->th_sport));
    }

    /* banner scanner output */
    tcphdr_len = sizeof(*tcp) + tcp_options;
    if (plen - dlt_len > ntohs(ip->ip_len))
	data_len = ntohs(ip->ip_len) - iphdr_len - tcphdr_len;
    else
	data_len = plen - dlt_len - iphdr_len - tcphdr_len;

    if (data_len <= 0)
	return(0);
    
    if ( (data = alloca(data_len + 1)) == NULL)
	return(-1);

    memcpy(data, align_buf + iphdr_len + tcphdr_len, data_len);

    if (mopt.scanflags & SCN_NVT)
    {
	if ((ans = alloca(data_len)) == NULL)
	    return(-1);

	decode_nvt(data, data_len, ans, &ans_len, data, &res_len);
	data_len = res_len;	/* we wrote everything into data */
    }

    snprintf(prefix, sizeof(prefix) - 1, "%s:%d ", int_ntoa(ip->ip_src), 
							ntohs (tcp->th_sport));
    save_write(stdout, prefix, data, data_len);

    if (tcp->th_flags & TH_RST) /* data_len != 0 */
	return(0);	/* evil peer resetted our connection */

    /* close after first data package or ack last RST if data_len >0 */
    if (!(mopt.scanflags & SCN_LETOPEN) || (tcp->th_flags & TH_RST))
        answer_tcp (opt->sox, ip, tcp, TH_ACK | TH_RST, ans, ans_len); 
    else
        answer_tcp (opt->sox, ip, tcp, TH_ACK, ans, ans_len);


   return(0);
}
