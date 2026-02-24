/*
 * This is unpublished proprietary source code.
 *
 * The contents of these coded instructions, statements and computer
 * programs may not be disclosed to third parties, copied or duplicated in
 * any form, in whole or in part, without the prior written permission of
 * the author.
 * (that includes you hack.co.za and other lame kid sites who dont
 *  get the point what hacking is about. damn kids.)
 *
 * (C) COPYRIGHT by me, 2000
 * All Rights Reserved
 */


#include <stdlib.h>
#include <math.h>
#include <bscan/bscan.h>
#include <bscan/snarf.h>
#include <bscan/tty.h>
#include <bscan/system.h>
#include <bscan/restore.h>
#include <bscan/module.h>
#include <bscan/version.h>
#include <bscan/cf_prse.h>
#include <sys/types.h>
#include <signal.h>
#include <math.h>
#include <libnet.h>

#ifdef HAVE_DLSYM
extern const int modcount;
extern const struct _mods mods[MAX_MODULES];
#endif

unsigned char packet[1024];
struct _opt *opt;

#define OPTS	"XOVhavr:C:L:M:m:l:d:p:i:s:f:o:"

static unsigned long int	gennextip (void);
static unsigned long int	gennext_spreadip (void);
static unsigned long int	gennext_random (void);

/*
 * make static mac entry in arp-table.
 * We use system() here [setting mac entry is heavily system dependent]
 */
int
setarp (uint32_t ip, u_char * mac)
{
    char buf[128];
    u_char *p = (u_char *) mac;

    snprintf (buf, sizeof (buf) - 1,
	      "arp -s %s %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x", int_ntoa (ip),
	      p[0], p[1], p[2], p[3], p[4], p[5]);
    /* put all your IFL fun in here ! this is the major security hole
       you were looking for.... */

    return (system (buf));
}


/*
 * delete the mac entry from the arp-table.
 * we use system() again
 */
int
unsetarp (uint32_t ip)
{
    char buf[128];

    snprintf (buf, sizeof (buf) - 1, "arp -d %s", int_ntoa (ip));
    /* put all your IFL fun in here ! this is the major security hole
       you were looking for.... */

    return (system (buf));
}


static void
usage (int code, char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    u_char *p = (u_char *) opt->spf_smac;
    int c;

    printf (VERSION "\n");
    printf (" b-scan -s <spoofed source ip> [options] <host/network> ...\n");
    printf ("   format of <host/network>:\n");
    printf ("      <host>, 10.23.0.1 or\n");
    printf ("      <start ip>-<end ip>, 10.23.0.1-10.23.255.254 or\n");
    printf ("      <start network/mask>, 10.23.0.1/16\n\n");
    printf ("Options:\n");
    printf (" -r <restore.bscan>\n");
#ifdef HAVE_DLSYM
    printf (" -L <module.so, shared library file>\n");
#endif
    printf (" -f <hostlist, one ip/line>\n");
    printf (" -s <spoofed ip address on your LOCAL (!) network>\n");
    printf (" -m <mac>, make a static arp-entry and spoof from this mac.\n");
    printf
	(" -M <mac>, dont make the static arpentry but spoof from this mac.\n");
    printf ("    Add the mac to your arp-table manually (arp -s ip mac),\n");
    printf ("    If no mac is given default mac is used:\n");
    printf ("    MAC : %x:%x:%x:%x:%x:%x\n", p[0], p[1], p[2], p[3], p[4],
	    p[5]);
    printf (" -i <ethernet interface>, default eth0\n");
    printf
	(" -X spreadmode [non-sequential, experimental but recommended]\n");
    printf (" -O output ip's, dont scan\n");
    printf
	(" -l <pps> limit packets per second, default 1000, 0 = unlimited\n");
    printf
	(" -d <delay> w8 delay seconds for outstanding packets, default 10\n");
    printf (" -C <configuration file>\n");
    printf (" -v verbose output\n\n");
    printf ("Example:\n");
    printf ("# bscan -s 10.1.6.6 -i eth2 -L \"modules/mod_banner.so\" -X 2.4.1.0-2.4.9.9\n");

#ifdef HAVE_DLSYM
    for (c = 0; c < modcount; c++)
	mods[c].musage ();
#endif

    if (fmt != NULL)
    {
	va_start (ap, fmt);
	vsnprintf (buf, sizeof (buf) - 1, fmt, ap);
	va_end (ap);
	fprintf (stderr, "ERROR: %s\n", buf);
    }

    exit (code);
}

/*
 * read's next ip from file. 
 * returns ip in NBO
 * returns -1 (eg. 255.255.255.255) on failure
 */
unsigned long int
readnextip (void)
{
    char buf[64];

    if (opt->ffd == NULL)
    {
	if ((opt->ffd = fopen (opt->hostfile, "r")) == NULL)
	{
	    perror ("unable to open hostfile");
	    return (-1);
	}
	opt->target = opt->hostfile;
    }
    fgets (buf, sizeof (buf), opt->ffd);

    return (inet_addr (buf));
}

/*
 * get next ip in NBO from network/mask
 * [could be random order]
 * returns -1 [255.255.255.255] if no more ip's
 * hint: rfc: "the first and last ip in a subnetwork are reserved"
 */
static unsigned long int
gennextip (void)
{

    if (opt->ip_pos <= opt->end_ip)
	return (htonl (opt->ip_pos++));

    return (-1);

}

/*
 * generate next ip in spread-mode
 * must: ip.end_ip - ip.start_ip > 2 
 */
static unsigned long int
gennext_spreadip (void)
{
    u_long pos = opt->ip_pos;


    if ((opt->ip_offset + 1 >= opt->ip_blklen) && (opt->ip_pos > opt->end_ip))
	return (-1);

    if ((opt->ip_pos + opt->ip_blklen > opt->end_ip)
	&& (opt->ip_offset + 1 < opt->ip_blklen))
	opt->ip_pos = opt->start_ip + (++opt->ip_offset);
    else
	opt->ip_pos += opt->ip_blklen;

    return (htonl (pos));

}


static unsigned long int
gennext_random (void)
{
    unsigned long int	ip;

    if (opt->random_maxcount != 0) {
	if (--opt->random_maxcount == 0)
	    return (-1);
    }

pitch:
    ip = (random () & 0xffff) << 16;
    ip |= random () & 0xffff;

    if (((ip & 0xe0000000) >= 0xe0000000) ||	/* 224.0.0.0/3 */
	((ip & 0xff000000) == 0x7f000000) ||	/* 127.0.0.0/8 */
	((ip & 0xff000000) == 0x0a000000) ||	/* 10.0.0.0/8 */
	((ip & 0xffff0000) == 0xc0a80000) ||	/* 192.168.0.0/16 */
	((ip & 0xffff0000) == 0xac100000) ||	/* 172.16.0.0/16 */
	(ip == 0x00000000))			/* 0.0.0.0/32 */
	goto pitch;

    return (htonl (ip));
}


/*
 * process all the options and load/init modules
 */
void
do_opt (int argc, char *argv[])
{
    extern char *optarg;
    extern int optind; /*, opterr, optopt;*/
    unsigned short int sp[ETH_ALEN];
    int c;
    char do_usage = 0;


    while ((c = getopt (argc, argv, OPTS)) != -1)
    {
	switch (c)
	{
	case 'C':		/* process conf file */
	    if (readConfFile (optarg))
	      {
		opt->flags |= FileOpt.flags;
		opt->limit = FileOpt.limit;
		opt->delay = FileOpt.delay;
		opt->nt.src = FileOpt.srcAddr;
		opt->lnet.device = FileOpt.device;
                for (c = 0; c < 6; c++)
                  opt->spf_smac[c] = FileOpt.mac[c];
	      }
	    else
	      fprintf (stderr, "%s is not a valid vonfig file\n", optarg);
	    break;
	case 'L':
	    break;		/* process module stuff AFTER main-opts */
	case 'h':
	    do_usage = 1;
	    break;
	case 'r':
	    if (read_restore (optarg) != 0)
	    {
		fprintf (stderr, "unable to read restore file '%s'\n",
			 optarg);
		exit (-1);
	    }
	    opt->flags |= OPT_REST;
	    break;
	case 'l':
	    opt->limit = atoi (optarg);
	    break;
	case 'v':
	    opt->flags |= OPT_VERB;
	    break;
	case 'X':
	    opt->flags |= OPT_SPREADSCAN;
	    break;
	case 'O':
	    opt->flags |= OPT_OUTONLY;	/* dont scan, output ip's only */
	    break;
	case 'm':
	    opt->flags |= OPT_SETARP;
	    sscanf (optarg, "%hx:%hx:%hx:%hx:%hx:%hx", &sp[0], &sp[1], &sp[2],
		    &sp[3], &sp[4], &sp[5]);
	    for (c = 0; c < 6; c++)
		opt->spf_smac[c] = (u_char) sp[c];
	    break;
	case 'M':
	    opt->flags &= ~OPT_SETARP;
	    sscanf (optarg, "%hx:%hx:%hx:%hx:%hx:%hx", &sp[0], &sp[1], &sp[2],
		    &sp[3], &sp[4], &sp[5]);
	    for (c = 0; c < 6; c++)
		opt->spf_smac[c] = (u_char) sp[c];
	    break;
	case 'd':
	    opt->delay = atoi (optarg);
	    break;
	case 'i':
	    opt->lnet.device = optarg;
	    break;
	case 's':
	    opt->nt.src = inet_addr (optarg);
	    break;
	case 'f':
	    opt->hostfile = optarg;
	    opt->flags |= OPT_HOSTFILE;
	    break;
	case 'V':
	    printf (VERSION "\n");
	    exit (0);
	case ':':
	    usage (0, "parameter missing", c);
	    break;
	default:
	    break;
	    usage (0, "unknown option -%c", c);
	}
    }

    /*
     * init modules AFTER processing main-opts
     */
#ifdef HAVE_DLSYM
    optind = 1;
    while ((c = getopt (argc, argv, OPTS)) != -1)
    {
	switch (c)
	{
	case 'L':
	    loadinit_mod(optarg);
	    break;
	}			/* eo switch(c) */
    }				/* eo while */
#endif
    if (do_usage != 0)
	usage (0, NULL);

    if ((optind < argc) && (!(opt->flags & OPT_REST)))
	opt->argvlist = &argv[optind];
    if (opt->flags & OPT_OUTONLY)
	opt->delay = 0;
    if (opt->nt.src == -1)
	usage (0, "you must specify a -s source address");
    if ((opt->argvlist == NULL) && (opt->hostfile == NULL))
	usage (0, "you must specify a -f hostfile or an ip-range");

}

/*
 * called via SIGCHLD and w8 for the pid [to destroy last kernel structure]
 * OBSOLETE, ###fixme
 */
void
waitchld (int sig)
{
    int status;
    wait (&status);		/* exit status of the child */
}

void
sig_handle_abort (int sig)
{

    if (pthread_self() != opt->bscantid)
	return;

    fprintf (stderr, "Session aborted ...one more to kill process\n");
    signal (sig, die);
    opt->flags |= OPT_ABRT;
}

/*
 * generic signal driver :>
 */
void
sigdriver (int sig)
{

    if (pthread_self() != opt->bscantid)
	return;

    if (sig == SIGUSR1)
	print_scanstat (stderr);
    if ((sig == SIGINT)	|| (sig == SIGQUIT))	/* ctrl-c */
	sig_handle_abort (sig);
}

/*
 * This function MUST be called on exit (..or use atexit():)
 * we have threads. Doesnt matter which thread calls this
 * function...do everything and exit() the process 
 * (kills all threads...not very gentle...but...).
 */
void
die (int sig)
{
    int c = 0;

    print_scanstat (stderr);	/* print before cleanup routines...*/

    if (opt->flags & OPT_ABRT)
        if (write_restore () != 0)
	    perror ("restorefile failed");
	if ((opt->flags & OPT_SETARP) && (unsetarp (opt->nt.src) != 0))
	    fprintf (stderr, "unable to unset arpentry. do it manually\n");
#ifdef HAVE_DLSYM
	while (c < modcount)
	    mods[c++].fini ();
#endif

#ifdef DEBUG
    printf ("calling exit.\n");
#endif

    fflush (stdout);

    exit (0);
}

/*
 * reset all vars used during the scan (counters, ...)
 * should be called before the call to make_iprange()
 * If not...make_iprange thinks we use restore-file
 */
void
reset_vars ()
{
    opt->target = NULL;
    opt->ipscan_count = 0;
    opt->bsent_count = 0;
    opt->ip_offset = 0;
    opt->ip_blklen = 0;
    opt->ip_pos = 0;
    opt->start_ip = 0;
    opt->end_ip = 0;
    opt->snarf.close_c = 0;
    opt->snarf.open_c = 0;
    opt->snarf.refused_c = 0;
    opt->snarf.icmp_c = 0;
}


void
init_vars (char **nullptr)
{
    srandom ((unsigned int) time (NULL));

    if ((opt = calloc (1, sizeof (*opt))) == NULL)
    {
	perror ("calloc");
	exit (-1);
    }
    memset (opt, 0, sizeof (struct _opt));

    opt->bscantid = 0;
    opt->snarftid = 0;
    opt->packet = packet;
    opt->pkg_maxlen = sizeof (packet);
    opt->pkg_len = 0;
    opt->scan_start.tv_sec = 0;
    opt->iptotscan_count = 0;
    opt->scan_start.tv_usec = 0;
    opt->hostfile = NULL;
    opt->limit = 1000;
    opt->flags = OPT_SETARP;
    opt->ffd = NULL;
    opt->argvlist = nullptr;
    opt->lnet.device = NULL;	/* done by libnet and libpcap */
    memcpy (opt->spf_smac, SPF_SMAC, 6);
    opt->nt.src = -1;
    opt->nt.dst = -1;
    opt->delay = 10;
    opt->lnet.device = NULL;
    reset_vars ();

    signal (SIGINT, sigdriver);
    signal (SIGQUIT, sigdriver);
    signal (SIGTERM, die);	/* also called by client */
    signal (SIGCHLD, SIG_IGN);
    signal (SIGUSR1, sigdriver);
}

void
print_opt ()
{
    u_char *p = (u_char *) opt->spf_smac;

    fprintf (stderr, "Pid           : %d\n", getpid());
    fprintf (stderr, "Interface     : %s\n", opt->lnet.device);
    fprintf (stderr, "Source IP     : %s\n", int_ntoa (opt->nt.src));
    fprintf (stderr, "Source MAC    : %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",
	     p[0], p[1], p[2], p[3], p[4], p[5]);
    fprintf (stderr, "pps           : %u\n", opt->limit);
}

/*
 * print scanstatistics on filedes
 */
void
print_scanstat (FILE * fd)
{
    char perc = 100;
    struct timeval tv2;
    time_t timep;
    struct tm mytm;

    gettimeofday (&tv2, NULL);
    time_diff (&opt->scan_start, &tv2);
    if (tv2.tv_sec == 0)
	tv2.tv_sec = 1;
    timep = tv2.tv_sec;
    gmtime_r (&timep, &mytm);

    if ((opt->end_ip - opt->start_ip) != 0)
	perc =
	    (((float)
	      opt->ipscan_count / (float) (opt->end_ip -
					   opt->start_ip)) * 100);

    fprintf (fd,
	     "%2.2d:%2.2d:%2.2d:%2.2d %s %3d%% p/s: %6d [o:%lu r:%lu c:%lu i:%lu]\n",
	     mytm.tm_yday, mytm.tm_hour, mytm.tm_min, mytm.tm_sec, 
             opt->target, perc, (int) (opt->iptotscan_count / tv2.tv_sec),
	     opt->snarf.open_c, opt->snarf.refused_c, opt->snarf.close_c,
	     opt->snarf.icmp_c);

}


/*
 * calculate beginning and end of ip-range
 * set start_ip and end_ip and target
 */
void
make_iprange (u_long * network, u_long * netmask, u_long * start_ip,
	      u_long * end_ip, char *str)
{
    char buf[64];
    char *ptr;

    opt->target = str;
    strncpy (buf, str, sizeof (buf));
    buf[sizeof (buf) - 1] = '\0';
    opt->getnextip = NULL;
    *start_ip = 0;

    if (strncmp (buf, "random", 6) == 0) {
	opt->getnextip = (void *) gennext_random;
	if (strchr (buf, ':') != NULL) {
	    sscanf (strchr (buf, ':') + 1, "%lu", &opt->random_maxcount);
	} else {
	    opt->random_maxcount = 0;
	}
	return;
    }

    /* a.b.c.d/e */
    if (strchr (buf, '/') != NULL)
    {
	*netmask = 0xffffffff;	/* for the lamers who forget the /<netmask> */

	if ((ptr = (char *) strrchr (buf, '/')) != NULL)
	    *netmask = 0xffffffff << (32 - atoi (ptr + 1));

	if ((ptr = (char *) strchr (buf, '/')) != NULL)
	    *ptr = '\0';

	*network = (ntohl (inet_addr (buf)) & *netmask);
	*start_ip = (*network & *netmask) + 1;
	*end_ip = (*network | ~*netmask) - 1;
	if (*netmask >= 0xfffffffe)
	    (*start_ip)--;
	if (*netmask == 0xffffffff)
	    (*end_ip)++;
    }

    /* a.b.c.d - w.x.y.z */
    if ((*start_ip == 0) && ((ptr = (char *) strrchr (buf, '-')) != NULL))
    {
	*end_ip = ntohl (inet_addr (ptr + 1));
	*ptr = '\0';
	*start_ip = ntohl (inet_addr (buf));
    }

    /* a.b.c.d */
    if (*start_ip == 0)
    {
	*end_ip = ntohl (inet_addr (buf));
	*start_ip = ntohl (inet_addr (buf));
    }

    if (opt->ip_pos == 0)	/* if != 0 we use restore-file */
	opt->ip_pos = *start_ip;

    /* initialize getnextip-funtion and spread scan variables */
    if ((opt->flags & OPT_SPREADSCAN) && (opt->end_ip - opt->start_ip > 2))
    {
	init_spreadscan (opt->end_ip - opt->start_ip);
	opt->getnextip = (void *) gennext_spreadip;
    }
    else
    {
	opt->getnextip = (void *) gennextip;
    }

}

/*
 * initialize offset for spread-scan
 * call make_iprange before
 *
 * most networks are /24. dont let ip_blklen get to big
 */
void
init_spreadscan (u_long diff)
{
    opt->ip_blklen = (u_long) sqrt (diff);

    if (opt->ip_blklen > 100)	/* range is 100^2 large */
	opt->ip_blklen = 257 + opt->ip_blklen * 0.2;	/* use a prime# here */

}


/*
 * output the ip's only. dont scan.
 */
void
do_outonly ()
{
    uint32_t ip;

    while ((ip = (*opt->getnextip) ()) != -1)
    {
	opt->ipscan_count++;
	printf ("%s\n", int_ntoa (ip));
    }

}


/*
 * process a scanrange from argv
 * Return -1 if abort
 */
int
process_iprange ()
{
    int 	c = 0;
    int 	ret;
#ifdef HAVE_DLSYM
    int 	mc = 0;
#endif

    while ((opt->nt.dst = (*opt->getnextip) ()) != -1)
    {
	memset (opt->packet, 0, opt->pkg_maxlen);

	opt->pkg_len = 0;

	if (opt->flags & OPT_VERB)
	    fprintf (stderr, "scanning %s:%d\n",
		     int_ntoa (opt->nt.dst), ntohs (opt->nt.dport));

#ifdef HAVE_DLSYM
	for (mc = 0; mc < modcount; mc++)
	{
	    ret = mods[mc].callmdl (MOD_FIRSTPKG, opt);
	    if (ret == RMOD_SKIP)
		continue;
	    if (ret == RMOD_ABRT)
	    {
		fprintf(stderr, "oops: callmdl returned RMOD_ABRT\n");
		return(-1);
	    }
#endif

	    opt->bsent_count +=
		send_ipv4 (opt->sox, opt->packet + ETH_SIZE, opt->pkg_len);
            opt->iptotscan_count++;
	    opt->ipscan_count++;   /* linear ipscan-offset */

	    if (opt->ipscan_count % opt->limit == 0)	/* every second */
	    {
		if ((c = tty_getchar ()) != -1)
		    print_scanstat (stderr);
		if (opt->flags & OPT_ABRT)
		    return (-1);	/* sig_abort_handler called */
	    }

	    /* do floodprotection */
	    while (opt->limit > 0)
	    {
		/*
		 * forgett about the initial value of tv.tv_usec...
		 * This is called 'optimizing algorithms'. The usec does
		 * not count if you scan >>10seconds...
		 */
		gettimeofday (&opt->tv2, NULL);
		opt->sec = (opt->tv2.tv_sec - opt->scan_start.tv_sec)
		    - (opt->scan_start.tv_usec - opt->tv2.tv_usec) / 1000000.0;
		if ((opt->iptotscan_count / opt->sec) >= opt->limit)
		    usleep (10);	/* should give up timeslice */
		else
		    break;
	    }
#ifdef HAVE_DLSYM
	}			/* modcount-loop */
#endif
    }
    return (0);
}

void *
p_doit(void *arg)
{
  printf("first thread here\n");
  sleep(100);
  return NULL;
}


int
main (int argc, char *argv[])
{
    struct sockaddr_in 	saddr;
    struct timeval 	tv;
    int 		size;
    int			pstatus;	/* pthread error status */	
#ifdef IP_HDRINCL
    const int 		on = 1;
#endif

    init_vars (&argv[argc]);		/* before do_opt */

    do_opt (argc, argv);
    tty_init ();

    if (opt->flags & OPT_SETARP)
	if (setarp (opt->nt.src, opt->spf_smac) != 0)
	{
	    fprintf (stderr, "unable to set arpentry. do it manually\n");
	    exit (1);
	}

    init_network_raw ();	
    prepare_libnet (&opt->lnet); /* used by arpg.c and maybe by bscan.c */

    memset (&saddr, 0, sizeof (saddr));

    if ((opt->sox = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
	fprintf (stderr, "error creating socket\n");
	exit (1);
    }
#ifdef IP_HDRINCL
    if (setsockopt (opt->sox, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0)
    {
	fprintf (stderr, "error setsockopt\n");
	exit (1);
    }
#endif

    size = 160 * 1024;		/* OK if setsockopt fails */
    setsockopt (opt->sox, SOL_SOCKET, SO_SNDBUF, &size, sizeof (size));

    opt->flags |= OPT_W8SEMA;
    opt->bscantid = pthread_self();
    pstatus = pthread_create(&opt->snarftid, NULL, &do_snarf, opt->lnet.device);
    if (pstatus != 0)
	err_abort(pstatus, "pthread_create");

    while (opt->flags & OPT_W8SEMA)
	usleep(50);

    print_opt ();

    if (opt->scan_start.tv_sec == 0)
	gettimeofday (&opt->scan_start, NULL);

    while ((*opt->argvlist != NULL) || (opt->flags & OPT_HOSTFILE))
    {
	if (!(opt->flags & OPT_REST))
	    reset_vars ();	/* reset all counting variables */

	if (!(opt->flags & OPT_HOSTFILE))
	{
	    make_iprange (&opt->network, &opt->netmask, &opt->start_ip,
			  &opt->end_ip, *opt->argvlist++);
	}
	else
	{
	    opt->getnextip = (void *) readnextip;
	    if (opt->flags & OPT_REST)
	    {
		int c = 0;

		fprintf (stderr, "restore: skipping %lu in '%s'\n",
			 opt->ipscan_count, opt->hostfile);
		while (c++ < opt->ipscan_count)
			if ((*opt->getnextip) () == -1)
				break;
	    }
	}

	opt->flags &= ~OPT_REST;	/* 2nd.. init not by restorefile */

	if ((opt->getnextip == NULL) || (opt->nt.src == 0)
	    || (opt->nt.src == -1))
	    usage (0, "no ip/range given or nonparseable range, skip");
	if (opt->flags & OPT_OUTONLY)
	{
	    do_outonly ();
	    continue;
	}

	if (process_iprange () == -1)
	{
	    print_scanstat (stderr);
	    break;		/* abort scan ! */
	}

	if (opt->flags & OPT_HOSTFILE)
	    break;		/* process only ONE hostfile */

	if (*opt->argvlist != NULL)
	    print_scanstat (stderr);
    }

    gettimeofday (&tv, NULL);
    time_diff (&opt->scan_start, &tv);
    opt->sec = tv.tv_sec + tv.tv_usec / 1000000.0;
    fprintf (stderr, "scanned %lu ip's in %.3f seconds\n", opt->iptotscan_count,
	     opt->sec);
    if (opt->delay > 0)
    {
	fprintf (stderr, "waiting %d sec for outstanding packets...\n",
		 opt->delay);
	signal (SIGINT, die);	/* if waiting exit immediatly on INTR */
	sleep (opt->delay);
    }

    die (0);
    return (0);
}
