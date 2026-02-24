/*
 * bscan, restore.c
 * this is the buggies part of the entire scanner :>
 * many buffer overflows in here
 */
#include <bscan/bscan.h>
#include <bscan/system.h>
#include <bscan/module.h>
#include <string.h>


extern struct _opt *opt;

#define RESTORE_FILE	"restore.bscan"

#define R_ARGVLIST	"argvlist"
#define R_MODARG	"modarg"
#define R_LIMIT		"limit"
#define R_FLAGS		"flags"
#define R_DELAY		"delay"
#define R_PSCANSTAT	"pscanstat"
#define R_IPSCAN_COUNT	"ipscan_count"
#define R_IPTOTSCAN_C	"iptotscan_count"
#define R_BSENT_COUNT	"bsent_count"
#define R_IP_OFFSET	"ip_offset"
#define R_IP_BLKLEN	"ip_blklen"
#define R_IP_POS	"ip_pos"
#define R_SCAN_TIME	"scan_time"
#define R_SPF_SIP	"spf_sip"
#define R_SPF_SMAC	"spf_smac"
#define R_SNARFICMP_C	"snarf.icmp_c"
#define R_SNARFCLOSE_C	"snarf.close_c"
#define R_SNARFOPEN_C	"snarf.open_c"
#define R_SNARFREFUSED_C	"snarf.refused_c"
#define R_IDEV		"lnet.device"
#define R_HOSTFILE	"hostfile"


/*
 * save everything that is required to restore/restart an inter session
 */
int
write_restore ()
{
    u_char *p = (u_char *) opt->spf_smac;
    FILE *fptr;
    char **myargv = opt->argvlist;
    struct timeval tv;
#ifdef HAVE_DLSYM
    int c=0;
    extern const int modcount;
    extern const struct _mods mods[MAX_MODULES];
#endif

    if (opt->flags & OPT_VERB)
	fprintf (stderr, "Writing restore file '%s'\n", RESTORE_FILE);

    if ((fptr = fopen (RESTORE_FILE, "w+")) == NULL)
	return (-1);

    fprintf (fptr, "# bscan restore file. This is an automatic generated\n");
    fprintf (fptr, "# file. Don't edit.\n");
    fprintf (fptr, "#\n");

    fprintf (fptr, R_ARGVLIST ": ");
    if ((opt->target != NULL) && !(opt->flags & OPT_HOSTFILE))
	fprintf (fptr, "\"%s\" ", opt->target);
    while (*myargv != NULL)
	fprintf (fptr, "\"%s\" ", *myargv++);
    fprintf (fptr, "\n");

#ifdef HAVE_DLSYM
    for (c = 0; c < modcount; c++)
   	fprintf(fptr, R_MODARG ": %s\n", mods[c].modarg);
#endif

    fprintf (fptr, R_LIMIT ": %u\n", opt->limit);
    fprintf (fptr, R_DELAY ": %u\n", opt->delay);
    fprintf (fptr, R_PSCANSTAT ": %u\n", opt->pscanstat);
    fprintf (fptr, R_IPSCAN_COUNT ": %lu\n", opt->ipscan_count);
    fprintf (fptr, R_IPTOTSCAN_C  ": %lu\n", opt->iptotscan_count);
    fprintf (fptr, R_BSENT_COUNT ": %lu\n", opt->bsent_count);
    fprintf (fptr, R_IP_OFFSET ": %lu\n", opt->ip_offset);
    fprintf (fptr, R_IP_BLKLEN ": %lu\n", opt->ip_blklen);
    fprintf (fptr, R_IP_POS ": %lu\n", opt->ip_pos);
    fprintf (fptr, R_FLAGS ": %4.4x\n", opt->flags);
    memcpy(&tv, &opt->tv2, sizeof(tv));
    time_diff (&opt->scan_start, &tv);
    fprintf (fptr, R_SCAN_TIME ": %ld\n", (long)tv.tv_sec);
    fprintf (fptr, R_SPF_SIP ": %s\n", int_ntoa (opt->nt.src));
    fprintf (fptr, R_SPF_SMAC ": %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",
	     p[0], p[1], p[2], p[3], p[4], p[5]);
    fprintf (fptr, R_SNARFICMP_C ": %lu\n", opt->snarf.icmp_c);
    fprintf (fptr, R_SNARFCLOSE_C ": %lu\n", opt->snarf.close_c);
    fprintf (fptr, R_SNARFOPEN_C ": %lu\n", opt->snarf.open_c);
    fprintf (fptr, R_SNARFREFUSED_C ": %lu\n", opt->snarf.refused_c);
    if (opt->lnet.device != NULL)
	fprintf (fptr, R_IDEV ": %s\n", opt->lnet.device);
    else
	fprintf (fptr, R_IDEV ": \n");

    if (opt->hostfile != NULL)
	fprintf (fptr, R_HOSTFILE ": %s\n", opt->hostfile);
    else
	fprintf (fptr, R_HOSTFILE ": \n");

    fclose (fptr);

    return (0);
}

int
restore_processtag (char *tag, char *arg)
{
    char *ptr = arg;
    int c = 0;

    if ((arg == NULL) || (tag == NULL))
	return (-1);

    if (!strcmp (R_ARGVLIST, tag))
	if (strlen (arg) > 0)
	{
	    int toggle = 0;
	    while (*ptr != '\0')
		if (*ptr++ == '"')
		    c++;
	    ptr = arg;
	    c = c / 2;
	    if (c <= 0)
		return (-1);	/* this should not happen */
	    if ((opt->argvlist = malloc ((c + 1) * sizeof (char *))) == NULL)
		return (-1);
	    for (toggle = 0; toggle < c + 1; toggle++)
		opt->argvlist[toggle] = NULL;

	    toggle = 0;
	    ptr = arg;
	    c = 0;
	    while (*ptr != '\0')
		if (*ptr++ == '"')
		{
		    *(ptr - 1) = '\0';
		    if (toggle++ == 1)
		    {
			toggle = 0;
			continue;
		    }
		    opt->argvlist[c++] = ptr;
		}

	    /* strings are ready + \0 terminated here */

	    for (toggle = 0; toggle < c; toggle++)
		opt->argvlist[toggle] = strdup (opt->argvlist[toggle]);

	    return (0);
	}

    if (!strcmp (R_MODARG, tag))
	loadinit_mod(arg);
	
    if (!strcmp (R_DELAY, tag))
	opt->delay = atoi (arg);
    if (!strcmp (R_LIMIT, tag))
	opt->limit = atoi (arg);
    if (!strcmp (R_PSCANSTAT, tag))
	opt->pscanstat = atoi (arg);
    if (!strcmp (R_IPSCAN_COUNT, tag))
	opt->ipscan_count = strtoul (arg, NULL, 10);
    if (!strcmp (R_IPTOTSCAN_C, tag))
	opt->iptotscan_count = strtoul (arg, NULL, 10);
    if (!strcmp (R_BSENT_COUNT, tag))
	opt->bsent_count = strtoul (arg, NULL, 10);
    if (!strcmp (R_IP_OFFSET, tag))
	opt->ip_offset = strtoul (arg, NULL, 10);
    if (!strcmp (R_IP_BLKLEN, tag))
	opt->ip_blklen = strtoul (arg, NULL, 10);
    if (!strcmp (R_IP_POS, tag))
	opt->ip_pos = strtoul (arg, NULL, 10);
    if (!strcmp (R_SCAN_TIME, tag))
    {				/* doing the date trick ..we had a scannerdowntime.. */
	gettimeofday (&opt->scan_start, NULL);
	opt->scan_start.tv_sec =
	    opt->scan_start.tv_sec - strtoul (arg, NULL, 10);
    }
    if (!strcmp (R_SPF_SIP, tag))
	opt->nt.src = inet_addr (arg);
    if (!strcmp (R_SPF_SMAC, tag))
    {
	unsigned short int sp[6];
	sscanf (arg, "%hx:%hx:%hx:%hx:%hx:%hx", &sp[0], &sp[1], &sp[2],
		&sp[3], &sp[4], &sp[5]);
	for (c = 0; c < 6; c++)
	    opt->spf_smac[c] = (u_char) sp[c];

    }
    if (!strcmp (R_FLAGS, tag))
    {
	sscanf (arg, "%hx", &opt->flags);
	opt->flags &= ~OPT_ABRT;
	opt->flags &= ~OPT_REST;
    }
    if (!strcmp (R_SNARFICMP_C, tag))
	opt->snarf.icmp_c = strtoul (arg, NULL, 10);
    if (!strcmp (R_SNARFCLOSE_C, tag))
	opt->snarf.close_c = strtoul (arg, NULL, 10);
    if (!strcmp (R_SNARFOPEN_C, tag))
	opt->snarf.open_c = strtoul (arg, NULL, 10);
    if (!strcmp (R_SNARFREFUSED_C, tag))
	opt->snarf.refused_c = strtoul (arg, NULL, 10);
    if (!strcmp (R_IDEV, tag))
	if (strlen (arg) > 0)
	    opt->lnet.device = strdup (arg);
    if (!strcmp (R_HOSTFILE, tag))
	if (strlen (arg) > 0)
	    opt->hostfile = strdup (arg);

    return (0);
}


/*
 * read restore-file
 * return 0 on success, -1 on failure
 * sscanf is exploitable. have fun. What kind of stupid admin
 * who set a +s on this programm. harhar
 */
int
read_restore (char *filename)
{
    FILE *fptr;
    char buf[1024];
    char tag[1024], arg[1024];

    if (opt->flags & OPT_VERB)
	fprintf (stderr, "Reading restore file '%s'.\n", filename);

    if ((fptr = fopen (filename, "rb")) == NULL)
    {
	printf ("OPEN FAILED\n");
	return (-1);
    }

    while (fgets (buf, sizeof (buf), fptr) != NULL)
    {
	if (strchr (buf, '#') != NULL)
	    continue;

	tag[0] = arg[0] = '\0';
	sscanf (buf, "%[^: ]%*[: \t]%[^#\n]%*[\n]", tag, arg);

	if (restore_processtag (tag, arg) == -1)
	{
	    fprintf (stderr, "error while processing restore file with '%s:%s' \n ", tag, arg);
             exit (-1);
        }

     }

     fclose (fptr);
     return (0);
}
