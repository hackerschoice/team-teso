/*
 * SimpleNetworkManagementProtocol module for bscan.
 * RFC 1157
 * <buggy/lame implementation>
 *
 * ###fixme todo: port to sparc
 */

#include <bscan/bscan.h>
#include <bscan/module.h>
#include <bscan/system.h>
#include <stdio.h>


#ifndef MOD_NAME
#define MOD_NAME	"mod_snmp"
#endif

#define SNMP_DFLT_REQOBJ	"1.3.6.1.2.1.1"

#define MAX_VALSTRLEN	512

#define MOPT_NOOBJ	0x01
#define	MOPT_STRIP	0x02

#define SNMP_GET	0xa0
#define SNMP_GET_NEXT	0xa1
#define SNMP_SET	0xa3
#define ASN_SUBCAT	0x30	/* BER encoding, sub-categorie */

#ifndef ASN_INTEGER
#define ASN_INTEGER         ((u_char)0x02)
#endif
#define ASN_INTEGERSTR		"INTEGER"
#ifndef ASN_BIT_STR
#define ASN_BIT_STR         ((u_char)0x03)
#endif
#define ASN_BIT_STRSTR		"BITSTRING"
#ifndef ASN_OCTET_STR
#define ASN_OCTET_STR       ((u_char)0x04)
#endif
#define ASN_OCTET_STRSTR	"STRING"
#ifndef ASN_NULL
#define ASN_NULL            ((u_char)0x05)
#endif
#define ASN_NULLSTR		"NULL"
#ifndef ASN_OBJECT_ID
#define ASN_OBJECT_ID       ((u_char)0x06)
#endif
#define ASN_OBJECT_IDSTR	"OBJ"
#ifndef ASN_APPLICATION
#define ASN_APPLICATION     ((u_char)0x40)
#endif
#ifndef ASN_LONG_LEN
#define ASN_LONG_LEN         ((u_char)0x80)
#endif
#define ASN_APPLICATIONSTR	"APPLICATION"
#ifndef ASN_IPADDRESS
#define ASN_IPADDRESS   (ASN_APPLICATION | 0)
#endif
#define ASN_IPADDRESSSTR	"IPADDR"
#ifndef ASN_UNSIGNED
#define ASN_UNSIGNED    (ASN_APPLICATION | 2)
#endif
#define ASN_UNSIGNEDSTR		ASN_INTEGERSTR
#ifndef ASN_TIMETICKS
#define ASN_TIMETICKS   (ASN_APPLICATION | 3)
#endif
#define ASN_TIMETICKSSTR	"TIMETICKS"
#ifndef ASN_COUNTER
#define ASN_COUNTER (ASN_APPLICATION | 1)
#endif
#define ASN_COUNTERSTR		"COUNTER"

#define SNMP_ERR_WRONGTYPE              (7)
#define SNMP_ERR_WRONGLENGTH            (8)
#define SNMP_ERR_WRONGENCODING          (9)
#define SNMP_ERR_WRONGVALUE             (10)
#define SNMP_ERR_NOCREATION             (11)
#define SNMP_ERR_INCONSISTENTVALUE      (12)
#define SNMP_ERR_RESOURCEUNAVAILABLE    (13)
#define SNMP_ERR_COMMITFAILED           (14)
#define SNMP_ERR_UNDOFAILED             (15)
#define SNMP_ERR_AUTHORIZATIONERROR     (16)
#define SNMP_ERR_NOTWRITABLE            (17)

char *snmp_error[] = {
	"NO ERROR",
	"TOO BIG",
	"NO SUCH NAME",
	"BAD VALUE",
	"READONLY",
	"GENERELL ERROR",
	"NO ACCESS",
	"WRONG TYPE",
	"WRONG LENGTH",
	"WRONG ENCODING",
	"WRONG VALUE",
	"NO CREATION",
	"INCONSISTENT VALUE",
	"RESOURCE UNAVAILABLE",
	"COMMIT FAILED",
	"UNDO FAILED",
	"AUTORISATION ERROR",
	"NOT WRITEABLE",
	"INCONSISTENT NAME" };

#define MAX_SNMP_ERR    18



#define ADD_DATA(ptr, in, len, totlen) memcpy(ptr, in, len);\
	*totlen = *totlen + len;

#define min(a,b)       ((a)<(b)?(a):(b))


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

struct _pdu
{
    u_char	*varbuf;
    int		varlen;
};

struct _mopt
{
    char 	*community;
    u_char	flags;
    u_char 	snmptor;	/* type of request */
    struct _pdu pdu;
} static mopt;

struct _pdunfo
{
    u_char *community;
    u_char *pdu_type;
    u_char *error_status;
    u_char *error_idx;
} static pdunfo;


/*
 * static functions prototypes
 */
static int mdo_opt(int, char **, struct _opt *);
static void init_vars(struct _opt *);
static int process_rcv(struct _opt *);
static int add_snmp (u_char *, int *);
static int add_snmpreq (u_char *, int *, u_char, u_char *, struct _pdu *);
static int add_snmp_var(struct _pdu *, u_char *);
static int build_snmp_objreq(u_char *, u_char *,u_char *, u_char, u_char *);
static int str2asnv(u_char *, u_char, u_char *, u_char *);
static int str2objid(u_char *, u_char *, u_char *);


/*
 * print out usage informations
 */
void
musage()
{
    printf ("\n"MOD_NAME"\n");
    printf ("snmp module\n");
    printf (" -p <port>, destination port, default 161\n");
    printf (" -o <port>, source port, default 53\n");
    printf (" -r <request[:type[:value]]>, default '1.3.6.1.2.1.1 (system)'\n");
    printf (" -c <community name>, default 'public'\n");
    printf (" -g <requesttype>, (get|getnext|set), default 'getnext'\n");
    printf (" -s strip unprintable characters from STRING types, and output as text\n");
    printf (" -q dont print out OBJ-types\n");
    printf ("\n");
    printf ("type: i: INTEGER, s: STRING, n: NULLOBJ, o: OBJID\n");
    printf ("      t: TIMETICKS, a: IPADDRESS, b: BITSTRING, c: COUNTER\n"); 
    printf ("\n");
    printf ("you can request multiple objects with one request:\n");
    printf ("-g get -r 1.3.6.1.2.1.1.1.0 -r 1.3.6.1.2.1.1.4.0 -r 1.3.6.1.2.1.1.5.0\n");
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
 * RMOD_ERROR: failed to create packet.
 * RMOD_ABRT: critical failure, abort!
 */
int
callmdl(int entry, struct _opt *opt)
{
#ifdef DEBUG
	printf("MODULE CALLMDL\n");
#endif
	if (entry == MOD_FIRSTPKG)
	{
 	    add_snmp(opt->packet+ ETH_SIZE + IP_SIZE + UDP_SIZE, &opt->pkg_len);
            add_udphdr (opt->packet+ ETH_SIZE+ IP_SIZE, &opt->nt, opt->pkg_len);
	    add_iphdr (opt->packet + ETH_SIZE, IPPROTO_UDP, &opt->nt, opt->pkg_len + UDP_SIZE);
	    opt->pkg_len += UDP_SIZE + IP_SIZE;

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
    opt->nt.sport = htons(32770);
    opt->nt.dport = htons(161);
    mopt.flags = 0;
    mopt.community = "public";
    mopt.snmptor = SNMP_GET_NEXT;
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

    while ((c = getopt (argc, argv, "qsg:c:r:p:o:")) != -1)
    {
	switch (c)
	{
	case 'q':
	   mopt.flags |= MOPT_NOOBJ;
	   break;
	case 's':
	   mopt.flags |= MOPT_STRIP;
	   break;
	case 'p':
	   opt->nt.dport = htons(atoi(optarg));	
	   break;
	case 'o':
	   opt->nt.sport = htons(atoi(optarg));	
	   break;
	case 'r':
	   add_snmp_var(&mopt.pdu, optarg);
	   break;
	case 'c':
	   mopt.community = optarg;
   	   break;
        case 'g':
	   if (strcasecmp (optarg, "get") == 0)
		mopt.snmptor = SNMP_GET;
	   else if (strcasecmp (optarg, "getnext") == 0)
		mopt.snmptor = SNMP_GET_NEXT;
	   else if (strcasecmp (optarg, "set") == 0)
		mopt.snmptor = SNMP_SET;
	   else
		return (-1);
	   break;
        case ':':
	    fprintf(stderr, "missing parameter\n");
	    return(-1);
        default:
	    return(-1);
	}
    }

    if (mopt.pdu.varbuf == NULL)
	add_snmp_var(&mopt.pdu, SNMP_DFLT_REQOBJ);
	
    return(0);
}


static u_char
strtoasn_vtype(int src)
{

    src = tolower(src);

    switch (src)
    {
	case 'i':
	    return(ASN_INTEGER);
	case 's':
	    return(ASN_OCTET_STR);
	case 'n':
	    return(ASN_NULL);
	case 'o':
	    return(ASN_OBJECT_ID);
	case 't':
	    return(ASN_TIMETICKS);
	case 'b':
	    return(ASN_BIT_STR);
	case 'a':
	    return(ASN_IPADDRESS);
	case 'u':
	    return(ASN_UNSIGNED);
	case 'c':
	    return(ASN_COUNTER);
	default:
	    fprintf(stderr, "WARNING: unsupported value-type.\n");
	    return(src);
    }
    
    return(ASN_NULL);
}

/*
 * add variable to our variable-queue
 * input: <objid-dodded notation>:<value type>:<value>-format
 * return 0 on success, !=0 on parse error etc
 */
static int
add_snmp_var(struct _pdu *pdu, u_char *src)
{
    u_char *request;
    u_char vtype = 5;
    u_char *value = NULL;
    u_char *ptr = NULL;
    u_char reqlen=0;

    if (pdu->varbuf == NULL)
    {
	pdu->varbuf = calloc(1, 1024);
	pdu->varlen = 0;
    }

    request = src;

    if ( (ptr = strchr(src, ':')) != NULL)
    	*ptr++ = '\0';

    src = ptr;
    if (ptr != NULL)
    {
        if ( (ptr = strchr(src, ':')) != NULL)
	{
	    *ptr++ = '\0';
	    if (strlen(ptr) > 0)
	        value = ptr;
	}
        vtype = strtoasn_vtype(*src);
    }

    if (build_snmp_objreq(pdu->varbuf + pdu->varlen, &reqlen, request, vtype, value) != 0)
     {
	fprintf(stderr, "WARNING: error while parsing reqOBJ\n");
        return(-1);
     }

    pdu->varlen += reqlen;

    return(0);
}

/*
 * convert OBJ-ID and build the snmp-request packet
 * save the work and reuse [better performance, the snmp
 * packet is always the same].
 * return 0 on success
 */
static int
add_snmp(u_char *ptr, int *lenptr)
{
    static u_char *buf = NULL;
    static int buflen;

    if (buf != NULL)	/* fastmode, use old copy of previous build snmppkg */
    {
	*lenptr = buflen;
        memcpy(ptr, buf, buflen);
        return(0);
    }

    if (buf == NULL)
	buf = malloc(1024);

    add_snmpreq (ptr, lenptr, mopt.snmptor, mopt.community, &mopt.pdu); 

    memcpy(buf, ptr, *lenptr);	/* for later reuse */
    buflen = *lenptr;

    return(0);
}

/*
 * convert snmp obj in dotted-notation, 0-terminated string to obj-id in asn.1
 */
static int
str2objid(u_char *dst, u_char *retlen, u_char *src)
{
    u_char *dotptr;
    u_char len;

    if (strncmp(src, "1.3.6.1.", 8) != 0)
        return(-1);     /* snmp only , iso.org.dot.internet.* */

    src += 8;  /* we know the first 8 bytes. */

    memcpy(dst, "\x2b\x06\x01", 3);     /* yepp, we know this. "1.3.6.1" */
    dst += 3;
    dotptr = src;
    len = 3;    /* 2b-06-01 */
    while ( (dotptr = strchr (src, '.')) != NULL)
    {
        *dotptr = '\0';
        *dst++ = (u_char)atoi(src);
        src = ++dotptr;
        len++;
    }
    if (strlen(src) > 0)
    {
        *dst++ = (u_char)atoi(src);
        len++;
    }

    *retlen = len;
    return(0);
}


/*
 * convert input to ASN.1 BER encodet <obj-id><value>
 * dst: guess what.
 * ptr: snmp obj in dotted-notation (1.3.6.1.2.1.1....), 0-terminated string
 * tov: type of value, ASN.1 encodet (int, 8octet string, ...)
 * value: the value (string, 0-terminated)
 * return: 0 on success
 */
static int 
build_snmp_objreq(u_char *dst, u_char *retlen, u_char *src, u_char tov, 
                  u_char *value)
{
    u_char *srcw;
    u_char vlen = 0;
    u_char *sublen;
    u_char *subsublen;
    u_char *subvlen;
    u_char len;

    srcw = alloca(strlen(src)+1);
    memcpy(srcw, src, strlen(src)+1);
    if (strlen(srcw) <= 4)
	return(-1);
    
    *dst++ = ASN_SUBCAT;	
    sublen = dst++;	/* we set the length later coz we dont know it yet */

    *dst++ = 0x06;	/* OBJ-ID */
    subsublen = dst++;  /* and this also not */

    if (str2objid(dst, &len, srcw) != 0)
	return(-1);

    *subsublen = len;	/* length of obj */
    dst += len;

    *dst++ = tov;	/* type of value */
    subvlen = dst++;	/* we set this later..we dont know the length yet */
    str2asnv(value, tov, dst, &vlen);

    *subvlen = vlen;	/* length of value */

    *sublen = len + vlen + 4;	/* length of <obj-id><tov:value> */

    *retlen = len + vlen + 6; 
    return(0);
}


/*
 * convert 0-terminated string value to asn encodet value
 * return 0 on success
 * on return the length of rvalue < value.
 * input: value [0 terminated string]
 *        tov [asn]-type of value
 * output: rvalue [non 0-terminated string with asn-value]
 *         vlen [length of rvalue]
 * return 0 on success
 * attention: we use full integers (length=4, not reduced in length
 * to the minimum size). the snmp-lib reduces the length of an
 * integer to the minimum size...but this is not a must
 */
static int
str2asnv(u_char *value, u_char tov, u_char *rvalue, u_char *vlen)
{
    unsigned long int ltmp;

    if (rvalue == NULL)
	return(0);		/* yes, NULL is allowed */
    if ((rvalue != NULL) && (vlen == NULL))
	return(-1);

    switch(tov)
    {
	case ASN_INTEGER:
            ltmp = htonl(strtol(value, NULL, 10));
            memcpy(rvalue, &ltmp, sizeof(ltmp));
	    *vlen = sizeof(ltmp);
	    break;
	case ASN_UNSIGNED:
	case ASN_COUNTER:
	case ASN_TIMETICKS:
	    ltmp = htonl(strtoul(value, NULL, 10));
	    memcpy(rvalue, &ltmp, sizeof(ltmp));
	    *vlen = (sizeof(ltmp));
	    break;
  	case ASN_IPADDRESS:
	    ltmp = inet_addr(value);
            memcpy(rvalue, &ltmp, sizeof(ltmp));
	    *vlen = sizeof(ltmp);
	    break;
	case ASN_OBJECT_ID:
            str2objid(rvalue, vlen, value);
	    break;
	case ASN_OCTET_STR:
	    memcpy(rvalue, value, strlen(value));
	    *vlen = strlen(value);
	    break;
	case ASN_NULL:
	    *vlen = 0;
	    break;
	default:
	    *vlen = 0;
	    fprintf(stderr, "WARNING, unsupported value type !\n");
    }

    return(0);
}

/*
 * add snmp request
 * build the entire SNMP packet [version, community, pdu, id, error, idx, ..]
 * req: objs + values [BER encodet, already with header and \x30 sub start]
 * reqlen: len of entire req [objs + values]
 * tor: type of request [get, getnext, set]
 */
static int
add_snmpreq (u_char *pkt, int *len, u_char tor, u_char *community, struct _pdu *pdu)
{
    int le = 0;

    *(pkt + le++) = ASN_SUBCAT;
    *(pkt + le++) = (u_char)(pdu->varlen +  strlen(community) + 18);
    ADD_DATA(pkt + le, "\x02\x01\x00\x04" , 4, &le);	/* SNMPv1 + STRINGOBJ*/
    *(pkt + le++) = (u_char)strlen(community);
    ADD_DATA(pkt + le, community, strlen(community), &le);
    *(pkt + le++) = tor;		/* PDU GET-NEXTrequest */
    /* lenof(<req-id> + <err-state> + <err-idx> + <SUB> <obj+values>) */
    *(pkt + le++) = (u_char)(pdu->varlen + 11);
    /* <req-id> + <err-state> + <err-idx> <SUB-OBJ> */
    ADD_DATA(pkt + le, "\x02\x01\x01\x02\x01\00\x02\x01\x00\x30", 10, &le);
    *(pkt + le++) = (u_char)(pdu->varlen); 
    ADD_DATA(pkt + le, pdu->varbuf, pdu->varlen, &le);

    *len = le;
    return(0);
}


/*
 * convert asn encoded obj to string
 * input: string of <type of value><length of value><value>
 * datalen: max len i'm allowed to read from "ptr --> ..."
 * return:
 * prefix is the string representation of the value-type e.g. "OCTET-STRING"..
 *   and '<trunc>' if value got truncated.
 *   is < 64 chars...
 * val: the value (0-terminated string)
 * return 0 on success
 * 1 if truncated (value-length > size of snmp or val to small)
 * -1 on error
 */
static int
asn2str(u_char *ptr, u_char *prefix, u_char *val, unsigned int datalen)
{
    unsigned long int 	len, day, hour, min, sec, msec;
    u_char 		*ptr2;
    u_char 		vlen = *(ptr+1);	/* saved value length */
    u_char 		tov = *ptr;
    unsigned long int 	ltmp;
    int 		i, slen = 0;
    u_char 		buf[128];

    if (vlen > datalen-2)
	len = datalen-2;
    else
	len = vlen;

    *val = '\0';
    *prefix = '\0';

    switch(tov)
    {
	case ASN_IPADDRESS:
	   if (len > sizeof(ltmp))
		len = sizeof(ltmp);

           ptr2 = (u_char *)&ltmp;
	   memcpy(ptr2 + sizeof(ltmp) - len, ptr+2, len);
	   sprintf(val, "%s", int_ntoa(ltmp));
	   strcpy(prefix, ASN_IPADDRESSSTR);
	   break;
	case ASN_NULL:
	   strcpy(prefix, ASN_NULLSTR);
	   break;
	case ASN_TIMETICKS:
	   if (len > sizeof(ltmp))
		len = sizeof(ltmp);

	    ltmp = 0;
	    ptr2 = (u_char *)&ltmp;
	    memcpy(ptr2 + sizeof(ltmp) - len, ptr+2, len);
	    ltmp = ntohl(ltmp);
	    day = ltmp / 8640000;
	    hour = (ltmp % 8640000) / 360000;
	    min = (ltmp % 360000) / 6000;
            sec = (ltmp % 6000) / 100;
	    msec = (ltmp % 100);
	    sprintf(val, "(%lu) %d days, %2.2d:%2.2d:%2.2d.%d", ltmp, 
			(int)day, (int)hour, (int)min, (int)sec, (int)msec);
	    if (tov == ASN_TIMETICKS)
		strcpy(prefix, ASN_TIMETICKSSTR);
	    break;
	case ASN_INTEGER:
	case ASN_UNSIGNED:
	case ASN_COUNTER:
	    ltmp = 0;
	    if (len > sizeof(ltmp))
		len = sizeof(ltmp);

	    ptr2 = (u_char *)&ltmp;
	    memcpy(ptr2 + sizeof(ltmp) - len, ptr+2, len);

	    if (tov == ASN_INTEGER)
		sprintf(val, "%lu", (unsigned long int)ntohl(ltmp));
	    else
            	sprintf(val, "%ld", (long int)ntohl(ltmp));

            if (tov == ASN_INTEGER)
		strcpy(prefix, ASN_INTEGERSTR);
	    if (tov == ASN_UNSIGNED)
		strcpy(prefix, ASN_UNSIGNEDSTR);
 	    if (tov == ASN_COUNTER)
		strcpy(prefix, ASN_COUNTERSTR);
	    break;
	case ASN_OCTET_STR:
	    if (isprintdata(ptr+2, len))
	    {
		if (len > MAX_VALSTRLEN-1)
		    len = MAX_VALSTRLEN-1;
		memcpy(val, ptr+2, len);
		val[len] = '\0';
	    } else if ((mopt.flags & MOPT_STRIP) == MOPT_STRIP) {
		dat2strip(val, MAX_VALSTRLEN, ptr+2, len);
	    } else {
		dat2hexstr(val, MAX_VALSTRLEN, ptr+2, len);
	    }

	    strcpy(prefix, ASN_OCTET_STRSTR);
	    break;
	case ASN_OBJECT_ID:
	    i = 0;
	    slen = 0;
	    while(i < len)
	    {
	  	if (*(ptr+2+i) == 0x2b)
		    strcpy(buf, "1.3.");	/* substituate shorts */
	  	else
		    snprintf(buf, sizeof(buf), "%d.", *(ptr+2+i));

		buf[sizeof(buf)-1] = '\0';
	  	slen = strlen(val) + strlen(buf);

		if (slen < MAX_VALSTRLEN -1)
		    strcat(val, buf);
		else
		    break;

	 	i++;
	    }
	    val[slen-1] = '\0';		/* remove last '.' */
	    strcpy(prefix, ASN_OBJECT_IDSTR);
	    break;
	default:
	    dat2hexstr(val, MAX_VALSTRLEN, ptr+2, len);
	    break;
    }

    if (*prefix == '\0')
	strcpy(prefix, "UNKNOWN");

    if (vlen > len)
    {
	strcat(prefix, "<trunc>");
	return(1);
    }

    return(0);
}

/*
 * return TypeOfValue and let next point to the next asn encodet obj
 * ptr: pointer to asn.1 encodet obj
 * len: returns the length of the OLD value + suffix [length we skipped]
 * next: returns a pointer to the next obj.
 */
static u_char 
asn_getnext(u_char *ptr, u_char *len, u_char **next)
{
    u_char 	vlen = *(ptr+1);

    if (*ptr == ASN_SUBCAT)
    {
	if (vlen & ASN_LONG_LEN)
	    vlen = vlen & ~ASN_LONG_LEN;
	else
	    vlen = 0;
     }

    *next = ptr + vlen + 2; 

    *len = vlen + 2;
    return(**next);
}

#define RETURN_ILLLEN(x,y,r)  if (x >= y) return(r);

/*
 * handle incoming snmp answers, answer with 'next' if not last record
 */
static int
process_rcv(struct _opt *opt)
{
    struct udphdr *udp;
    u_char *ptr;
    int len;
    int snmplen;
    uint iphdr_len = 0;
    u_char objlen;
    u_char buf[MAX_VALSTRLEN];
    u_char prefix[32];
    u_char buf2[MAX_VALSTRLEN + 32];
    u_char asnprefix[128];
    u_char c;

    if (ip->ip_p != IPPROTO_UDP)
	return(0);

    iphdr_len = IP_SIZE + ip_options;
    if (plen < dlt_len + iphdr_len + sizeof(*udp))
	return(-1);	/* invalid size */

    udp = (struct udphdr *) (align_buf + iphdr_len);
    ptr = (u_char *) (align_buf + iphdr_len + sizeof(*udp));
    snmplen = plen - dlt_len - iphdr_len - sizeof(*udp);
    len = 0;
  
    /*
     * we dont check the value of the ASN_SUBCAT-length coz many buggy
     * hosts out there return a wrong length [0xff, 0x80, ...]
     */

    ptr += 2; len += 3;	/* pointing on the 3rd element */
    RETURN_ILLLEN(len, snmplen, 0);

    asn_getnext(ptr, &objlen, &ptr); 	/* skip version, get community */
    len += objlen;
    RETURN_ILLLEN(len, snmplen, 0);
    pdunfo.community = ptr;
    
    asn_getnext(ptr, &objlen, &ptr);	/* skip community, get pdu */
    len += objlen;
    RETURN_ILLLEN(len, snmplen, 0);
    pdunfo.pdu_type = ptr;
    ptr += 2;
    len += 2;				/* skip pdu, get reqid */
    RETURN_ILLLEN(len, snmplen, 0);

    asn_getnext(ptr, &objlen, &ptr);	/* skip reqid, get errorstatus */
    len += objlen;
    RETURN_ILLLEN(len, snmplen, 0);
    pdunfo.error_status = ptr;

    asn_getnext(ptr, &objlen, &ptr);	/* skip errorstatus, get erroridx */
    len += objlen;
    RETURN_ILLLEN(len, snmplen, 0);
    pdunfo.error_idx = ptr;

    asn_getnext(ptr, &objlen, &ptr);	/* skip erroridx, get */
    len += objlen;
    RETURN_ILLLEN(len, snmplen, 0);

    asn_getnext(ptr, &objlen, &ptr);	/* we reached the SUB section */
    len += objlen;
    RETURN_ILLLEN(len, snmplen, 0);

    snprintf(prefix, sizeof(prefix) - 1, "%s:%d ", int_ntoa(ip->ip_src),
				ntohs(udp->uh_sport));

    c = *(pdunfo.error_status+2);
    if (c != 0)
    {
	if (c < MAX_SNMP_ERR)
	{
	    printf("%s%s (%d)\n", prefix, snmp_error[c],
			*(pdunfo.error_idx+2));
	} else {
	    printf("%s UNKNOWN ERROR\n", prefix);
	}
    }

    while (1)
    {
	asn_getnext(ptr, &objlen, &ptr);
	if (objlen == 0)
	    return(0);

	len += objlen;
	RETURN_ILLLEN(len, snmplen, 0);
	if (*ptr == ASN_SUBCAT)
	    continue;

        if ((mopt.flags & MOPT_NOOBJ) && (*ptr == ASN_OBJECT_ID))
	   continue;

        asn2str(ptr, asnprefix, buf, snmplen - len + 1);
	snprintf(buf2, sizeof(buf2)-1, "%s %s", asnprefix, buf);
	buf2[sizeof(buf2)-1] = '\0';
	save_write(stdout, prefix, buf2, strlen(buf2));
    }

    return(0);
   
}


