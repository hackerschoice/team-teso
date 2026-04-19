/* zodiac - advanced dns spoofer
 *
 * by scut / teso
 *
 * dns tool routines
 */

#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <libnet.h>
#include "common.h"
#include "dns.h"
#include "dns-tools.h"
#include "dnsq.h"
#include "dns-build.h"
#include "dns-spoof.h"
#include "dnsq.h"
#include "network.h"
#include "output.h"
#include "packet.h"
#include "zodiac.h"


#define DT_SECT_AN	0x1
#define DT_SECT_NS	0x2
#define DT_SECT_AR	0x3


/* keep local functions private
 */
static void	dt_process_pkt (dt_answer *ans, dq_packet *pkt, u_short type);
static		dt_section *dt_choose_sect(dt_answer *ans, int sect);
static void 	dt_answer_add_A (dt_answer *ans, char *name, struct in_addr ip,
	u_short type, int sect);
static void	dt_answer_add_normal (dt_answer *ans, char *name, char *label,
	u_short type, int sect);


static rrec	*dt_search_sect (dt_section *sect, u_short type, char *name);

/* Access with DT_ANSWER_* defines.
 */
char *dterrlist[] = {	"Success",
			"Response Timed Out",
			"Nameserver returned error",
			"Error resolving nameserver",
			"Unknown type",
			"Filter error"};


/* dt_ns_get_auth
 *
 * retrieve a list of authority for a domain, from a particular nameserver
 *
 * return an allocated, null-terminated array of 'struct in_addr' on
 *   success
 * return NULL on reror
 *   put error in 'int *err' if err != NULL
 */

struct in_addr *
dt_ns_get_auth (char *ns_query, char *domain, int *err)
{
	struct in_addr	*ns = NULL;
	int		ns_cnt = 0,
			i;
	dt_answer	*ans;
	dt_section	*sect;

	if (err) *err = DT_ANSWER_OK;

	ans = dt_query_bind (ns_query, T_NS, C_IN, domain);
	if (ans->answer != DT_ANSWER_OK) {
		if (err != NULL) *err = ans->answer;
		dt_answer_free (ans);

		return NULL;
	}

	sect = &ans->an_section;

	for (i = 0; i < sect->rrec_cnt; i++) {
		rrec		*rrec_ptr,
				*ptr;
		struct in_addr	tmp;

		rrec_ptr = &sect->rrecords[i];
		if (rrec_ptr->type != T_NS)
			continue;

		/* try and find the relevant A record in the ar section */
		ptr = dt_search_sect (&ans->ar_section,
			T_A, rrec_ptr->data.label);

		if (ptr == NULL) {
			/* this iz kinda ugly */
			tmp.s_addr = net_resolve (rrec_ptr->data.label);

			if (tmp.s_addr == htonl(INADDR_ANY)) /* hmm */
				continue;
		} else {
			tmp.s_addr = ptr->data.ip.s_addr;
		}

		++ns_cnt;
		ns = (struct in_addr *) 
			xrealloc (ns, sizeof(struct in_addr) * ns_cnt);
		ns[ns_cnt - 1].s_addr = tmp.s_addr;
	}
	dt_answer_free (ans);

	if (ns_cnt == 0)
		return (NULL);

	/* null terminate it */
	ns = (struct in_addr *) 
		xrealloc (ns, sizeof(struct in_addr) * ++ns_cnt);
	ns[ns_cnt - 1].s_addr = 0;

	return (ns);
}

/*
 * Search for a resource record in a particular section.
 * 
 * return a pointer to the relevant resource record on success.
 * return NULL on error.
 * -smiler
 */

static rrec
*dt_search_sect (dt_section *sect, u_short type, char *name)
{
	rrec	*record = NULL;
	int	i;

	for (i = 0; i < sect->rrec_cnt; i++) {
		if (sect->rrecords[i].type != type)
			continue;

		if (strcasecmp(name, sect->rrecords[i].name))
			continue;

		record = &sect->rrecords[i];
		break; /* so the function returns */
	}
	return (record);
}

/* dt_bind_version
 *
 * try to retrieve a version number from a dns server with the host name
 * `host' which is running the bind named.
 *
 * this would be easily done using a fixed buffer and an udp socket, but
 * we want to do it with style, oh yeah =) (in other words i didn't write
 * this routines to lever me down to udp sockets again ;)
 *
 * return an allocated string with the server response
 * return an allocated string "unknown" if the version couldn't be retrieved
 * return NULL on failure (no response)
 *
 * changed to use dt_query_bind().... -smiler
 */

char *
dt_bind_version (char *host)
{
	dt_answer	*ans;
	char		tmp[256];

	ans = dt_query_bind (host, T_TXT, C_CHAOS, "VERSION.BIND.");
	if (ans->answer != DT_ANSWER_OK) {
		dt_answer_free (ans);

		return (NULL);
	}

	/* copy the label into a temporary buffer, free the answer struct,
	 * /then/ allocate space for the string. hopefully this will avoid
	 * fragmentation in the heap space...
	 */

	tmp[255] = 0;
	strncpy (tmp, ans->an_section.rrecords[0].data.label, sizeof (tmp) - 1);
	dt_answer_free (ans);

	return (xstrdup (tmp));	
}


/* dt_query_bind
 *
 * generic query function. query a remote nameserver `serv' for a query
 * `query' of the type `type' and class `class'.
 *
 * return a pointer to a generic answer structure
 *   on failure ans->answer will be set appropiatly
 *
 * -smiler
 */

dt_answer *
dt_query_bind (char *serv, u_short type, u_short class, char *query)
{
	extern struct in_addr	localip;
	char			tmp[20],
				localip_str[20];
	dns_pdata		*packet;
	dq_packet		*catch;
	int			desc,
				cnt;
	u_short			sport,
				dns_id;
	struct in_addr 		servaddr;
	struct timeval		tv;
	dt_answer		*ans = xcalloc (1, sizeof (dt_answer));

	switch (type) {
		case T_A:
		case T_PTR:
		case T_NS:
		case T_TXT:
			break;
		default:
			ans->answer = DT_ANSWER_UNKNOWNTYPE;
			return (ans);
	}

	servaddr.s_addr = net_resolve (serv);
	if (servaddr.s_addr == htonl (INADDR_ANY)) {
		ans->answer = DT_ANSWER_RESOLVE;

		return (ans);
	}

	sport = (libnet_get_prand (PRu16) % (65534 - 1024)) + 1025;
	dns_id = libnet_get_prand (PRu16);

	desc = dq_filter_install (
		servaddr,
		localip,
		53,
		sport,
		1, dns_id, dns_id,
		NULL);
	
	if (desc == -1) {
		ans->answer = DT_ANSWER_FILTERERR;

		return (ans);
	}

	packet = dns_build_new ();
	dns_build_q (packet, query, type, class);

	net_printip (&servaddr, tmp, sizeof(tmp) - 1);
	net_printip (&localip, localip_str, sizeof(localip_str) - 1);
	dns_packet_send (localip_str, tmp, sport, 53,
			dns_id, DF_RD, 1, 0, 0, 0, packet, 0);
	dns_build_destroy (packet);

	tv.tv_sec = 10;
	tv.tv_usec = 0;

	cnt = dq_filter_wait (desc, &tv);
	if (cnt == 0) {
		dq_filter_uninstall (desc);
		ans->answer = DT_ANSWER_TIMEOUT;

		return (ans);
	}

	catch = dq_p_get (desc);
	dq_filter_uninstall (desc);
	if (catch == NULL) {
		ans->answer = DT_ANSWER_FILTERERR;

		return (ans);
	}

	/* jump into helper function now :/ */
	dt_process_pkt (ans, catch, type);
	dq_p_free (catch);

	return (ans);
}


/* dt_process_pkt
 *
 * helper function, parse the packet (a well known childrens party game).
 *
 * return in any case
 *
 * -smiler
 */

static void
dt_process_pkt (dt_answer *ans, dq_packet *pkt, u_short type)
{
	u_short		qdcount,
			ancount,
			nscount,
			arcount;
	int		i,
			sect;
	unsigned char 	*ptr,
			*dns_start;

	ptr = pkt->packet;
	ptr += (((ip_hdr *) ptr)->ip_hl) << 2;
	ptr += UDP_H;
	dns_start = ptr;

	qdcount = ntohs (((HEADER *)ptr)->qdcount);
	ancount = ntohs (((HEADER *)ptr)->ancount);
	nscount = ntohs (((HEADER *)ptr)->nscount);
	arcount = ntohs (((HEADER *)ptr)->arcount);

	if (ancount == 0) {
		ans->answer = DT_ANSWER_ERR;
		return;
	}

	/* this should initialize the sections */
	memset (&ans->an_section, '\0', sizeof (dt_section));
	memset (&ans->ns_section, '\0', sizeof (dt_section));
	memset (&ans->ar_section, '\0', sizeof (dt_section));

	ptr += sizeof (HEADER);

	/* skip question section */
	while (qdcount-- > 0) {
		ptr += dns_labellen (ptr);
		ptr += 4;
	}

	sect = DT_SECT_AN;

	for (i = 0; i < (ancount + nscount + arcount); i++) {
		struct in_addr	tmp;
		u_short		rdlength;
		char		label[256],
				label2[256];

		*label = *label2 = '\0';

		if (i == ancount) {
			sect++;
		} else if (i == (ancount + nscount)) {
			sect++;
		}

		dns_dcd_label (dns_start, &ptr, label, sizeof (label) - 1, 5);
		GETSHORT (type, ptr);
		ptr += 6;
		GETSHORT (rdlength, ptr);

		switch (type) {
			case T_A:
				tmp.s_addr = *(u_int32_t *) ptr;
				dt_answer_add_A (ans, label, tmp, type, sect);
				ptr += 4;

				break;
			case T_NS:
			case T_PTR:
			case T_TXT: /* RFC1035 SUCKS ASS! */
				dns_dcd_label (dns_start, &ptr, label2, sizeof (label2) - 1, 5);
				dt_answer_add_normal (ans, label, label2, type, sect);

				break;
			default:
				break;
		}
	}

	return;
}


static dt_section *
dt_choose_sect (dt_answer *ans, int sect)
{
	dt_section	*dt_sect = NULL;

	switch (sect) {
		case DT_SECT_AN:
			dt_sect = &ans->an_section;
			break;
		case DT_SECT_NS:
			dt_sect = &ans->ns_section;
			break;
		case DT_SECT_AR:
			dt_sect = &ans->ar_section;
			break;			
	}

	return (dt_sect);
}


static void
dt_answer_add_A (dt_answer *ans, char *name, struct in_addr ip, u_short type, int sect)
{
	int		cnt;
	rrec		*ptr;
	dt_section	*dt_sect;

	dt_sect = dt_choose_sect (ans, sect);

	cnt = ++(dt_sect->rrec_cnt);
	ptr = dt_sect->rrecords;

	ptr = (rrec *) xrealloc (ptr, sizeof (rrec) * cnt);

	ptr[cnt - 1].type = type;
	ptr[cnt - 1].name = xstrdup (name);
	ptr[cnt - 1].data.ip.s_addr = ip.s_addr;
	dt_sect->rrecords = ptr;

	return;
}


static void
dt_section_free (dt_section *dt_sect)
{
	int i;

	for (i = 0; i < dt_sect->rrec_cnt; ++i) {
		rrec *ptr = &dt_sect->rrecords[i];

		free(ptr->name);
		switch (ptr->type) {
			case T_A:
				break;
			case T_PTR:
			case T_NS:
			case T_TXT:
				free (ptr->data.label);
				break;
			default:
				break;
		}
	}

	free (dt_sect->rrecords);

	return;
}


/* dt_answer_free
 *
 * free a generic answer structure.
 *
 * return 0 on error
 * return 1 on success
 */

int 
dt_answer_free (dt_answer *ans)
{
	if (ans == NULL)
		return (0);

	dt_section_free (&ans->an_section);
	dt_section_free (&ans->ns_section);
	dt_section_free (&ans->ar_section);
	free(ans);

	return (1);
}


static void
dt_answer_add_normal (dt_answer *ans, char *name, char *label, u_short type, int sect)
{
	int             cnt;
	rrec            *ptr;
	dt_section      *dt_sect;

	dt_sect = dt_choose_sect (ans, sect);

	cnt = ++(dt_sect->rrec_cnt);
	ptr = dt_sect->rrecords;

	ptr = (rrec *) xrealloc (ptr, sizeof (rrec) * cnt);

	ptr[cnt - 1].type = type;
	ptr[cnt - 1].name = xstrdup (name);
	ptr[cnt - 1].data.label = xstrdup (label);
	dt_sect->rrecords = ptr;	

	return;
}


