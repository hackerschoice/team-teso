/* bscan - garage.c - per IP storage functions
 *
 * by scut / teso
 * by skyper / teso
 *
 * this module implements a per-IP storage method to allow other modules
 * to store state information about hosts (ie for TCP fingerprinting or
 * stateful protocols).
 *
 * 2000/12/31	version 1.0.1 - scut
 *		- added CIDR helper functions
 *		- added mg_cidr_getmask function to convert CIDR/netmask
 *		  notation
 *		- added mg_cidr_maskcount to count max possible hosts in a mask
 *		- added mg_cidr_count function to count hosts in garage that
 *		  match a mask
 *		- added ip based counter to the garage structure, this costs
 *		  only few cycles when working with elements, but repays for
 *		  the mg_count and some of the mg_cidr_* functions
 *		- changed mg_count to take advantage of the garage counter
 *		- added mg_cidr_match function
 *		- workaround for some size-dependant misoptimizations of gcc
 *
 * 2000/12/31	version 1.0.0 - scut
 *		- support for storage, retrieval and max-keep counter
 *		  with automatic deallocation
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bscan/garage.h>


/* memory layout:
 *
 * each per-ip data is stored in a linked list element. the linked list
 * can (theoretically) contain up to 2^16 elements, if the entire IP space
 * is scanned at once.
 *
 * up to 2^16 of this linked lists can exist, hence 2^16*2^16 = 2^32 = whole
 * IPv4 space. to access the correct linked list we calculate a hash value,
 * to directly read from a one dimensional table of linked list root pointers.
 *
 * unsigned long int ip;
 *
 * h = ((ip >> 16) + ip) 0xffff)
 *
 * the linked list indexed by this two hash values is sorted in ascending
 * order by the IP as unsigned long int.
 */

#define	MG_H(ip) ((((ip) >> 16) + (ip)) & 0xffff)


#ifdef DEBUG
unsigned long long int	tackall = 0;
unsigned long long int	tackc = 0;
#endif

#if 0
/* unused code
 */
static unsigned long int
mg_count_slot (ip_list *list);
#endif


/* XXX/FIXME/TODO: shouldn't be here
 */
void *
xcalloc (unsigned int factor, unsigned int size)
{
	void *	foo = calloc (factor, size);

	if (foo == NULL) {
		perror ("xcalloc");

		exit (EXIT_FAILURE);
	}

	return (foo);
}


/* destroy the ip_list element given in `slot'
 */
static void
mg_destroy_slot (garage_hdlr *g, ip_list *slot, void (* cleaner)(ip_list *));


garage_hdlr *
mg_init (char *name, unsigned long int max_hosts_in_list,
	void (* cleaner)(ip_list *))
{
	garage_hdlr *	new = xcalloc (1, sizeof (garage_hdlr));

	new->name = name;
	new->garage = xcalloc (256 * 256, sizeof (ip_list *));
	new->cleaner = cleaner;
	new->ip_count = 0;

	if (max_hosts_in_list == 0) {
		new->timeout_tbl = NULL;
		new->timeout_max = 0;
		new->timeout_idx = 0;
	} else {
		new->timeout_tbl = xcalloc (max_hosts_in_list,
			sizeof (unsigned long int));
		new->timeout_max = max_hosts_in_list;
		new->timeout_idx = 0;
	}

	memset (new->garage, '\x00', 256 * 256 * sizeof (ip_list *));
	if (new->timeout_tbl != NULL)
		memset (new->timeout_tbl, '\x00', max_hosts_in_list *
			sizeof (unsigned long int));

	return (new);
}


void
mg_destroy (garage_hdlr *g, int do_handler)
{
	int	h;


#ifdef DEBUG
	printf ("tackcount = %Lu\n", tackc);
	printf ("tackall = %Lu\n", tackall);
	printf ("tackmedian = %2.3f\n", (float) ((float) tackall / (float) tackc));
#endif

	for (h = 0 ; h < (256 * 256) ; ++h) {
		if (g->garage[h] != NULL) {
			/* the IP list structure for the IP will be free'd
			 * by mg_clean, too, so we don't have to do that
			 * manually
			 */
			mg_destroy_slot (g, g->garage[h], (do_handler == 0) ?
				NULL : g->cleaner);
			g->garage[h] = NULL;
		}
	}

	free (g->garage);
	if (g->timeout_tbl == NULL)
		free (g->timeout_tbl);

	/* g->name is not to be free'd */

	free (g);
}


static void
mg_destroy_slot (garage_hdlr *g, ip_list *slot, void (* cleaner)(ip_list *))
{
	ip_list *	next;

	do {
		next = slot->next;
		mg_clean (g, slot->ip, cleaner);
		slot = next;
	} while (slot != NULL);

	return;
}


void
mg_write (garage_hdlr *g, unsigned long int ip, void *data, size_t data_len,
	int data_free)
{
	ip_list *	il;
	ip_elem *	new = xcalloc (1, sizeof (ip_elem));


	new->next = NULL;
	new->data_free = data_free;
	new->data_len = data_len;
	new->data = data;


	il = g->garage[MG_H (ip)];
	if (il == NULL) {
		il = xcalloc (1, sizeof (ip_list));
		il->next = NULL;
		il->ip = ip;
		il->data = new;

		g->garage[MG_H (ip)] = il;
		g->ip_count += 1;
	} else {
		ip_list **	cw = &g->garage[MG_H (ip)];

		while (il != NULL && ip > il->ip) {
			cw = &il->next;
			il = il->next;
		}

		if (il != NULL && ip == il->ip) {
			new->next = il->data;
			il->data = new;
		} else {
			ip_list *	il_tmp = xcalloc (1, sizeof (ip_list));

			il_tmp->next = il;
			*cw = il_tmp;
			il = il_tmp;

			il->ip = ip;
			il->data = new;

			g->ip_count += 1;
		}
	}

	if (g->timeout_tbl != NULL) {
#ifdef DEBUG
		printf ("tbl = 0x%08lx   tbl_idx = %5lu   tbl_max = %5lu   tbl_count = %8lu\n",
			(unsigned long int) g->timeout_tbl,
			(unsigned long int) g->timeout_idx,
			(unsigned long int) g->timeout_max,
			(unsigned long int) mg_count (g));
		printf ("g->timeout_tbl[g->timeout_idx] = %lu\n", g->timeout_tbl[g->timeout_idx]);
		printf ("condition = %s\n", (g->timeout_tbl[g->timeout_idx] != 0) ? "true" : "false");
#endif

		if (g->timeout_tbl[g->timeout_idx] != 0)
			mg_clean (g, g->timeout_tbl[g->timeout_idx], NULL);

		g->timeout_tbl[g->timeout_idx] = il->ip;
#ifdef DEBUG
		printf ("g->timeout_idx = %5ld   g->timeout_max = %5ld\n\n",
			g->timeout_idx, g->timeout_max);
#endif
		g->timeout_idx = (g->timeout_idx + 1) % g->timeout_max;
	}
}


ip_elem *
mg_read (garage_hdlr *g, unsigned long int ip)
{
#ifdef DEBUG
	int		tackcount = 0;
#endif
	ip_list *	il = g->garage[MG_H (ip)];

	/* no list for this hash value -> no IP stored
	 */
	if (il == NULL)
		return (NULL);

	/* walk the list
	 */
	do {
		if (il->ip == ip)
#ifdef DEBUG
		{
			printf ("tackcount = %d\n", tackcount);
			tackall += tackcount;
			tackc += 1;
#endif
			return (il->data);
#ifdef DEBUG
		} else {
			tackcount += 1;
		}
#endif

		il = il->next;

	} while (il != NULL && il->ip <= ip);

	return (NULL);
}


void
mg_clean (garage_hdlr *g, unsigned long int ip, void (* cleaner)(ip_list *))
{
	ip_elem *	iel;
	ip_elem *	iel_tmp;

	ip_list **	cw = &g->garage[MG_H (ip)];
	ip_list *	il;


	il = *cw;

	/* walk the list
	 */
	while (il != NULL && il->ip < ip) {
		cw = &il->next;
		il = il->next;
	}

	if (il == NULL || il->ip != ip)
		return;

	*cw = il->next;

	/* if a cleaner has been given, or there is a default cleaner in the
	 * garage, then run it
	 */
	if (cleaner != NULL) {
		cleaner (il);
	} else if (g->cleaner != NULL) {
		g->cleaner (il);
	}

	iel = il->data;
	while (iel != NULL) {
		iel_tmp = iel;
		if (iel->data_free)
			free (iel->data);

		iel = iel->next;
		free (iel_tmp);
	}

	g->ip_count -= 1;

	free (il);

	return;
}


void
mg_show (garage_hdlr *g)
{
	int	h1, h2;
	int	count;

	char	display[] = ".123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

	printf ("=== garage = %s === elements in garage = %lu\n", g->name, mg_count (g));
	printf ("0_________0_________0_________0_________0_________0_________0_________\n");

	for (h1 = 0 ; h1 < 256 ; ++h1) {
		count = 0;
		for (h2 = 0 ; h2 < 256 ; ++h2) {
			if (g->garage[h1 * 256 + h2] != NULL)
				count += 1;
		}

		printf ("%c", count >= (sizeof (display) - 1) ? '>' : display[count]);
		if ((h1 + 1) % 70 == 0) {
			printf ("\n");
			printf ("0_________0_________0_________0_________0_________0_________0_________\n");
		}
	}
	printf ("\n");

}


unsigned long int
mg_count (garage_hdlr *g)
{
	return (g->ip_count);
}


#if 0
/* unused code
 */
static unsigned long int
mg_count_slot (ip_list *list)
{
	unsigned long int	count = 0;

	do {
		count += 1;
		list = list->next;
	} while (list != NULL);

	return (count);
}
#endif


int
mg_ip_isin (garage_hdlr *g, unsigned long int ip)
{
	ip_list *	il = g->garage[MG_H (ip)];

	if (il == NULL)
		return (0);

	while (il != NULL && ip < il->ip) {
		il = il->next;
	}

	if (il != NULL && ip == il->ip)
		return (1);

	return (0);
}



/* CIDR routines
 *
 * XXX: maybe move some basic CIDR routines to an extra file for maintance
 * XXX: beta code, please test
 */

unsigned long int
mg_cidr_getmask (unsigned long int mask)
{
	/* work around to dumb gcc 'optimizations' (ie compiler bug)
	 */
	if (mask == 0)
		return (0);

	if (mask > 32) {
		return (mask);
	} else {
		unsigned long int	nm = 0xffffffff;

		/* clear zero bits
		 */
		mask = 32 - mask;
		nm >>= mask;
		nm <<= mask;

		return (nm);
	}
}


unsigned long int
mg_cidr_maskcount (unsigned long int mask)
{
	return ((~mg_cidr_getmask (mask)) + 1);
}


int
mg_cidr_match (unsigned long int ip1, unsigned long int ip2,
	unsigned long int mask)
{
	mask = mg_cidr_getmask (mask);
	ip1 &= mask;
	ip2 &= mask;

	return (ip1 == ip2);
}


unsigned long int
mg_cidr_count (garage_hdlr *g, unsigned long int ip, unsigned long int mask)
{
	unsigned long int	count = 0;
	unsigned long int	ip_start,
				ip_end;


	ip_start = ip & mg_cidr_getmask (mask);
	ip_end = ip_start + mg_cidr_maskcount (mask);

	/* workaround for /0 cidr mask (if sizeof (unsigned long int) == 4)
	 * it will make ip_end = 0, so we have to catch this case)
	 */
	if (ip_end == 0)
		return (mg_count (g));

	if ((ip_end - ip_start) >= mg_count (g)) {
		/* since there are less elements then the ip range contains,
		 * we go for a count-matching-elements-by-scanning-through-
		 * the-entire-array like technique
		 */
		unsigned long int	h;
		ip_list *		il;

		for (h = 0 ; h < (256 * 256) ; ++h) {
			if (g->garage[h] != NULL) {
				il = g->garage[h];

				do {
					if (mg_cidr_match (il->ip, ip, mask))
						count += 1;

					il = il->next;
				} while (il != NULL);
			}
		}
	} else {
		/* there are more elements in the garage then this range
		 * contains, so scam this range only
		 */
		do {
			count += mg_ip_isin (g, ip_start);

			ip_start += 1;
		} while (ip_start < ip_end);
	}

	return (count);
}


