/* bscan - mod_garage.h - per IP storage functions include file
 *
 * by scut / teso
 */

#ifndef _MOD_GARAGE_H
#define	_MOD_GARAGE_H

#include <sys/types.h>

#define	GARAGE_VERSION	"1.0.1"


typedef struct	ip_elem {
	struct ip_elem *	next;	/* more then one data stored */

	int			data_free;	/* 1 = do free() on destroy */
	size_t			data_len;
	void *			data;	/* must be free() able */
} ip_elem;


typedef struct	ip_list {
	struct ip_list *	next;	/* another IP, always greater then this ! */
	unsigned long int	ip;

	ip_elem *		data;
} ip_list;


/* not for use in other code then garage.c
 */
typedef struct {
	char *			name;
	ip_list	**		garage;

	void			(* cleaner)(ip_list *);

	unsigned long int	ip_count;

	unsigned long int	timeout_max;
	unsigned long int	timeout_idx;
	unsigned long int *	timeout_tbl;
} garage_hdlr;


/* mg_init
 *
 * setup the required structures for the garage
 *
 * return 0 on success
 * return 1 on failure
 */

garage_hdlr *
mg_init (char *name, unsigned long int max_hosts_in_list,
	void (* cleaner)(ip_list *));


/* mg_destroy
 *
 * destroy all data in the garage `g', use the standard handler in case
 * `do_handler' is not zero, otherwise just free.
 */

void
mg_destroy (garage_hdlr *g, int do_handler);


/* mg_write
 *
 * store pointer `data' with len `data_len' to the garage for IP `ip'
 * if `data_free' is non-zero the `data' pointer will be freed if mg_clean
 * or mg_destroy is called.
 */

void
mg_write (garage_hdlr *g, unsigned long int ip, void *data, size_t data_len,
	int data_free);


/* mg_read
 *
 * return first ip_elem for ip `ip' on success (it is not removed from garage)
 * return NULL on failure
 */

ip_elem *
mg_read (garage_hdlr *g, unsigned long int ip);


/* mg_clean
 *
 * clean everything stored in the garage for IP `ip'
 */

void
mg_clean (garage_hdlr *g, unsigned long int ip, void (*cleaner)(ip_list *));


/* mg_show
 *
 * DEBUG function, to show IP distribution in garage
 */

void
mg_show (garage_hdlr *g);


/* mg_count
 *
 * count elements in garage
 */

unsigned long int
mg_count (garage_hdlr *g);


/* mg_ip_isin
 *
 * check whether the ip `ip' is stored in the garage pointed to by `g'.
 *
 * return zero in case it is not
 * return != zero if it is
 */

int
mg_ip_isin (garage_hdlr *g, unsigned long int ip);


/* CIDR routines
 */

/* mg_cidr_getmask
 *
 * convert a netmask (eg 0xfffffc00) or a cidr notation (eg 24) given in
 * `mask' to a netmask.
 */

unsigned long int
mg_cidr_getmask (unsigned long int mask);


/* mg_cidr_maskcount
 *
 * return the number of hosts that are possible using a mask `mask' in
 * either CIDR or netmask notation
 */

unsigned long int
mg_cidr_maskcount (unsigned long int mask);


/* mg_cidr_match
 *
 * check whether `ip1' and `ip2' are in the same network, given the network
 * size by `mask' (CIDR or netmask notation)
 */

int
mg_cidr_match (unsigned long int ip1, unsigned long int ip2,
	unsigned long int mask);


/* mg_cidr_count
 *
 * count elements in garage `g', that are within the CIDR range build from
 * ip `ip' and netmask `mask'. `mask' is either the number of bits, if it's in
 * the range of 0-32, or the real mask, if it is greater then 32. (for the
 * zero case the netmask is equal to the cidr notation).
 */

unsigned long int
mg_cidr_count (garage_hdlr *g, unsigned long int ip, unsigned long int mask);


#endif

