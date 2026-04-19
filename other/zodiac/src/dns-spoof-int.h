/* 
 * New, hopefully more flexible interface to dns-spoof.c
 * If anyone can come up with more imaginative/descriptive nomenclature, 
 * please change it :/
 */

#ifndef Z_DNS_SPOOF_INT_H
#define Z_DNS_SPOOF_INT_H

#include <pthread.h>

#define SPOOF_ID_MAX 3	/* maximum number of id spoofs in a single request */

#define SPOOF_STYLE_SNIFFID	0x1
#define SPOOF_STYLE_LOCAL	0x2
#define SPOOF_STYLE_JIZZ	0x3
#define SPOOF_STYLE_SNOOFID	0x4 /* not supported yet ! */

typedef struct spoof_style_jizz {
	char	*nameserver,
		*local_domain,	
		*local_dns_ip,
		*spoof_from,
		*spoof_to;
} spoof_style_jizz;

typedef struct spoof_style_local {
	int	spoof_type; /* A, PTR.. */

	char	*spoof_victim,
		*spoof_from,
		*spoof_to,
		*local_dns,
		*local_dns_ip;
} spoof_style_local;


typedef struct spoof_id_list {
	struct spoof_id_list	*next;

	int	spoof_type; /* A, PTR.. */

	char	*spoof_from,
		*spoof_from_domain,
		*spoof_to;
} spoof_id_list;


typedef struct spoof_style_id {
	char	*nameserver,	/* victim nameserver */
		*local_domain;	/* guess */

	int	id_cnt;		/* number of spoofs requested */
	spoof_id_list	*root;  /* linked list of spoofs */
} spoof_style_id;


typedef struct spoof_base {
	int		spoof_style;	/* id, jizz, local ... */

	union {
		spoof_style_id		id_spoof;
		spoof_style_local	local_spoof;
		spoof_style_jizz	jizz_spoof;
	} spoof;
} spoof_base;


spoof_base	*spoof_jizz_new (char *ns, char *domain, char *local_ip,
				char *spoof_from, char *spoof_to);
spoof_base	*spoof_id_new (char *ns, char *local_domain);
int		spoof_id_add (spoof_base *base, int type, char *spoof_from, 
				char *spoof_to, char *spoof_from_domain);
spoof_base	*spoof_local_new (char *victim, char *from, char *to,
				char *dns, char *dns_ip, int type);
void		spoof_destroy (spoof_base *spoof_base);

void		spoof_do (spoof_base *base);
pthread_t	spoof_do_threaded (spoof_base *base);

#endif

