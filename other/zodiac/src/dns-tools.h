/* zodiac - advanced dns spoofer
 *
 * by scut / teso, smiler
 *
 * dns tool routines include file
 */


#ifndef	Z_DNSTOOLS_H
#define	Z_DNSTOOLS_H

#define DT_ANSWER_OK		0x0
#define DT_ANSWER_TIMEOUT	0x1 /* no answer ! */
/* indicates a DNS error - should I be more specific? */
#define DT_ANSWER_ERR		0x2
#define DT_ANSWER_RESOLVE	0x3
#define DT_ANSWER_UNKNOWNTYPE	0x4
#define DT_ANSWER_FILTERERR	0x5


typedef struct {
	char	*name;
	u_short	type;
	union {
		struct in_addr ip;	/* A */
		char		*label; /* PTR NS TXT */
	} data;
} rrec;


typedef struct {
	int	rrec_cnt;
	rrec	*rrecords; /* array of resource records */
} dt_section;


typedef struct {
	unsigned int	answer;		/* should be of form DT_ANSWER_* */

	dt_section	an_section,
			ns_section,
			ar_section;
} dt_answer;


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
 */

char		*dt_bind_version (char *host);

/* dt_query_bind
 *
 * generic query function. query a remote nameserver `serv' for a query
 * `query' of the type `type' and class `class'.
 *
 * return a pointer to a generic answer structure
 *   on failure ans->answer will be set appropiatly
 *
 * -smiler
 * we just don't *do* windoze NSs ;-)
 */

dt_answer	*dt_query_bind (char *serv, u_short type, u_short class, char *query);
int		dt_answer_free (dt_answer *ans);

/* Array of strings for DT_ANSWER_* macros.
 */
extern char	*dterrlist[];

struct in_addr *dt_ns_get_auth (char *ns_query, char *domain, int *err);


#endif

