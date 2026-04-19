/* zodiac - advanced dns spoofer
 *
 * spoofing routines include file
 *
 * by scut / teso
 */

#ifndef	Z_DNS_SPOOF_H
#define	Z_DNS_SPOOF

#include <arpa/inet.h>
#include "dns-spoof-int.h"

int	spoof_ip_check (char *ns, char *ourdomain);
int	spoof_query (char *nameserver, char *ourdomain, int timeout, struct in_addr *proxy);
void	spoof_local (spoof_style_local *cs);
void	spoof_jizz (spoof_style_jizz *cs);
void	spoof_dnsid (spoof_style_id *cs);
void	spoof_poison (char *ns, struct in_addr proxy, struct in_addr  *auth_ns, 
			int dns_id, char *spoof_from, char *spoof_to, int type);

#endif

