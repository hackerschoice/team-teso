/* zylyx - file find
 *
 * by scut of teso
 */

#ifndef	_ZYL_ZYLYX_H
#define	_ZYL_ZYLYX_H

#define	VERSION	"0.1.1"
#define	AUTHORS	"scut of teso"

typedef struct	proxy {
	char			*file;
	char			*host;
	unsigned short int	port;
	int			x, y;	/* field with proxy info :) */
} proxy;

typedef struct	result {
	int			found;
	char			*proxy_host;
	unsigned short int	proxy_port;
	char			*file;
} result;

void	zyl_assign_prx (proxy **pl);
void	zyl_main (proxy **pl, int proxycount, char *file);

#endif

