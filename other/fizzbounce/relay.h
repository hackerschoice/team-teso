#ifndef	FIZZ_RELAY_H
#define	FIZZ_RELAY_H
#include "client.h"

void	rly_client (client *cl);
int	rly_clparse (client *cl, char *buffer, int buflen);
int	rly_srvparse (client *cl, char *buffer, int buflen);
int	rly_rb (int fd, char *buffer, int buflen);


#endif

