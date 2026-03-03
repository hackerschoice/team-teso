/* $Id: bindresvport.h,v 1.1.1.1 2001/09/19 14:44:59 stealth Exp $ */

#ifndef _BSD_BINDRESVPORT_H
#define _BSD_BINDRESVPORT_H

#include "config.h"

#ifndef HAVE_BINDRESVPORT_SA
int bindresvport_sa(int sd, struct sockaddr *sa);
#endif /* !HAVE_BINDRESVPORT_SA */

#endif /* _BSD_BINDRESVPORT_H */
