/* $Id: daemon.h,v 1.1.1.1 2001/09/19 14:44:59 stealth Exp $ */

#ifndef _BSD_DAEMON_H
#define _BSD_DAEMON_H

#include "config.h"
#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose);
#endif /* !HAVE_DAEMON */

#endif /* _BSD_DAEMON_H */
