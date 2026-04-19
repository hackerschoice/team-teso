/* $Id: setproctitle.h,v 1.1.1.1 2001/09/19 14:44:59 stealth Exp $ */

#ifndef _BSD_SETPROCTITLE_H
#define _BSD_SETPROCTITLE_H

#include "config.h"

#ifndef HAVE_SETPROCTITLE
void setproctitle(const char *fmt, ...);
#endif

#endif /* _BSD_SETPROCTITLE_H */
