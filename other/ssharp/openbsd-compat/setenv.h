/* $Id: setenv.h,v 1.1.1.1 2001/09/19 14:44:59 stealth Exp $ */

#ifndef _BSD_SETENV_H
#define _BSD_SETENV_H

#include "config.h"

#ifndef HAVE_SETENV

int setenv(register const char *name, register const char *value, int rewrite);

#endif /* !HAVE_SETENV */

#endif /* _BSD_SETENV_H */
