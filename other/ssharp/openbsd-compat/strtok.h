/* $Id: strtok.h,v 1.1.1.1 2001/09/19 14:44:59 stealth Exp $ */

#ifndef _BSD_STRTOK_H
#define _BSD_STRTOK_H

#include "config.h"

#ifndef HAVE_STRTOK_R
char *strtok_r(char *s, const char *delim, char **last);
#endif /* HAVE_STRTOK_R */

#endif /* _BSD_STRTOK_H */
