/*-
 * Copyright (c) 1991 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * From: @(#)genget.c	5.1 (Berkeley) 2/28/91
 */
char gg_rcsid[] = 
  "$Id: genget.cc,v 1.3 1996/07/26 09:54:09 dholland Exp $";

#include <string.h>
#include <ctype.h>

#include "genget.h"

#define	LOWER(x) (isupper(x) ? tolower(x) : (x))
/*
 * The prefix function returns 0 if *s1 is not a prefix
 * of *s2.  If *s1 exactly matches *s2, the negative of
 * the length is returned.  If *s1 is a prefix of *s2,
 * the length of *s1 is returned.
 */
int isprefix(const char *s1, const char *s2) {
        const char *os1;
	char c1, c2;

        if (*s1 == 0) return -1;

        os1 = s1;
	c1 = *s1;
	c2 = *s2;

        while (LOWER(c1) == LOWER(c2)) {
		if (c1 == 0) break;
                c1 = *++s1;
                c2 = *++s2;
        }
	if (*s1) return 0;
        return *s2 ? (s1 - os1) : (os1 - s1);
}

/*
 * name: name to match
 * table: name entry in table
 */
char **genget(const char *name, char **table, int stlen) {
	char **c, **found;
	int n;

	if (!name) return NULL;

	found = NULL;
	for (c = table; *c; c = (char **)((char *)c + stlen)) {
		n = isprefix(name, *c);
		if (n == 0) continue;
		if (n < 0) return c;	/* exact match */
		if (found) return (char **)AMBIGUOUS;
		found = c;
	}
	return found;
}

