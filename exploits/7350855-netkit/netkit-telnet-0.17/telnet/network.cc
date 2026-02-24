/*
 * Copyright (c) 1988 Regents of the University of California.
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
 * From: @(#)network.c	5.2 (Berkeley) 3/1/91
 */
char net_rcsid[] = 
  "$Id: network.cc,v 1.15 1996/08/13 08:09:58 dholland Exp $";

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/telnet.h>

#include "ring.h"
#include "defines.h"
#include "externs.h"
#include "proto.h"
#include "netlink.h"

ringbuf netoring;
ringbuf netiring;

/*
 * Initialize internal network data structures.
 */

void init_network(void) {
    if (netoring.init(2*BUFSIZ, netsink, NULL) != 1) {
	exit(1);
    }
    if (netiring.init(BUFSIZ, NULL, netsrc) != 1) {
	exit(1);
    }
    NetTrace = stdout;
}


/*
 *  netflush
 *		Send as much data as possible to the network,
 *	handling requests for urgent data.
 *
 *		The return value indicates whether we did any
 *	useful work.
 */


int netflush(void) {
    int r = netoring.flush();
    if (r < -1) {
	setcommandmode();
	perror(hostname);
	nlink.close(0);
	netoring.clear_mark();
	siglongjmp(peerdied, -1);
	/*NOTREACHED*/
    }
    return r>0;
}
