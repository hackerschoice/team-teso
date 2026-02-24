/*
 * Copyright (c) 1988, 1990 Regents of the University of California.
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
 * From: @(#)sys_bsd.c	5.2 (Berkeley) 3/1/91
 */
char bsd_rcsid[] = 
  "$Id: sys_bsd.cc,v 1.24 1999/09/28 16:29:24 dholland Exp $";

/*
 * The following routines try to encapsulate what is system dependent
 * (at least between 4.x and dos) which is used in telnet.c.
 */

#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <arpa/telnet.h>

#include "ring.h"

#include "defines.h"
#include "externs.h"
#include "types.h"
#include "proto.h"
#include "netlink.h"
#include "terminal.h"

static fd_set ibits, obits, xbits;

void init_sys(void)
{
    tlink_init();
    FD_ZERO(&ibits);
    FD_ZERO(&obits);
    FD_ZERO(&xbits);

    errno = 0;
}


#ifdef	KLUDGELINEMODE
extern int kludgelinemode;
#endif
/*
 * TerminalSpecialChars()
 *
 * Look at an input character to see if it is a special character
 * and decide what to do.
 *
 * Output:
 *
 *	0	Don't add this character.
 *	1	Do add this character
 */

void intp(), sendbrk(), sendabort();

int
TerminalSpecialChars(int c)
{
    void xmitAO(), xmitEL(), xmitEC();

    if (c == termIntChar) {
	intp();
	return 0;
    } else if (c == termQuitChar) {
#ifdef	KLUDGELINEMODE
	if (kludgelinemode)
	    sendbrk();
	else
#endif
	    sendabort();
	return 0;
    } else if (c == termEofChar) {
	if (my_want_state_is_will(TELOPT_LINEMODE)) {
	    sendeof();
	    return 0;
	}
	return 1;
    } else if (c == termSuspChar) {
	sendsusp();
	return(0);
    } else if (c == termFlushChar) {
	xmitAO();		/* Transmit Abort Output */
	return 0;
    } else if (!MODE_LOCAL_CHARS(globalmode)) {
	if (c == termKillChar) {
	    xmitEL();
	    return 0;
	} else if (c == termEraseChar) {
	    xmitEC();		/* Transmit Erase Character */
	    return 0;
	}
    }
    return 1;
}



cc_t *tcval(int func) {
    switch(func) {
    case SLC_IP:	return(&termIntChar);
    case SLC_ABORT:	return(&termQuitChar);
    case SLC_EOF:	return(&termEofChar);
    case SLC_EC:	return(&termEraseChar);
    case SLC_EL:	return(&termKillChar);
    case SLC_XON:	return(&termStartChar);
    case SLC_XOFF:	return(&termStopChar);
    case SLC_FORW1:	return(&termForw1Char);
    case SLC_FORW2:	return(&termForw2Char);
#ifdef	VDISCARD
    case SLC_AO:	return(&termFlushChar);
#endif
#ifdef	VSUSP
    case SLC_SUSP:	return(&termSuspChar);
#endif
#ifdef	VWERASE
    case SLC_EW:	return(&termWerasChar);
#endif
#ifdef	VREPRINT
    case SLC_RP:	return(&termRprntChar);
#endif
#ifdef	VLNEXT
    case SLC_LNEXT:	return(&termLiteralNextChar);
#endif
#ifdef	VSTATUS
    case SLC_AYT:	return(&termAytChar);
#endif

    case SLC_SYNCH:
    case SLC_BRK:
    case SLC_EOR:
    default:
	return NULL;
    }
}

#if defined(TN3270)
void NetSigIO(int fd, int onoff) {
    ioctl(fd, FIOASYNC, (char *)&onoff);	/* hear about input */
}

void NetSetPgrp(int fd) {
    int myPid;

    myPid = getpid();
    fcntl(fd, F_SETOWN, myPid);
}
#endif	/*defined(TN3270)*/

/*
 * Various signal handling routines.
 */

#if 0
static void deadpeer(int /*sig*/) {
    setcommandmode();
    siglongjmp(peerdied, -1);
}
#endif

static void intr(int /*sig*/) {
    if (localchars) {
	intp();
    }
    else {
#if 0
        setcommandmode();
	siglongjmp(toplevel, -1);
#else
	signal(SIGINT, SIG_DFL);
	raise(SIGINT);
#endif
    }
}

static void intr2(int /*sig*/) {
    if (localchars) {
#ifdef	KLUDGELINEMODE
	if (kludgelinemode)
	    sendbrk();
	else
#endif
	    sendabort();
	return;
    }
    signal(SIGQUIT, SIG_DFL);
    raise(SIGQUIT);
}

#ifdef	SIGWINCH
static void sendwin(int /*sig*/) {
    if (connected) {
	sendnaws();
    }
}
#endif

#ifdef	SIGINFO
void ayt(int sig) {
    (void)sig;

    if (connected)
	sendayt();
    else
	ayt_status(0);
}
#endif

void sys_telnet_init(void) {
    signal(SIGINT, intr);
    signal(SIGQUIT, intr2);
#if 0
    signal(SIGPIPE, deadpeer);
#endif
#ifdef	SIGWINCH
    signal(SIGWINCH, sendwin);
#endif
#ifdef	SIGINFO
    signal(SIGINFO, ayt);
#endif

    setconnmode(0);

    nlink.nonblock(1);

#if defined(TN3270)
    if (noasynchnet == 0) {			/* DBX can't handle! */
	NetSigIO(net, 1);
	NetSetPgrp(net);
    }
#endif	/* defined(TN3270) */

    nlink.oobinline();
}

/*
 * Process rings -
 *
 *	This routine tries to fill up/empty our various rings.
 *
 *	The parameter specifies whether this is a poll operation,
 *	or a block-until-something-happens operation.
 *
 *	The return value is 1 if something happened, 0 if not.
 */

int process_rings(int netin, int netout, int netex, int ttyin, int ttyout, 
		  int poll /* If 0, then block until something to do */)
{
    register int c, maxfd;
		/* One wants to be a bit careful about setting returnValue
		 * to one, since a one implies we did some useful work,
		 * and therefore probably won't be called to block next
		 * time (TN3270 mode only).
		 */
    int returnValue = 0;
    static struct timeval TimeValue = { 0, 0 };
    
    int net = nlink.getfd();
    int tin = tlink_getifd();
    int tout = tlink_getofd();

    if (netout) {
	FD_SET(net, &obits);
    } 
    if (ttyout) {
	FD_SET(tout, &obits);
    }
    if (ttyin) {
	FD_SET(tin, &ibits);
    }
    if (netin) {
	FD_SET(net, &ibits);
    }
    if (netex) {
	FD_SET(net, &xbits);
    }

    maxfd = net;
    if (maxfd < tin) maxfd=tin;
    if (maxfd < tout) maxfd=tout;

    if ((c = select(maxfd+1, &ibits, &obits, &xbits,
			(poll == 0)? (struct timeval *)0 : &TimeValue)) < 0) {
	if (c == -1) {
		    /*
		     * we can get EINTR if we are in line mode,
		     * and the user does an escape (TSTP), or
		     * some other signal generator.
		     */
	    if (errno == EINTR) {
		return 0;
	    }
#if defined(TN3270)
		    /*
		     * we can get EBADF if we were in transparent
		     * mode, and the transcom process died.
		    */
	    if (errno == EBADF) {
			/*
			 * zero the bits (even though kernel does it)
			 * to make sure we are selecting on the right
			 * ones.
			*/
		FD_ZERO(&ibits);
		FD_ZERO(&obits);
		FD_ZERO(&xbits);
		return 0;
	    }
#endif /* TN3270 */
		    /* I don't like this, does it ever happen? */
	    printf("sleep(5) from telnet, after select\r\n");
	    sleep(5);
	}
	return 0;
    }

    /*
     * Any urgent data?
     */
    if (FD_ISSET(net, &xbits)) {
	FD_CLR(net, &xbits);
	SYNCHing = 1;
	(void) ttyflush(1);	/* flush already enqueued data */
    }

    /*
     * Should flush output buffers first to make room for new input. --okir
     */
    if (FD_ISSET(net, &obits)) {
	FD_CLR(net, &obits);
	returnValue |= netflush();
    }
    if (FD_ISSET(tout, &obits)) {
	FD_CLR(tout, &obits);
	returnValue |= (ttyflush(SYNCHing|flushout) > 0);
    }

    /*
     * Something to read from the network...
     */
    if (FD_ISSET(net, &ibits)) {
	/* hacks for systems without SO_OOBINLINE removed */

	FD_CLR(net, &ibits);
	/* Only call network input routine if there is room. Otherwise
	 * we will try a 0 byte read, which we happily interpret as the
	 * server having dropped the connection...
	 * NB the input routine reserves 1 byte for ungetc.
	 *                              12.3.97 --okir */
	returnValue = 1;
	if (netiring.empty_count() > 1) {
		c = netiring.read_source();
		if (c <= 0)
		    return -1;
		else if (c == 0)
		    returnValue = 0;
	}
    }

    /*
     * Something to read from the tty...
     */
    if (FD_ISSET(tin, &ibits)) {
	FD_CLR(tin, &ibits);
	c = ttyiring.read_source();
	if (c < 0) {
	    return -1;
	}
	else if (c==0) returnValue = 0;
	else returnValue = 1;		/* did something useful */
    }

    return returnValue;
}
