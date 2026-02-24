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
 * From: @(#)terminal.c	5.3 (Berkeley) 3/22/91
 */
char terminal_rcsid[] = 
  "$Id: terminal.cc,v 1.25 1999/12/12 19:48:05 dholland Exp $";

#include <arpa/telnet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <termios.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>

#include "ring.h"
#include "defines.h"
#include "externs.h"
#include "types.h"
#include "proto.h"
#include "terminal.h"

static int TerminalWrite(const char *buf, int n);
static int TerminalRead(char *buf, int n);

ringbuf ttyoring, ttyiring;

#ifndef VDISCARD
cc_t termFlushChar;
#endif

#ifndef VLNEXT
cc_t termLiteralNextChar;
#endif

#ifndef VSUSP
cc_t termSuspChar;
#endif

#ifndef VWERASE
cc_t termWerasChar;
#endif

#ifndef VREPRINT
cc_t termRprntChar;
#endif

#ifndef VSTART
cc_t termStartChar;
#endif

#ifndef VSTOP
cc_t termStopChar;
#endif

#ifndef VEOL
cc_t termForw1Char;
#endif

#ifndef VEOL2
cc_t termForw2Char;
#endif

#ifndef VSTATUS
cc_t termAytChar;
#endif

/*
 * initialize the terminal data structures.
 */
void init_terminal(void) {
    if (ttyoring.init(2*BUFSIZ, ttysink, NULL) != 1) {
	exit(1);
    }
    if (ttyiring.init(BUFSIZ, NULL, ttysrc) != 1) {
	exit(1);
    }
    autoflush = TerminalAutoFlush();
}


/*
 *		Send as much data as possible to the terminal.
 *              if arg "drop" is nonzero, drop data on the floor instead.
 *
 *		Return value:
 *			-1: No useful work done, data waiting to go out.
 *			 0: No data was waiting, so nothing was done.
 *			 1: All waiting data was written out.
 *			 n: All data - n was written out.
 */
int ttyflush(int drop) {
    datasink *s = NULL;
    if (drop) {
	TerminalFlushOutput();
	s = ttyoring.setsink(nullsink);
    }
    int rv = ttyoring.flush();
    if (s) ttyoring.setsink(s);
    return rv;
}



/*
 * These routines decides on what the mode should be (based on the values
 * of various global variables).
 */
int getconnmode(void) {
    extern int linemode;
    int mode = 0;
#ifdef	KLUDGELINEMODE
    extern int kludgelinemode;
#endif

    if (In3270)
	return(MODE_FLOW);

    if (my_want_state_is_dont(TELOPT_ECHO))
	mode |= MODE_ECHO;

    if (localflow)
	mode |= MODE_FLOW;

    if (my_want_state_is_will(TELOPT_BINARY))
	mode |= MODE_INBIN;

    if (his_want_state_is_will(TELOPT_BINARY))
	mode |= MODE_OUTBIN;

#ifdef	KLUDGELINEMODE
    if (kludgelinemode) {
	if (my_want_state_is_dont(TELOPT_SGA)) {
	    mode |= (MODE_TRAPSIG|MODE_EDIT);
	    if (dontlecho && (clocks.echotoggle > clocks.modenegotiated)) {
		mode &= ~MODE_ECHO;
	    }
	}
	return(mode);
    }
#endif
    if (my_want_state_is_will(TELOPT_LINEMODE))
	mode |= linemode;
    return(mode);
}

void setconnmode(int force) {
    int newmode;

    newmode = getconnmode()|(force?MODE_FORCE:0);

    TerminalNewMode(newmode);

}


void setcommandmode(void) {
    TerminalNewMode(-1);
}


/*********************/

static int tout;		/* Output file descriptor */
static int tin;			/* Input file descriptor */


class ttysynk : public datasink {
  public:
    virtual int write(const char *buf, int len) {
	return TerminalWrite(buf, len);
    }
    virtual int writeurg(const char *buf, int len) {
	return TerminalWrite(buf, len);
    }
};

class ttysorc : public ringbuf::source {
    virtual int read(char *buf, int maxlen) {
	int l = TerminalRead(buf, maxlen);
	if (l<0 && errno==EWOULDBLOCK) l = 0;
	else if (l==0 && MODE_LOCAL_CHARS(globalmode) && isatty(tin)) {
	    /* EOF detection for line mode!!!! */
	    /* must be an EOF... */
	    *buf = termEofChar;
	    l = 1;
	}
	return l;
    }
};

static ttysynk chan1;
static ttysorc chan2;
datasink *ttysink = &chan1;
ringbuf::source *ttysrc = &chan2;


struct termios old_tc;
struct termios new_tc;

#ifndef	TCSANOW

#if defined(TCSETS)
#define	TCSANOW		TCSETS
#define	TCSADRAIN	TCSETSW
#define	tcgetattr(f, t) ioctl(f, TCGETS, (char *)t)

#elif defined(TCSETA)
#define	TCSANOW		TCSETA
#define	TCSADRAIN	TCSETAW
#define	tcgetattr(f, t) ioctl(f, TCGETA, (char *)t)

#else
#define	TCSANOW		TIOCSETA
#define	TCSADRAIN	TIOCSETAW
#define	tcgetattr(f, t) ioctl(f, TIOCGETA, (char *)t)

#endif

#define	tcsetattr(f, a, t) ioctl(f, a, (char *)t)
#define	cfgetospeed(ptr)	((ptr)->c_cflag&CBAUD)
#ifdef CIBAUD
#define	cfgetispeed(ptr)	(((ptr)->c_cflag&CIBAUD) >> IBSHIFT)
#else
#define	cfgetispeed(ptr)	cfgetospeed(ptr)
#endif

#endif /* no TCSANOW */


static void susp(int sig);

void tlink_init(void) {
#ifdef	SIGTSTP
    signal(SIGTSTP, susp);
#endif
    tout = fileno(stdout);
    tin = fileno(stdin);
}

int tlink_getifd(void) {
    return tin;
}

int tlink_getofd(void) {
    return tout;
}

static int TerminalWrite(const char *buf, int n) {
    int r;
    do {
	r = write(tout, buf, n);
    } while (r<0 && errno==EINTR);
    if (r<0 && (errno==ENOBUFS || errno==EWOULDBLOCK)) r = 0;
    return r;
}

static int TerminalRead(char *buf, int n) {
    int r;
    do {
	r = read(tin, buf, n);
    } while (r<0 && errno==EINTR);
    return r;
}

#ifdef	SIGTSTP
static void susp(int /*sig*/) {
    if ((rlogin != _POSIX_VDISABLE) && rlogin_susp())
	return;
    if (localchars)
	sendsusp();
}
#endif

/*
 * TerminalNewMode - set up terminal to a specific mode.
 *	MODE_ECHO: do local terminal echo
 *	MODE_FLOW: do local flow control
 *	MODE_TRAPSIG: do local mapping to TELNET IAC sequences
 *	MODE_EDIT: do local line editing
 *
 *	Command mode:
 *		MODE_ECHO|MODE_EDIT|MODE_FLOW|MODE_TRAPSIG
 *		local echo
 *		local editing
 *		local xon/xoff
 *		local signal mapping
 *
 *	Linemode:
 *		local/no editing
 *	Both Linemode and Single Character mode:
 *		local/remote echo
 *		local/no xon/xoff
 *		local/no signal mapping
 */

void TerminalNewMode(int f)
{
    static int prevmode = 0;
    struct termios tmp_tc;

    int onoff;
    int old;
    cc_t esc;

    globalmode = f&~MODE_FORCE;
    if (prevmode == f)
	return;

    /*
     * Write any outstanding data before switching modes
     * ttyflush() returns 0 only when there is no more data
     * left to write out, it returns -1 if it couldn't do
     * anything at all, otherwise it returns 1 + the number
     * of characters left to write.
     */
    old = ttyflush(SYNCHing|flushout);
    if (old < 0 || old > 1) {
	tcgetattr(tin, &tmp_tc);
	do {
	    /*
	     * Wait for data to drain, then flush again.
	     */
	    tcsetattr(tin, TCSADRAIN, &tmp_tc);
	    old = ttyflush(SYNCHing|flushout);
	} while (old < 0 || old > 1);
    }

    old = prevmode;
    prevmode = f&~MODE_FORCE;
    tmp_tc = new_tc;

    if (f&MODE_ECHO) {
	tmp_tc.c_lflag |= ECHO;
	tmp_tc.c_oflag |= ONLCR;
	if (crlf)
		tmp_tc.c_iflag |= ICRNL;
    } 
    else {
	tmp_tc.c_lflag &= ~ECHO;
	tmp_tc.c_oflag &= ~ONLCR;
	if (crlf) tmp_tc.c_iflag &= ~ICRNL;
    }

    if ((f&MODE_FLOW) == 0) {
	tmp_tc.c_iflag &= ~(IXANY|IXOFF|IXON);
    } 
    else {
	tmp_tc.c_iflag |= IXANY|IXOFF|IXON;
    }

    if ((f&MODE_TRAPSIG) == 0) {
	tmp_tc.c_lflag &= ~ISIG;
	localchars = 0;
    } 
    else {
	tmp_tc.c_lflag |= ISIG;
	localchars = 1;
    }

    if (f&MODE_EDIT) {
	tmp_tc.c_lflag |= ICANON;
    } 
    else {
	tmp_tc.c_lflag &= ~ICANON;
	tmp_tc.c_iflag &= ~ICRNL;
	tmp_tc.c_cc[VMIN] = 1;
	tmp_tc.c_cc[VTIME] = 0;
    }

    if ((f&(MODE_EDIT|MODE_TRAPSIG)) == 0) {
#ifdef VLNEXT
	tmp_tc.c_cc[VLNEXT] = (cc_t)(_POSIX_VDISABLE);
#endif
    }

    if (f&MODE_SOFT_TAB) {
#ifdef OXTABS
	tmp_tc.c_oflag |= OXTABS;
#endif
#ifdef TABDLY
	tmp_tc.c_oflag &= ~TABDLY;
	tmp_tc.c_oflag |= TAB3;
#endif
    } 
    else {
#ifdef OXTABS
	tmp_tc.c_oflag &= ~OXTABS;
#endif
#ifdef TABDLY
	tmp_tc.c_oflag &= ~TABDLY;
#endif
    }

    if (f&MODE_LIT_ECHO) {
#ifdef ECHOCTL
	tmp_tc.c_lflag &= ~ECHOCTL;
#endif
    } 
    else {
#ifdef ECHOCTL
	tmp_tc.c_lflag |= ECHOCTL;
#endif
    }

    if (f == -1) {
	onoff = 0;
    } 
    else {
	if (f & MODE_INBIN) {
		tmp_tc.c_iflag &= ~ISTRIP;
	}
	else {
		// Commented this out 5/97 so it works with 8-bit characters
		// ...and put it back 12/99 because it violates the RFC and
		// breaks SunOS.
	 	tmp_tc.c_iflag |= ISTRIP;
	}
	if (f & MODE_OUTBIN) {
		tmp_tc.c_cflag &= ~(CSIZE|PARENB);
		tmp_tc.c_cflag |= CS8;
		tmp_tc.c_oflag &= ~OPOST;
	} else {
		tmp_tc.c_cflag &= ~(CSIZE|PARENB);
		tmp_tc.c_cflag |= old_tc.c_cflag & (CSIZE|PARENB);
		tmp_tc.c_oflag |= OPOST;
	}
	onoff = 1;
    }

    if (f != -1) {
#ifdef	SIGTSTP
	signal(SIGTSTP, susp);
#endif	/* SIGTSTP */

#ifdef	SIGINFO
	signal(SIGINFO, ayt);
#endif	SIGINFO

#if defined(NOKERNINFO)
	tmp_tc.c_lflag |= NOKERNINFO;
#endif
	/*
	 * We don't want to process ^Y here.  It's just another
	 * character that we'll pass on to the back end.  It has
	 * to process it because it will be processed when the
	 * user attempts to read it, not when we send it.
	 */
#ifdef VDSUSP
	tmp_tc.c_cc[VDSUSP] = (cc_t)(_POSIX_VDISABLE);
#endif
	/*
	 * If the VEOL character is already set, then use VEOL2,
	 * otherwise use VEOL.
	 */
	esc = (rlogin != _POSIX_VDISABLE) ? rlogin : escapechar;
	if ((tmp_tc.c_cc[VEOL] != esc)
#ifdef VEOL2
	    && (tmp_tc.c_cc[VEOL2] != esc)
#endif
	    ) {
		if (tmp_tc.c_cc[VEOL] == (cc_t)(_POSIX_VDISABLE))
		    tmp_tc.c_cc[VEOL] = esc;
#ifdef VEOL2
		else if (tmp_tc.c_cc[VEOL2] == (cc_t)(_POSIX_VDISABLE))
		    tmp_tc.c_cc[VEOL2] = esc;
#endif
	}
    } 
    else {

#ifdef	SIGINFO
	signal(SIGINFO, ayt_status);
#endif	SIGINFO

#ifdef	SIGTSTP
	signal(SIGTSTP, SIG_DFL);
/*	(void) sigsetmask(sigblock(0) & ~(1<<(SIGTSTP-1))); */
#endif	/* SIGTSTP */

	tmp_tc = old_tc;
    }
    if (tcsetattr(tin, TCSADRAIN, &tmp_tc) < 0)
	tcsetattr(tin, TCSANOW, &tmp_tc);

    ioctl(tin, FIONBIO, (char *)&onoff);
    ioctl(tout, FIONBIO, (char *)&onoff);

#if defined(TN3270)
    if (noasynchtty == 0) {
	ioctl(tin, FIOASYNC, (char *)&onoff);
    }
#endif	/* defined(TN3270) */

}

#ifndef	B19200
#define B19200 B9600
#endif

#ifndef	B38400
#define B38400 B19200
#endif

#ifndef B57600
#define B57600 B38400
#endif

#ifndef B115200
#define B115200 B57600
#endif

/*
 * This code assumes that the values B0, B50, B75...
 * are in ascending order.  They do not have to be
 * contiguous.
 */
struct termspeeds {
	long speed;
	long value;
} termspeeds[] = {
	{ 0,      B0 },      { 50,     B50 },    { 75,     B75 },
	{ 110,    B110 },    { 134,    B134 },   { 150,    B150 },
	{ 200,    B200 },    { 300,    B300 },   { 600,    B600 },
	{ 1200,   B1200 },   { 1800,   B1800 },  { 2400,   B2400 },
	{ 4800,   B4800 },   { 9600,   B9600 },  { 19200,  B19200 },
	{ 38400,  B38400 },  { 57600,  B57600 }, { 115200, B115200 },
	{ -1,     B115200 }
};

void TerminalSpeeds(long *ispeed, long *ospeed) {
    register struct termspeeds *tp;
    register long in, out;

    out = cfgetospeed(&old_tc);
    in = cfgetispeed(&old_tc);
    if (in == 0)
	in = out;

    tp = termspeeds;
    while ((tp->speed != -1) && (tp->value < in))
	tp++;
    *ispeed = tp->speed;

    tp = termspeeds;
    while ((tp->speed != -1) && (tp->value < out))
	tp++;
    *ospeed = tp->speed;
}

int TerminalWindowSize(long *rows, long *cols) {
#ifdef	TIOCGWINSZ
    struct winsize ws;

    if (ioctl(fileno(stdin), TIOCGWINSZ, (char *)&ws) >= 0) {
	*rows = ws.ws_row;
	*cols = ws.ws_col;
	return 1;
    }
#endif	/* TIOCGWINSZ */
    return 0;
}


/*
 * EmptyTerminal - called to make sure that the terminal buffer is 
 * empty. Note that we consider the buffer to run all the way to the 
 * kernel (thus the select).
 */
void EmptyTerminal(void) {
    fd_set o;
    FD_ZERO(&o);
    
    if (TTYBYTES() == 0) {
	FD_SET(tout, &o);
	select(tout+1, NULL, &o, NULL, NULL);	/* wait for TTLOWAT */
    } 
    else {
	while (TTYBYTES()) {
	    ttyflush(0);
	    FD_SET(tout, &o);
	    select(tout+1, NULL, &o, NULL, NULL); /* wait for TTLOWAT */
	}
    }
}

int
TerminalAutoFlush(void)
{
#if	defined(LNOFLSH)
    int flush;

    ioctl(tin, TIOCLGET, (char *)&flush);
    return !(flush&LNOFLSH);	/* if LNOFLSH, no autoflush */
#else	/* LNOFLSH */
    return 1;
#endif	/* LNOFLSH */
}

/*
 * Flush output to the terminal
 */
    void
TerminalFlushOutput()
{
#ifdef	TIOCFLUSH
    (void) ioctl(fileno(stdout), TIOCFLUSH, (char *) 0);
#else
    (void) ioctl(fileno(stdout), TCFLSH, (char *) 0);
#endif
}

    void
TerminalSaveState()
{
#ifndef	USE_TERMIO
    ioctl(0, TIOCGETP, (char *)&ottyb);
    ioctl(0, TIOCGETC, (char *)&otc);
    ioctl(0, TIOCGLTC, (char *)&oltc);
    ioctl(0, TIOCLGET, (char *)&olmode);

    ntc = otc;
    nltc = oltc;
    nttyb = ottyb;

#else	/* USE_TERMIO */
    tcgetattr(0, &old_tc);

    new_tc = old_tc;

#ifndef	VDISCARD
    termFlushChar = CONTROL('O');
#endif
#ifndef	VWERASE
    termWerasChar = CONTROL('W');
#endif
#ifndef	VREPRINT
    termRprntChar = CONTROL('R');
#endif
#ifndef	VLNEXT
    termLiteralNextChar = CONTROL('V');
#endif
#ifndef	VSTART
    termStartChar = CONTROL('Q');
#endif
#ifndef	VSTOP
    termStopChar = CONTROL('S');
#endif
#ifndef	VSTATUS
    termAytChar = CONTROL('T');
#endif
#endif	/* USE_TERMIO */
}

void TerminalDefaultChars(void) {
#ifndef	USE_TERMIO
    ntc = otc;
    nltc = oltc;
    nttyb.sg_kill = ottyb.sg_kill;
    nttyb.sg_erase = ottyb.sg_erase;
#else	/* USE_TERMIO */
    memcpy(new_tc.c_cc, old_tc.c_cc, sizeof(old_tc.c_cc));
#ifndef	VDISCARD
    termFlushChar = CONTROL('O');
#endif
#ifndef	VWERASE
    termWerasChar = CONTROL('W');
#endif
#ifndef	VREPRINT
    termRprntChar = CONTROL('R');
#endif
#ifndef	VLNEXT
    termLiteralNextChar = CONTROL('V');
#endif
#ifndef	VSTART
    termStartChar = CONTROL('Q');
#endif
#ifndef	VSTOP
    termStopChar = CONTROL('S');
#endif
#ifndef	VSTATUS
    termAytChar = CONTROL('T');
#endif
#endif	/* USE_TERMIO */
}
