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
 * From: @(#)telnet.c	5.53 (Berkeley) 3/22/91
 */
char telnet_rcsid[] = 
"$Id: telnet.cc,v 1.36 2000/07/23 03:24:53 dholland Exp $";

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <arpa/telnet.h>

#include <ctype.h>

#include "ring.h"
#include "defines.h"
#include "externs.h"
#include "types.h"
#include "environ.h"
#include "proto.h"
#include "ptrarray.h"
#include "netlink.h"
#include "terminal.h"

/*
 * Due to lossage in some linux distributions/kernel releases/libc versions
 * this must come *after* termios.h (which is included in externs.h)
 */
#include <termcap.h>

#ifdef USE_NCURSES
#include <term.h>
#endif


#define	strip(x)	((x)&0x7f)

static unsigned char subbuffer[SUBBUFSIZE];
static unsigned char *subpointer, *subend;	 /* buffer for sub-options */
#define	SB_CLEAR()	subpointer = subbuffer;
#define	SB_TERM()	{ subend = subpointer; SB_CLEAR(); }
#define	SB_ACCUM(c)	if (subpointer < (subbuffer+sizeof subbuffer)) { \
  *subpointer++ = (c); \
			 }

#define	SB_GET()	(*subpointer++)
#define	SB_PEEK()	(*subpointer)
#define	SB_EOF()	(subpointer >= subend)
#define	SB_LEN()	(subend - subpointer)

char	options[256];		/* The combined options */
char	do_dont_resp[256];
char	will_wont_resp[256];

int
eight = 0,
  autologin = 0,	/* Autologin anyone? */
  skiprc = 0,
  connected,
  showoptions,
  In3270,		/* Are we in 3270 mode? */
  ISend,		/* trying to send network data in */
  debug = 0,
  crmod,
  crlf,		/* Should '\r' be mapped to <CR><LF> (or <CR><NUL>)? */
#if	defined(TN3270)
  noasynchtty = 0,/* User specified "-noasynch" on command line */
  noasynchnet = 0,/* User specified "-noasynch" on command line */
  askedSGA = 0,	/* We have talked about suppress go ahead */
#endif	/* defined(TN3270) */
  telnetport,
  SYNCHing,	/* we are in TELNET SYNCH mode */
  flushout,	/* flush output */
  autoflush = 0,	/* flush output when interrupting? */
  autosynch,	/* send interrupt characters with SYNCH? */
  localflow,	/* we handle flow control locally */
  localchars,	/* we recognize interrupt/quit */
  donelclchars,	/* the user has set "localchars" */
  donebinarytoggle,	/* the user has put us in binary */
  dontlecho,	/* do we suppress local echoing right now? */
  globalmode;

char *prompt = 0;

cc_t escapechar;
cc_t rlogin;
#ifdef	KLUDGELINEMODE
cc_t echoc;
#endif

/*
 * Telnet receiver states for fsm
 */
#define	TS_DATA		0
#define	TS_IAC		1
#define	TS_WILL		2
#define	TS_WONT		3
#define	TS_DO		4
#define	TS_DONT		5
#define	TS_CR		6
#define	TS_SB		7		/* sub-option collection */
#define	TS_SE		8		/* looking for sub-option end */

static int telrcv_state;

sigjmp_buf toplevel;
sigjmp_buf peerdied;

int flushline;
int linemode;

#ifdef	KLUDGELINEMODE
int kludgelinemode = 1;
#endif

/*
 * The following are some clocks used to decide how to interpret
 * the relationship between various variables.
 */

Clocks clocks;

#ifdef	notdef
Modelist modelist[] = {
  { "telnet command mode", COMMAND_LINE },
  { "character-at-a-time mode", 0 },
  { "character-at-a-time mode (local echo)", LOCAL_ECHO|LOCAL_CHARS },
  { "line-by-line mode (remote echo)", LINE | LOCAL_CHARS },
  { "line-by-line mode", LINE | LOCAL_ECHO | LOCAL_CHARS },
  { "line-by-line mode (local echoing suppressed)", LINE | LOCAL_CHARS },
  { "3270 mode", 0 },
};
#endif

/*
 * Initialize telnet environment.
 */
void init_telnet(void) {
  env_init();
  cmdtab_init();
  
  SB_CLEAR();
  memset(options, 0, sizeof(options));
  
  connected = In3270 = ISend = localflow = donebinarytoggle = 0;
  
  SYNCHing = 0;
  
  /* Don't change NetTrace */
  
  escapechar = CONTROL(']');
  rlogin = _POSIX_VDISABLE;
#ifdef	KLUDGELINEMODE
  echoc = CONTROL('E');
#endif
  
  flushline = 1;
  telrcv_state = TS_DATA;
}


#if 0
#include <stdarg.h>

static void printring(Ring *ring, const char *format, ...) {
  va_list ap;
  char buffer[100];		/* where things go */
  char *ptr;
  char *string;
  int i;
  
  va_start(ap, format);
  
  ptr = buffer;
  
  while ((i = *format++) != 0) {
    if (i == '%') {
      i = *format++;
      switch (i) {
      case 'c':
	*ptr++ = va_arg(ap, int);
	break;
      case 's':
	string = va_arg(ap, char *);
	ring->supply_data(buffer, ptr-buffer);
	ring->supply_data(string, strlen(string));
	ptr = buffer;
	break;
      case 0:
	ExitString("printring: trailing %%.\n", 1);
	/*NOTREACHED*/
      default:
	ExitString("printring: unknown format character.\n", 1);
	/*NOTREACHED*/
      }
    } 
    else {
      *ptr++ = i;
    }
  }
  ring->supply_data(buffer, ptr-buffer);
}
#endif

/*
 * These routines are in charge of sending option negotiations
 * to the other side.
 *
 * The basic idea is that we send the negotiation if either side
 * is in disagreement as to what the current state should be.
 */

void send_do(int c, int init) {
  if (init) {
    if (((do_dont_resp[c] == 0) && my_state_is_do(c)) ||
	my_want_state_is_do(c))
      return;
    set_my_want_state_do(c);
    do_dont_resp[c]++;
  }
  NET2ADD(IAC, DO);
  NETADD(c);
  printoption("SENT", DO, c);
}

void send_dont(int c, int init) {
  if (init) {
    if (((do_dont_resp[c] == 0) && my_state_is_dont(c)) ||
	my_want_state_is_dont(c))
      return;
    set_my_want_state_dont(c);
    do_dont_resp[c]++;
  }
  NET2ADD(IAC, DONT);
  NETADD(c);
  printoption("SENT", DONT, c);
}

void send_will(int c, int init) {
  if (init) {
    if (((will_wont_resp[c] == 0) && my_state_is_will(c)) ||
	my_want_state_is_will(c))
      return;
    set_my_want_state_will(c);
    will_wont_resp[c]++;
  }
  NET2ADD(IAC, WILL);
  NETADD(c);
  printoption("SENT", WILL, c);
}

void send_wont(int c, int init) {
  if (init) {
    if (((will_wont_resp[c] == 0) && my_state_is_wont(c)) ||
	my_want_state_is_wont(c))
      return;
    set_my_want_state_wont(c);
    will_wont_resp[c]++;
  }
  NET2ADD(IAC, WONT);
  NETADD(c);
  printoption("SENT", WONT, c);
}


void willoption(int option) {
  int new_state_ok = 0;
  
  if (do_dont_resp[option]) {
    --do_dont_resp[option];
    if (do_dont_resp[option] && my_state_is_do(option))
      --do_dont_resp[option];
  }
  
  if ((do_dont_resp[option] == 0) && my_want_state_is_dont(option)) {
    switch (option) {
    case TELOPT_ECHO:
#if defined(TN3270)
      /*
       * The following is a pain in the rear-end.
       * Various IBM servers (some versions of Wiscnet,
       * possibly Fibronics/Spartacus, and who knows who
       * else) will NOT allow us to send "DO SGA" too early
       * in the setup proceedings.  On the other hand,
       * 4.2 servers (telnetd) won't set SGA correctly.
       * So, we are stuck.  Empirically (but, based on
       * a VERY small sample), the IBM servers don't send
       * out anything about ECHO, so we postpone our sending
       * "DO SGA" until we see "WILL ECHO" (which 4.2 servers
       * DO send).
       */
      {
	if (askedSGA == 0) {
	  askedSGA = 1;
	  if (my_want_state_is_dont(TELOPT_SGA))
	    send_do(TELOPT_SGA, 1);
	}
      }
      /* Fall through */
    case TELOPT_EOR:
#endif /* TN3270 */
    case TELOPT_BINARY:
    case TELOPT_SGA:
      settimer(modenegotiated);
      /* FALL THROUGH */
    case TELOPT_STATUS:
      new_state_ok = 1;
      break;
      
    case TELOPT_TM:
      if (flushout)
	flushout = 0;
      /*
       * Special case for TM.  If we get back a WILL,
       * pretend we got back a WONT.
       */
      set_my_want_state_dont(option);
      set_my_state_dont(option);
      return;			/* Never reply to TM will's/wont's */
      
    case TELOPT_LINEMODE:
    default:
      break;
    }
    
    if (new_state_ok) {
      set_my_want_state_do(option);
      send_do(option, 0);
      setconnmode(0);		/* possibly set new tty mode */
    } 
    else {
      do_dont_resp[option]++;
      send_dont(option, 0);
    }
  }
  set_my_state_do(option);
}

void wontoption(int option) {
  if (do_dont_resp[option]) {
    --do_dont_resp[option];
    if (do_dont_resp[option] && my_state_is_dont(option))
      --do_dont_resp[option];
  }
  
  if ((do_dont_resp[option] == 0) && my_want_state_is_do(option)) {
    
    switch (option) {
      
#ifdef	KLUDGELINEMODE
    case TELOPT_SGA:
      if (!kludgelinemode)
	break;
      /* FALL THROUGH */
#endif
    case TELOPT_ECHO:
      settimer(modenegotiated);
      break;
      
    case TELOPT_TM:
      if (flushout)
	flushout = 0;
      set_my_want_state_dont(option);
      set_my_state_dont(option);
      return;		/* Never reply to TM will's/wont's */
      
    default:
      break;
    }
    set_my_want_state_dont(option);
    if (my_state_is_do(option))
      send_dont(option, 0);
    setconnmode(0);			/* Set new tty mode */
  } 
  else if (option == TELOPT_TM) {
    /*
     * Special case for TM.
     */
    if (flushout)
      flushout = 0;
    set_my_want_state_dont(option);
  }
  set_my_state_dont(option);
}

static void dooption(int option) {
  int new_state_ok = 0;
  
  if (will_wont_resp[option]) {
    --will_wont_resp[option];
    if (will_wont_resp[option] && my_state_is_will(option))
      --will_wont_resp[option];
  }
  
  if (will_wont_resp[option] == 0) {
    if (my_want_state_is_wont(option)) {
      
      switch (option) {
	
      case TELOPT_TM:
	/*
	 * Special case for TM.  We send a WILL, but pretend
	 * we sent WONT.
	 */
	send_will(option, 0);
	set_my_want_state_wont(TELOPT_TM);
	set_my_state_wont(TELOPT_TM);
	return;
	
#	if defined(TN3270)
      case TELOPT_EOR:		/* end of record */
#	endif	/* defined(TN3270) */
      case TELOPT_BINARY:		/* binary mode */
      case TELOPT_NAWS:		/* window size */
      case TELOPT_TSPEED:		/* terminal speed */
      case TELOPT_LFLOW:		/* local flow control */
      case TELOPT_TTYPE:		/* terminal type option */
      case TELOPT_SGA:		/* no big deal */
      case TELOPT_ENVIRON:	/* environment variable option */
	new_state_ok = 1;
	break;
	
      case TELOPT_XDISPLOC:	/* X Display location */
	if (env_getvalue("DISPLAY", 0))
	  new_state_ok = 1;
	break;
	
      case TELOPT_LINEMODE:
#ifdef	KLUDGELINEMODE
	kludgelinemode = 0;
	send_do(TELOPT_SGA, 1);
#endif
	set_my_want_state_will(TELOPT_LINEMODE);
	send_will(option, 0);
	set_my_state_will(TELOPT_LINEMODE);
	slc_init();
	return;
	
      case TELOPT_ECHO:		/* We're never going to echo... */
      default:
	break;
      }
      
      if (new_state_ok) {
	set_my_want_state_will(option);
	send_will(option, 0);
	setconnmode(0);			/* Set new tty fmode */
      } 
      else {
	will_wont_resp[option]++;
	send_wont(option, 0);
      }
    } 
    else {
      /*
       * Handle options that need more things done after the
       * other side has acknowledged the option.
       */
      switch (option) {
      case TELOPT_LINEMODE:
#ifdef	KLUDGELINEMODE
	kludgelinemode = 0;
	send_do(TELOPT_SGA, 1);
#endif
	set_my_state_will(option);
	slc_init();
	send_do(TELOPT_SGA, 0);
	return;
      }
    }
  }
  set_my_state_will(option);
}

static void dontoption(int option) {
  if (will_wont_resp[option]) {
    --will_wont_resp[option];
    if (will_wont_resp[option] && my_state_is_wont(option))
      --will_wont_resp[option];
  }
  
  if ((will_wont_resp[option] == 0) && my_want_state_is_will(option)) {
    switch (option) {
    case TELOPT_LINEMODE:
      linemode = 0;	/* put us back to the default state */
      break;
    }
    /* we always accept a DONT */
    set_my_want_state_wont(option);
    if (my_state_is_will(option))
      send_wont(option, 0);
    setconnmode(0);			/* Set new tty mode */
  }
  set_my_state_wont(option);
}

/*
 * Given a buffer returned by tgetent(), this routine will turn
 * the pipe seperated list of names in the buffer into an array
 * of pointers to null terminated names.  We toss out any bad,
 * duplicate, or verbose names (names with spaces).
 */

typedef ptrarray<const char> stringarray;

static int is_unique(const char *name, const stringarray &ar) {
  for (int i=0; i<ar.num(); i++) if (!strcasecmp(ar[i], name)) return 0;
  return 1;
}

static void mklist(char *buf, const char *name, stringarray &fill) {
  char *cp; 
  
  fill.setsize(0);
  cp = strchr(buf, ':');
  if (cp) *cp = 0;
  for (cp = strtok(buf, "|:"); cp; cp = strtok(NULL, "|:")) {
    /*
     * Skip entries longer than 40 characters.
     * Skip entries with spaces or non-ascii values.
     * Convert lower case letters to upper case.
     */
    if (strlen(cp)>40) continue;
    int bad = 0;
    for (int i=0; cp[i]; i++) if (!isascii(cp[i]) || cp[i]==' ') bad=1;
    if (bad) continue;
    upcase(cp);
    if (is_unique(cp, fill)) fill.add(cp);
  }
  
  /*
   * Move the name we were passed to the beginning if it's not already
   * there.
   */
  for (int j=1; j<fill.num(); j++) if (!strcasecmp(name, fill[j])) {
    const char *temp = fill[j];
    fill[j] = fill[0];
    fill[0] = temp;
  }
  
  /*
   * Check for an old V6 2 character name. If present,
   * move it to the end of the array.
   */
  for (int k=1; k<fill.num()-1; k++) {
    if (strlen(fill[k])==2 && fill[k]==buf) {
      const char *temp = fill[fill.num()-1];
      fill[fill.num()-1] = fill[k];
      fill[k] = temp;
    }
  }
  
  /*
   * If we got nothing, add in what we were passed
   */
  if (fill.num()==0) {
    if (name && strlen(name)<40) fill.add(name);
    else fill.add("UNKNOWN");
  }
  
  /*
   * Duplicate last name, for TTYPE option, and null
   * terminate the array.  If we didn't find a match on
   * our terminal name, put that name at the beginning.
   */
  
  fill.add(fill[fill.num()-1]);

  /* dholland 21-May-2000 I think this is bogus */
  /*fill.add(NULL);*/
}

char termbuf[2048];

static int my_setupterm(const char *tname, int /*fd*/, int *errp) {
  if (tgetent(termbuf, tname) == 1) {
    /* its Sun Mar 15 00:03:36 PST 1998 this could never have worked with
     * ncurses.  The ncurses tgetent() ignores its first parameter
     */
    
#ifndef USE_NCURSES
    termbuf[1023] = '\0';
#else
    strncpy(termbuf, CUR term_names, sizeof(termbuf));
#endif
    
    if (errp)
      *errp = 1;
    return 0;
  }
  if (errp) *errp = 0;
  return -1;
}

int resettermname = 1;

static const char *gettermname(void) {
  static stringarray termtypes;
  static int next;
  
  const char *tname;
  int err;
  
  if (resettermname) {
    resettermname = 0;
    tname = env_getvalue("TERM", 0);
    if (!tname || my_setupterm(tname, 1, &err)) {
      termbuf[0] = 0;
      tname = "UNKNOWN";
    }
    mklist(termbuf, tname, termtypes);
    next = 0;
  }
  if (next==termtypes.num()-1) next = 0;
  return termtypes[next++];
}
/*
 * suboption()
 *
 *	Look at the sub-option buffer, and try to be helpful to the other
 * side.
 *
 *	Currently we recognize:
 *
 *		Terminal type, send request.
 *		Terminal speed (send request).
 *		Local flow control (is request).
 *		Linemode
 */

static void suboption(void) {
  printsub('<', subbuffer, SB_LEN()+2);
  switch (SB_GET()) {
  case TELOPT_TTYPE:
    if (my_want_state_is_wont(TELOPT_TTYPE))
      return;
    if (SB_EOF() || SB_GET() != TELQUAL_SEND) {
      return;
    } 
    else {
      const char *name;
      
#if defined(TN3270)
      if (tn3270_ttype()) {
	return;
      }
#endif /* TN3270 */
      name = gettermname();
      netoring.xprintf("%c%c%c%c%s%c%c", IAC, SB, TELOPT_TTYPE,
		      TELQUAL_IS, name, IAC, SE);
    }
    break;
  case TELOPT_TSPEED:
    if (my_want_state_is_wont(TELOPT_TSPEED))
      return;
    if (SB_EOF())
      return;
    if (SB_GET() == TELQUAL_SEND) {
      long oospeed, iispeed;
      TerminalSpeeds(&iispeed, &oospeed);
      netoring.xprintf("%c%c%c%c%ld,%ld%c%c", IAC, SB, TELOPT_TSPEED, 
		      TELQUAL_IS, oospeed, iispeed, IAC, SE);
    }
    break;
  case TELOPT_LFLOW:
    if (my_want_state_is_wont(TELOPT_LFLOW))
      return;
    if (SB_EOF())
      return;
    switch(SB_GET()) {
    case 1:
      localflow = 1;
      break;
    case 0:
      localflow = 0;
      break;
    default:
      return;
    }
    setcommandmode();
    setconnmode(0);
    break;
    
  case TELOPT_LINEMODE:
    if (my_want_state_is_wont(TELOPT_LINEMODE))
      return;
    if (SB_EOF())
      return;
    switch (SB_GET()) {
    case WILL:
      lm_will(subpointer, SB_LEN());
      break;
    case WONT:
      lm_wont(subpointer, SB_LEN());
      break;
    case DO:
      lm_do(subpointer, SB_LEN());
      break;
    case DONT:
      lm_dont(subpointer, SB_LEN());
      break;
    case LM_SLC:
      slc(subpointer, SB_LEN());
      break;
    case LM_MODE:
      lm_mode(subpointer, SB_LEN(), 0);
      break;
    default:
      break;
    }
    break;
    
  case TELOPT_ENVIRON:
    if (SB_EOF())
      return;
    switch(SB_PEEK()) {
    case TELQUAL_IS:
    case TELQUAL_INFO:
      if (my_want_state_is_dont(TELOPT_ENVIRON))
	return;
      break;
    case TELQUAL_SEND:
      if (my_want_state_is_wont(TELOPT_ENVIRON)) {
	return;
      }
      break;
    default:
      return;
    }
    env_opt(subpointer, SB_LEN());
    break;
    
  case TELOPT_XDISPLOC:
    if (my_want_state_is_wont(TELOPT_XDISPLOC))
      return;
    if (SB_EOF())
      return;
    if (SB_GET() == TELQUAL_SEND) {
      const char *dp = env_getvalue("DISPLAY", 0);
      if (dp == NULL) {
	/*
	 * Something happened, we no longer have a DISPLAY
	 * variable.  So, turn off the option.
	 */
	send_wont(TELOPT_XDISPLOC, 1);
	break;
      }
      netoring.xprintf("%c%c%c%c%s%c%c", IAC, SB, TELOPT_XDISPLOC,
		      TELQUAL_IS, dp, IAC, SE);
    }
    break;
    
  default:
    break;
  }
}

//static char str_lm[] = { IAC, SB, TELOPT_LINEMODE, 0, 0, IAC, SE };

void lm_will(unsigned char *cmd, int len) {
  if (len < 1) {
    /*@*/	printf("lm_will: no command!!!\n");	/* Should not happen... */
    return;
  }
  
  netoring.xprintf("%c%c%c%c%c%c%c", IAC, SB, TELOPT_LINEMODE, 
		  DONT, cmd[0], IAC, SE);
}

void lm_wont(unsigned char * /*cmd*/, int len) {
  if (len < 1) {
    /*@*/	printf("lm_wont: no command!!!\n");	/* Should not happen... */
    return;
  }
  /* We are always DONT, so don't respond */
}

void lm_do(unsigned char *cmd, int len) {
  if (len < 1) {
    /*@*/	printf("lm_do: no command!!!\n");	/* Should not happen... */
    return;
  }
  netoring.xprintf("%c%c%c%c%c%c%c", IAC, SB, TELOPT_LINEMODE, 
		  WONT, cmd[0], IAC, SE);
}

void lm_dont(unsigned char * /*cmd*/, int len) {
  if (len < 1) {
    /*@*/	printf("lm_dont: no command!!!\n");	/* Should not happen... */
    return;
  }
  /* we are always WONT, so don't respond */
}

void lm_mode(unsigned char *cmd, int len, int init) {
  if (len != 1) return;
  if ((linemode&MODE_MASK&~MODE_ACK) == *cmd) return;
  if (*cmd&MODE_ACK) return;
  
  linemode = *cmd&(MODE_MASK&~MODE_ACK);
  int k = linemode;
  if (!init) {
    k |= MODE_ACK;
  }
  
  netoring.xprintf("%c%c%c%c%c%c%c", IAC, SB, TELOPT_LINEMODE, LM_MODE,
		  k, IAC, SE);
  
  setconnmode(0);	/* set changed mode */
}


/*
 * slc()
 * Handle special character suboption of LINEMODE.
 */

struct spc {
  cc_t val;
  cc_t *valp;
  char flags;	/* Current flags & level */
  char mylevel;	/* Maximum level & flags */
} spc_data[NSLC+1];

#define SLC_IMPORT	0
#define	SLC_EXPORT	1
#define SLC_RVALUE	2
static int slc_mode = SLC_EXPORT;

void slc_init(void) {
  register struct spc *spcp;
  
  localchars = 1;
  for (spcp = spc_data; spcp < &spc_data[NSLC+1]; spcp++) {
    spcp->val = 0;
    spcp->valp = 0;
    spcp->flags = spcp->mylevel = SLC_NOSUPPORT;
  }
  
#define	initfunc(func, flags) { \
							    spcp = &spc_data[func]; \
										      if ((spcp->valp = tcval(func))) { \
															  spcp->val = *spcp->valp; \
																		     spcp->mylevel = SLC_VARIABLE|flags; \
																							   } else { \
																								      spcp->val = 0; \
																										       spcp->mylevel = SLC_DEFAULT; \
																														      } \
																															  }
  
  initfunc(SLC_SYNCH, 0);
  /* No BRK */
  initfunc(SLC_AO, 0);
  initfunc(SLC_AYT, 0);
  /* No EOR */
  initfunc(SLC_ABORT, SLC_FLUSHIN|SLC_FLUSHOUT);
  initfunc(SLC_EOF, 0);
  initfunc(SLC_SUSP, SLC_FLUSHIN);
  
  initfunc(SLC_EC, 0);
  initfunc(SLC_EL, 0);
  
  initfunc(SLC_XON, 0);
  initfunc(SLC_XOFF, 0);
  
  initfunc(SLC_FORW1, 0);
  initfunc(SLC_FORW2, 0);
  /* No FORW2 */
  
  initfunc(SLC_IP, SLC_FLUSHIN|SLC_FLUSHOUT);
#undef	initfunc
  
  if (slc_mode == SLC_EXPORT)
    slc_export();
  else
    slc_import(1);
  
}

void slcstate(void) {
  printf("Special characters are %s values\n",
	 slc_mode == SLC_IMPORT ? "remote default" :
	 slc_mode == SLC_EXPORT ? "local" :
	 "remote");
}

void slc_mode_export(void) {
  slc_mode = SLC_EXPORT;
  if (my_state_is_will(TELOPT_LINEMODE))
    slc_export();
}

void slc_mode_import(int def) {
  slc_mode = def ? SLC_IMPORT : SLC_RVALUE;
  if (my_state_is_will(TELOPT_LINEMODE))
    slc_import(def);
}

void slc_import(int def) {
  if (def) {
    netoring.xprintf("%c%c%c%c%c%c%c%c%c", IAC, SB, TELOPT_LINEMODE,
		    LM_SLC, 0, SLC_DEFAULT, 0, IAC, SE);
  }
  else {
    netoring.xprintf("%c%c%c%c%c%c%c%c%c", IAC, SB, TELOPT_LINEMODE,
		    LM_SLC, 0, SLC_VARIABLE, 0, IAC, SE);
  }
}

void slc_export(void) {
  register struct spc *spcp;
  
  TerminalDefaultChars();
  
  slc_start_reply();
  for (spcp = &spc_data[1]; spcp < &spc_data[NSLC+1]; spcp++) {
    if (spcp->mylevel != SLC_NOSUPPORT) {
      if (spcp->val == (cc_t)(_POSIX_VDISABLE))
	spcp->flags = SLC_NOSUPPORT;
      else
	spcp->flags = spcp->mylevel;
      if (spcp->valp)
	spcp->val = *spcp->valp;
      slc_add_reply(spcp - spc_data, spcp->flags, spcp->val);
    }
  }
  slc_end_reply();
  (void)slc_update();
  setconnmode(1);	/* Make sure the character values are set */
}

void slc(unsigned char *cp, int len) {
  register struct spc *spcp;
  register int func,level;
  
  slc_start_reply();
  
  for (; len >= 3; len -=3, cp +=3) {
    
    func = cp[SLC_FUNC];
    
    if (func == 0) {
      /*
       * Client side: always ignore 0 function.
       */
      continue;
    }
    if (func > NSLC) {
      if ((cp[SLC_FLAGS] & SLC_LEVELBITS) != SLC_NOSUPPORT)
	slc_add_reply(func, SLC_NOSUPPORT, 0);
      continue;
    }
    
    spcp = &spc_data[func];
    
    level = cp[SLC_FLAGS]&(SLC_LEVELBITS|SLC_ACK);
    
    if ((cp[SLC_VALUE] == spcp->val) &&
	((level&SLC_LEVELBITS) == (spcp->flags&SLC_LEVELBITS))) {
      continue;
    }
    
    if (level == (SLC_DEFAULT|SLC_ACK)) {
      /*
       * This is an error condition, the SLC_ACK
       * bit should never be set for the SLC_DEFAULT
       * level.  Our best guess to recover is to
       * ignore the SLC_ACK bit.
       */
      cp[SLC_FLAGS] &= ~SLC_ACK;
    }
    
    if (level == ((spcp->flags&SLC_LEVELBITS)|SLC_ACK)) {
      spcp->val = (cc_t)cp[SLC_VALUE];
      spcp->flags = cp[SLC_FLAGS];	/* include SLC_ACK */
      continue;
    }
    
    level &= ~SLC_ACK;
    
    if (level <= (spcp->mylevel&SLC_LEVELBITS)) {
      spcp->flags = cp[SLC_FLAGS]|SLC_ACK;
      spcp->val = (cc_t)cp[SLC_VALUE];
    }
    if (level == SLC_DEFAULT) {
      if ((spcp->mylevel&SLC_LEVELBITS) != SLC_DEFAULT)
	spcp->flags = spcp->mylevel;
      else
	spcp->flags = SLC_NOSUPPORT;
    }
    slc_add_reply(func, spcp->flags, spcp->val);
  }
  slc_end_reply();
  if (slc_update())
    setconnmode(1);	/* set the  new character values */
}

void slc_check(void) {
  register struct spc *spcp;
  
  slc_start_reply();
  for (spcp = &spc_data[1]; spcp < &spc_data[NSLC+1]; spcp++) {
    if (spcp->valp && spcp->val != *spcp->valp) {
      spcp->val = *spcp->valp;
      if (spcp->val == (cc_t)(_POSIX_VDISABLE))
	spcp->flags = SLC_NOSUPPORT;
      else
	spcp->flags = spcp->mylevel;
      slc_add_reply(spcp - spc_data, spcp->flags, spcp->val);
    }
  }
  slc_end_reply();
  setconnmode(1);
}


unsigned char slc_reply[128];
unsigned char *slc_replyp;

void slc_start_reply(void) {
  slc_replyp = slc_reply;
  *slc_replyp++ = IAC;
  *slc_replyp++ = SB;
  *slc_replyp++ = TELOPT_LINEMODE;
  *slc_replyp++ = LM_SLC;
}

void slc_add_reply(int func, int flags, int value) {
  if ((*slc_replyp++ = func) == IAC)
    *slc_replyp++ = IAC;
  if ((*slc_replyp++ = flags) == IAC)
    *slc_replyp++ = IAC;
  if ((*slc_replyp++ = value) == IAC)
    *slc_replyp++ = IAC;
}

void slc_end_reply(void) {
  register int len;
  
  *slc_replyp++ = IAC;
  *slc_replyp++ = SE;
  len = slc_replyp - slc_reply;
  if (len <= 6) return;
  
  printsub('>', &slc_reply[2], len - 2);
  netoring.write((char *)slc_reply, len);
}

int slc_update(void) {
  struct spc *spcp;
  int need_update = 0;
  
  for (spcp = &spc_data[1]; spcp < &spc_data[NSLC+1]; spcp++) {
    if (!(spcp->flags&SLC_ACK))
      continue;
    spcp->flags &= ~SLC_ACK;
    if (spcp->valp && (*spcp->valp != spcp->val)) {
      *spcp->valp = spcp->val;
      need_update = 1;
    }
  }
  return(need_update);
}

void env_opt(unsigned char *buf, int len) {
  unsigned char *ep = 0, *epc = 0;
  int i;
  
  switch(buf[0]) {
  case TELQUAL_SEND:
    env_opt_start();
    if (len == 1) {
      env_opt_add(NULL);
    } 
    else for (i = 1; i < len; i++) {
      switch (buf[i]) {
      case ENV_VALUE:
	if (ep) {
	  *epc = 0;
	  env_opt_add((const char *)ep);
	}
	ep = epc = &buf[i+1];
	break;
      case ENV_ESC:
	i++;
				/*FALL THROUGH*/
      default:
	if (epc)
	  *epc++ = buf[i];
	break;
      }
      if (ep) {
	*epc = 0;
	env_opt_add((const char *)ep);
      }
    }
    env_opt_end(1);
    break;
    
  case TELQUAL_IS:
  case TELQUAL_INFO:
    /* Ignore for now.  We shouldn't get it anyway. */
    break;
    
  default:
    break;
  }
}

/* OPT_REPLY_SIZE must be a multiple of 2. */
#define	OPT_REPLY_SIZE	256
unsigned char *opt_reply;
unsigned char *opt_replyp;
unsigned char *opt_replyend;

void env_opt_start(void) {
  if (opt_reply)
    opt_reply = (unsigned char *)realloc(opt_reply, OPT_REPLY_SIZE);
  else
    opt_reply = (unsigned char *)malloc(OPT_REPLY_SIZE);
  if (opt_reply == NULL) {
    /*@*/		printf("env_opt_start: malloc()/realloc() failed!!!\n");
    opt_reply = opt_replyp = opt_replyend = NULL;
    return;
  }
  opt_replyp = opt_reply;
  opt_replyend = opt_reply + OPT_REPLY_SIZE;
  *opt_replyp++ = IAC;
  *opt_replyp++ = SB;
  *opt_replyp++ = TELOPT_ENVIRON;
  *opt_replyp++ = TELQUAL_IS;
}

void env_opt_start_info(void) {
  env_opt_start();
  if (opt_replyp)
    opt_replyp[-1] = TELQUAL_INFO;
}

void env_opt_add(const char *ep) {
  const char *vp;
  const unsigned char *tp;
  unsigned char c;
  
  if (opt_reply == NULL)		/*XXX*/
    return;			/*XXX*/
  
  if (ep == NULL || *ep == '\0') {
    int i;
    env_iterate(&i, 1);
    for (ep = env_next(&i,1); ep; ep = env_next(&i,1)) env_opt_add(ep);
    return;
  }
  vp = env_getvalue(ep, 1);
  tp = opt_replyp + (vp ? strlen(vp) * 2 : 0) + strlen(ep) * 2 + 6;
  if (tp > opt_replyend)
    {
      register int len;
      len = ((tp - opt_reply) + OPT_REPLY_SIZE - 1) & ~(OPT_REPLY_SIZE - 1);
      opt_replyend = opt_reply + len;
      opt_reply = (unsigned char *)realloc(opt_reply, len);
      if (opt_reply == NULL) {
	/*@*/			printf("env_opt_add: realloc() failed!!!\n");
	opt_reply = opt_replyp = opt_replyend = NULL;
	return;
      }
      opt_replyp = opt_reply + len - (opt_replyend - opt_replyp);
      opt_replyend = opt_reply + len;
    }
  *opt_replyp++ = ENV_VAR;
  for (;;) {
    while ((c = *ep++)!=0) {
      switch(c) {
      case IAC:
	*opt_replyp++ = IAC;
	break;
      case ENV_VALUE:
      case ENV_VAR:
      case ENV_ESC:
	*opt_replyp++ = ENV_ESC;
	break;
      }
      *opt_replyp++ = c;
    }
    if ((ep = vp)!=NULL) {
      *opt_replyp++ = ENV_VALUE;
      vp = NULL;
    } else
      break;
  }
}

void env_opt_end(int emptyok) {
  register int len;
  
  len = opt_replyp - opt_reply + 2;
  if (emptyok || len > 6) {
    *opt_replyp++ = IAC;
    *opt_replyp++ = SE;
    printsub('>', &opt_reply[2], len - 2);
    netoring.write((char *)opt_reply, len);
  }
  if (opt_reply) {
    free(opt_reply);
    opt_reply = opt_replyp = opt_replyend = NULL;
  }
}


int telrcv(void) {
  int c;
  int returnValue = 0;
  
  while (TTYROOM() > 2) {
    if (!netiring.getch(&c)) {
      /* No more data coming in */
      break;
    }
    returnValue = 1;
    
    switch (telrcv_state) {
    case TS_CR:
      telrcv_state = TS_DATA;
      if (c == '\0') {
	break;	/* Ignore \0 after CR */
      }
      else if ((c == '\n') && 
	       my_want_state_is_dont(TELOPT_ECHO) && 
	       !crmod) 
	{
	  TTYADD(c);
	  break;
	}
      /* Else, fall through */
      
    case TS_DATA:
      if (c == IAC) {
	telrcv_state = TS_IAC;
	break;
      }
#if defined(TN3270)
      if (In3270) {
	*Ifrontp++ = c;
	while (netiring.getch(&c)) {
	  if (c == IAC) {
	    telrcv_state = TS_IAC;
	    break;
	  }
	  *Ifrontp++ = c;
	}
      } else
#endif /* defined(TN3270) */
	/*
	 * The 'crmod' hack (see following) is needed
	 * since we can't * set CRMOD on output only.
	 * Machines like MULTICS like to send \r without
	 * \n; since we must turn off CRMOD to get proper
	 * input, the mapping is done here (sigh).
	 */
	if ((c == '\r') && my_want_state_is_dont(TELOPT_BINARY)) {
	  if (netiring.getch(&c)) {
	    if (c == 0) {
	      /* a "true" CR */
	      TTYADD('\r');
	    } 
	    else if (my_want_state_is_dont(TELOPT_ECHO) &&
		     (c == '\n')) {
	      TTYADD('\n');
	    } 
	    else {
	      netiring.ungetch(c);
	      TTYADD('\r');
	      if (crmod) TTYADD('\n');
	    }
	  } 
	  else {
	    telrcv_state = TS_CR;
	    TTYADD('\r');
	    if (crmod) TTYADD('\n');
	  }
	} 
	else {
	  TTYADD(c);
	}
      continue;
      
    case TS_IAC:
    process_iac:
    switch (c) {
    case WILL:
      telrcv_state = TS_WILL;
      continue;
    case WONT:
      telrcv_state = TS_WONT;
      continue;
    case DO:
      telrcv_state = TS_DO;
      continue;
    case DONT:
      telrcv_state = TS_DONT;
      continue;
    case DM:
      /*
       * We may have missed an urgent notification,
       * so make sure we flush whatever is in the
       * buffer currently.
       */
      printoption("RCVD", IAC, DM);
      SYNCHing = 1;
      ttyflush(1);
      SYNCHing = nlink.stilloob();
      settimer(gotDM);
      break;
    case SB:
      SB_CLEAR();
      telrcv_state = TS_SB;
      continue;
      
#if defined(TN3270)
    case EOR:
      if (In3270) {
	if (Ibackp == Ifrontp) {
	  Ibackp = Ifrontp = Ibuf;
	  ISend = 0;	/* should have been! */
	} 
	else {
	  Ibackp += DataFromNetwork(Ibackp, Ifrontp-Ibackp, 1);
	  ISend = 1;
	}
      }
      printoption("RCVD", IAC, EOR);
      break;
#endif /* defined(TN3270) */
      
    case IAC:
#if !defined(TN3270)
      TTYADD(IAC);
#else /* !defined(TN3270) */
      if (In3270) {
	*Ifrontp++ = IAC;
      } 
      else {
	TTYADD(IAC);
      }
#endif /* !defined(TN3270) */
      break;
      
    case NOP:
    case GA:
    default:
      printoption("RCVD", IAC, c);
      break;
    }
    telrcv_state = TS_DATA;
    continue;
    
    case TS_WILL:
      printoption("RCVD", WILL, c);
      willoption(c);
      SetIn3270();
      telrcv_state = TS_DATA;
      continue;
      
    case TS_WONT:
      printoption("RCVD", WONT, c);
      wontoption(c);
      SetIn3270();
      telrcv_state = TS_DATA;
      continue;
      
    case TS_DO:
      printoption("RCVD", DO, c);
      dooption(c);
      SetIn3270();
      if (c == TELOPT_NAWS) {
	sendnaws();
      } 
      else if (c == TELOPT_LFLOW) {
	localflow = 1;
	setcommandmode();
	setconnmode(0);
      }
      telrcv_state = TS_DATA;
      continue;
      
    case TS_DONT:
      printoption("RCVD", DONT, c);
      dontoption(c);
      flushline = 1;
      setconnmode(0);	/* set new tty mode (maybe) */
      SetIn3270();
      telrcv_state = TS_DATA;
      continue;
      
    case TS_SB:
      if (c == IAC) {
	telrcv_state = TS_SE;
      } 
      else {
	SB_ACCUM(c);
      }
      continue;
      
    case TS_SE:
      if (c != SE) {
	if (c != IAC) {
	  /*
	   * This is an error.  We only expect to get
	   * "IAC IAC" or "IAC SE".  Several things may
	   * have happend.  An IAC was not doubled, the
	   * IAC SE was left off, or another option got
	   * inserted into the suboption are all possibilities.
	   * If we assume that the IAC was not doubled,
	   * and really the IAC SE was left off, we could
	   * get into an infinate loop here.  So, instead,
	   * we terminate the suboption, and process the
	   * partial suboption if we can.
	   */
	  SB_ACCUM(IAC);
	  SB_ACCUM(c);
	  subpointer -= 2;
	  SB_TERM();
	  
	  printoption("In SUBOPTION processing, RCVD", IAC, c);
	  suboption();	/* handle sub-option */
	  SetIn3270();
	  telrcv_state = TS_IAC;
	  goto process_iac;
	}
	SB_ACCUM(c);
	telrcv_state = TS_SB;
      } 
      else {
	SB_ACCUM(IAC);
	SB_ACCUM(SE);
	subpointer -= 2;
	SB_TERM();
	suboption();	/* handle sub-option */
	SetIn3270();
	telrcv_state = TS_DATA;
      }
    }
    
  }
  return returnValue;
}

static int bol = 1, local = 0;

int rlogin_susp(void) {
  if (local) {
    local = 0;
    bol = 1;
    command(0, "z\n", 2);
    return(1);
  }
  return(0);
}

static int telsnd(void) {
  //    int tcc;
  //    int count;
  int returnValue = 0;
  //    const char *tbp = NULL;
  
  //    tcc = 0;
  //    count = 0;
  while (netoring.empty_count() > 2) {
    int c, sc;
    
    if (!ttyiring.getch(&c)) {
      break;
    }
    returnValue = 1;
    
    sc = strip(c);
    
    if (rlogin != _POSIX_VDISABLE) {
      if (bol) {
	bol = 0;
	if (sc == rlogin) {
	  local = 1;
	  continue;
	}
      } 
      else if (local) {
	local = 0;
	if (sc == '.' || c == termEofChar) {
	  bol = 1;
	  command(0, "close\n", 6);
	  continue;
	}
	if (sc == termSuspChar) {
	  bol = 1;
	  command(0, "z\n", 2);
	  continue;
	}
	if (sc == escapechar && escapechar !=_POSIX_VDISABLE) {
	  int l;
	  char buf[128];
	  l = ttyiring.gets(buf, sizeof(buf));
	  command(0, buf, l);
	  bol = 1;
	  flushline = 1;
	  break;
	}
	if (sc != rlogin) {
	  ttyiring.ungetch(c);
	  c = sc = rlogin;
	}
      }
      if ((sc == '\n') || (sc == '\r'))
	bol = 1;
    } 
    else if (sc == escapechar && escapechar != _POSIX_VDISABLE) {
      int ignore = 0;
      /*
       * Double escape is a pass through of a single escape character.
       */
      if (ttyiring.getch(&c)) {
	if (strip(c) != escapechar) ttyiring.ungetch(c);
	else {
	  bol = 0;
	  ignore = 1;
	}
      } 
      if (!ignore) {
	int l;
	char buf[128];
	l = ttyiring.gets(buf, sizeof(buf));
	command(0, buf, l);
	bol = 1;
	flushline = 1;
	break;
      }
    } 
    else {
      bol = 0;
    }
#ifdef	KLUDGELINEMODE
    if (kludgelinemode && (globalmode&MODE_EDIT) && (sc == echoc)) {
      int ignore=0;
      if (ttyiring.getch(&c) > 0) {
	if (strip(c) != echoc) ttyiring.ungetch(c);
	else ignore=1;
      } 
      if (!ignore) {
	dontlecho = !dontlecho;
	settimer(echotoggle);
	setconnmode(0);
	flushline = 1;
	break;
      }
    }
#endif
    if (MODE_LOCAL_CHARS(globalmode)) {
      if (TerminalSpecialChars(sc) == 0) {
	bol = 1;
	break;
      }
    }
    if (my_want_state_is_wont(TELOPT_BINARY)) {
      switch (c) {
      case '\n':
	/*
	 * If we are in CRMOD mode (\r ==> \n)
	 * on our local machine, then probably
	 * a newline (unix) is CRLF (TELNET).
	 */
	if (MODE_LOCAL_CHARS(globalmode)) {
	  NETADD('\r');
	}
	NETADD('\n');
	bol = flushline = 1;
	break;
      case '\r':
	if (!crlf) {
	  NET2ADD('\r', '\0');
	} 
	else {
	  NET2ADD('\r', '\n');
	}
	bol = flushline = 1;
	break;
      case IAC:
	NET2ADD(IAC, IAC);
	break;
      default:
	NETADD(c);
	break;
      }
    } 
    else if (c == IAC) {
      NET2ADD(IAC, IAC);
    } 
    else {
      NETADD(c);
    }
  }
  
  return returnValue;		/* Non-zero if we did anything */
}

/*
 * Scheduler()
 *
 * Try to do something.
 *
 * If we do something useful, return 1; else return 0.
 *
 */

/* block: should we block in the select ? */
int Scheduler(int block) {
  /* One wants to be a bit careful about setting returnValue
   * to one, since a one implies we did some useful work,
   * and therefore probably won't be called to block next
   * time (TN3270 mode only).
   */
  int returnValue;
  int netin, netout, netex, ttyin, ttyout;
  
  /* Decide which rings should be processed */
  
  netout = netoring.full_count() &&
    (flushline ||
     (my_want_state_is_wont(TELOPT_LINEMODE)
#ifdef	KLUDGELINEMODE
      && (!kludgelinemode || my_want_state_is_do(TELOPT_SGA))
#endif
      ) ||
     my_want_state_is_will(TELOPT_BINARY));
  ttyout = ttyoring.full_count();
  
#if	defined(TN3270)
  ttyin = ttyiring.empty_count() && (shell_active == 0);
#else	/* defined(TN3270) */
  ttyin = ttyiring.empty_count();
#endif	/* defined(TN3270) */
  
#if defined(TN3270)
  netin = netiring.empty_count();
#else /* !defined(TN3270) */
  netin = !ISend && netiring.empty_count();
#endif /* !defined(TN3270) */
  
  netex = !SYNCHing;
  
  /* If we have seen a signal recently, reset things */
#ifdef TN3270
  if (HaveInput) {
    HaveInput = 0;
    (void) signal(SIGIO, inputAvailable);
  }
#endif	/* TN3270 */
  
  /* Call to system code to process rings */
  
  returnValue = process_rings(netin, netout, netex, ttyin, ttyout, !block);
  
  /* Now, look at the input rings, looking for work to do. */
  
  if (ttyiring.full_count()) {
#if defined(TN3270)
    if (In3270) {
      int c;
      
      c = DataFromTerminal(ttyiring.consume,
			   ring_full_consecutive(&ttyiring));
      if (c) {
	returnValue = 1;
	ring_consumed(&ttyiring, c);
      }
    } else {
#endif /* defined(TN3270) */
      returnValue |= telsnd();
#if defined(TN3270)
    }
#endif /* defined(TN3270) */
  }
  
  if (netiring.full_count()) {
#	if !defined(TN3270)
    returnValue |= telrcv();
#	else /* !defined(TN3270) */
    returnValue = Push3270();
#	endif /* !defined(TN3270) */
  }
  return returnValue;
}

/*
 * Select from tty and network...
 */
void telnet(const char * /*user*/) {
  sys_telnet_init();
  
  
#if !defined(TN3270)
  if (telnetport) {
    send_do(TELOPT_SGA, 1);
    send_will(TELOPT_TTYPE, 1);
    send_will(TELOPT_NAWS, 1);
    send_will(TELOPT_TSPEED, 1);
    send_will(TELOPT_LFLOW, 1);
    send_will(TELOPT_LINEMODE, 1);
    send_will(TELOPT_ENVIRON, 1);
    send_do(TELOPT_STATUS, 1);
    if (env_getvalue("DISPLAY", 0))
      send_will(TELOPT_XDISPLOC, 1);
    if (eight)
      tel_enter_binary(eight);
  }
#endif /* !defined(TN3270) */
  
#if !defined(TN3270)
  for (;;) {
    int schedValue;
    
    while ((schedValue = Scheduler(0)) != 0) {
      if (schedValue == -1) {
	setcommandmode();
	return;
      }
    }
    
    if (Scheduler(1) == -1) {
      setcommandmode();
      return;
    }
  }
#else /* !defined(TN3270) */
  for (;;) {
    int schedValue;
    
    while (!In3270 && !shell_active) {
      if (Scheduler(1) == -1) {
	setcommandmode();
	return;
      }
    }
    
    while ((schedValue = Scheduler(0)) != 0) {
      if (schedValue == -1) {
	setcommandmode();
	return;
      }
    }
    /* If there is data waiting to go out to terminal, don't
     * schedule any more data for the terminal.
     */
    if (ring_full_count(&ttyoring)) {
      schedValue = 1;
    } else {
      if (shell_active) {
	if (shell_continue() == 0) {
	  ConnectScreen();
	}
      } else if (In3270) {
	schedValue = DoTerminalOutput();
      }
    }
    if (schedValue && (shell_active == 0)) {
      if (Scheduler(1) == -1) {
	setcommandmode();
	return;
      }
    }
  }
#endif /* !defined(TN3270) */
}

#if	0	/* XXX - this not being in is a bug */
/*
 * nextitem()
 *
 *	Return the address of the next "item" in the TELNET data
 * stream.  This will be the address of the next character if
 * the current address is a user data character, or it will
 * be the address of the character following the TELNET command
 * if the current address is a TELNET IAC ("I Am a Command")
 * character.
 */

static unsigned char *nextitem(unsigned char *current) {
  if (*current != IAC) {
    return current+1;
  }
  switch (current[1]) {
  case DO:
  case DONT:
  case WILL:
  case WONT:
    return current+3;
  case SB:		/* loop forever looking for the SE */
    {
      unsigned char *look = current+2;
      
      for (;;) {
	if (*look++ == IAC) {
	  if (*look++ == SE) {
	    return look;
	  }
	}
      }
    }
  default:
    return current+2;
  }
}
#endif	/* 0 */

/*
 * netclear()
 *
 *	We are about to do a TELNET SYNCH operation.  Clear
 * the path to the network.
 *
 *	Things are a bit tricky since we may have sent the first
 * byte or so of a previous TELNET command into the network.
 * So, we have to scan the network buffer from the beginning
 * until we are up to where we want to be.
 *
 *	A side effect of what we do, just to keep things
 * simple, is to clear the urgent data pointer.  The principal
 * caller should be setting the urgent data pointer AFTER calling
 * us in any case.
 */

static void netclear(void) {
#if	0	/* XXX */
  register char *thisitem, *next;
  char *good;
#define	wewant(p)	((nfrontp > p) && (*p == IAC) && \
			 (p[1] != EC) && (p[1] != EL))
    
    thisitem = netobuf;
    
    while ((next = nextitem(thisitem)) <= netobuf.send) {
      thisitem = next;
    }
    
    /* Now, thisitem is first before/at boundary. */
    
    good = netobuf;	/* where the good bytes go */
    
    while (netoring.add > thisitem) {
      if (wewant(thisitem)) {
	int length;
	
	next = thisitem;
	do {
	  next = nextitem(next);
	} while (wewant(next) && (nfrontp > next));
	length = next-thisitem;
	memcpy(good, thisitem, length);
	good += length;
	thisitem = next;
      } else {
	thisitem = nextitem(thisitem);
      }
    }
    
#endif	/* 0 */
}

/*
 * These routines add various telnet commands to the data stream.
 */

static void doflush(void) {
  NET2ADD(IAC, DO);
  NETADD(TELOPT_TM);
  flushline = 1;
  flushout = 1;
  (void) ttyflush(1);			/* Flush/drop output */
  /* do printoption AFTER flush, otherwise the output gets tossed... */
  printoption("SENT", DO, TELOPT_TM);
}

void xmitAO(void) {
  NET2ADD(IAC, AO);
  printoption("SENT", IAC, AO);
  if (autoflush) {
    doflush();
  }
}


void xmitEL(void) {
  NET2ADD(IAC, EL);
  printoption("SENT", IAC, EL);
}

void xmitEC(void) {
  NET2ADD(IAC, EC);
  printoption("SENT", IAC, EC);
}


int dosynch(void) {
  netclear();			/* clear the path to the network */
  NETADD(IAC);
  netoring.set_mark();
  NETADD(DM);
  printoption("SENT", IAC, DM);
  return 1;
}

int want_status_response = 0;

int get_status(const char *, const char *) {
  unsigned char tmp[16];
  unsigned char *cp;
  
  if (my_want_state_is_dont(TELOPT_STATUS)) {
    printf("Remote side does not support STATUS option\n");
    return 0;
  }
  cp = tmp;
  
  *cp++ = IAC;
  *cp++ = SB;
  *cp++ = TELOPT_STATUS;
  *cp++ = TELQUAL_SEND;
  *cp++ = IAC;
  *cp++ = SE;
  printsub('>', tmp+2, cp - tmp - 2);
  netoring.write((char *)tmp, cp-tmp);
  ++want_status_response;
  return 1;
}

void intp(void) {
  NET2ADD(IAC, IP);
  printoption("SENT", IAC, IP);
  flushline = 1;
  if (autoflush) {
    doflush();
  }
  if (autosynch) {
    dosynch();
  }
}

void sendbrk(void) {
  NET2ADD(IAC, BREAK);
  printoption("SENT", IAC, BREAK);
  flushline = 1;
  if (autoflush) {
    doflush();
  }
  if (autosynch) {
    dosynch();
  }
}

void sendabort(void) {
  NET2ADD(IAC, ABORT);
  printoption("SENT", IAC, ABORT);
  flushline = 1;
  if (autoflush) {
    doflush();
  }
  if (autosynch) {
    dosynch();
  }
}

void sendsusp(void) {
  NET2ADD(IAC, SUSP);
  printoption("SENT", IAC, SUSP);
  flushline = 1;
  if (autoflush) {
    doflush();
  }
  if (autosynch) {
    dosynch();
  }
}

void sendeof(void) {
  NET2ADD(IAC, xEOF);
  printoption("SENT", IAC, xEOF);
}

void sendayt(void) {
  NET2ADD(IAC, AYT);
  printoption("SENT", IAC, AYT);
}

/*
 * Send a window size update to the remote system.
 */

void sendnaws(void) {
  long rows, cols;
  unsigned char tmp[16];
  unsigned char *cp;
  
  if (my_state_is_wont(TELOPT_NAWS))
    return;
  
#define	PUTSHORT(cp, x) { if ((*cp++ = ((x)>>8)&0xff) == IAC) *cp++ = IAC; \
      if ((*cp++ = ((x))&0xff) == IAC) *cp++ = IAC; }
  
  if (TerminalWindowSize(&rows, &cols) == 0) {	/* Failed */
    return;
  }
  
  cp = tmp;
  
  *cp++ = IAC;
  *cp++ = SB;
  *cp++ = TELOPT_NAWS;
  PUTSHORT(cp, cols);
  PUTSHORT(cp, rows);
  *cp++ = IAC;
  *cp++ = SE;
  printsub('>', tmp+2, cp - tmp - 2);
  netoring.write((char *)tmp, cp-tmp);
}

void tel_enter_binary(int rw) {
  if (rw&1)
    send_do(TELOPT_BINARY, 1);
  if (rw&2)
    send_will(TELOPT_BINARY, 1);
}

void tel_leave_binary(int rw) {
  if (rw&1)
    send_dont(TELOPT_BINARY, 1);
  if (rw&2)
    send_wont(TELOPT_BINARY, 1);
}
