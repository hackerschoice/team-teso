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
 *
 *	from: @(#)externs.h	5.3 (Berkeley) 3/22/91
 *	$Id: externs.h,v 1.20 1999/08/19 09:34:15 dholland Exp $
 */

#ifndef	BSD
#define BSD 43
#endif

#include <stdio.h>
#include <setjmp.h>
#include <sys/ioctl.h>
#include <features.h>
#include <termios.h>

#if defined(NO_CC_T)
typedef unsigned char cc_t;
#endif

#ifdef __linux__
#include <unistd.h>   /* get _POSIX_VDISABLE */
#endif

#ifndef	_POSIX_VDISABLE
#error "Please fix externs.h to define _POSIX_VDISABLE"
#endif

#define	SUBBUFSIZE	256

extern int autologin;		/* Autologin enabled */
extern int skiprc;		/* Don't process the ~/.telnetrc file */
extern int eight;		/* use eight bit mode (binary in and/or out */
extern int flushout;		/* flush output */
extern int connected;		/* Are we connected to the other side? */
extern int globalmode;		/* Mode tty should be in */
extern int In3270;			/* Are we in 3270 mode? */
extern int telnetport;		/* Are we connected to the telnet port? */
extern int localflow;		/* Flow control handled locally */
extern int localchars;		/* we recognize interrupt/quit */
extern int donelclchars;		/* the user has set "localchars" */
extern int showoptions;

extern int crlf;	/* Should '\r' be mapped to <CR><LF> (or <CR><NUL>)? */
extern int autoflush;		/* flush output when interrupting? */
extern int autosynch;		/* send interrupt characters with SYNCH? */
extern int SYNCHing;		/* Is the stream in telnet SYNCH mode? */
extern int donebinarytoggle;	/* the user has put us in binary */
extern int dontlecho;		/* do we suppress local echoing right now? */
extern int crmod;
//extern int netdata;		/* Print out network data flow */
//extern int prettydump;	/* Print "netdata" output in user readable format */
extern int debug;			/* Debug level */

#ifdef TN3270
extern int cursesdata;		/* Print out curses data flow */
#endif /* unix and TN3270 */

extern cc_t escapechar;	 /* Escape to command mode */
extern cc_t rlogin;	 /* Rlogin mode escape character */
#ifdef	KLUDGELINEMODE
extern cc_t echoc;	/* Toggle local echoing */
#endif

extern char *prompt;		/* Prompt for command. */

extern char doopt[];
extern char dont[];
extern char will[];
extern char wont[];
extern char options[];		/* All the little options */
extern char *hostname;		/* Who are we connected to? */

/*
 * We keep track of each side of the option negotiation.
 */

#define	MY_STATE_WILL		0x01
#define	MY_WANT_STATE_WILL	0x02
#define	MY_STATE_DO		0x04
#define	MY_WANT_STATE_DO	0x08

/*
 * Macros to check the current state of things
 */

#define	my_state_is_do(opt)		(options[opt]&MY_STATE_DO)
#define	my_state_is_will(opt)		(options[opt]&MY_STATE_WILL)
#define my_want_state_is_do(opt)	(options[opt]&MY_WANT_STATE_DO)
#define my_want_state_is_will(opt)	(options[opt]&MY_WANT_STATE_WILL)

#define	my_state_is_dont(opt)		(!my_state_is_do(opt))
#define	my_state_is_wont(opt)		(!my_state_is_will(opt))
#define my_want_state_is_dont(opt)	(!my_want_state_is_do(opt))
#define my_want_state_is_wont(opt)	(!my_want_state_is_will(opt))

#define	set_my_state_do(opt)		{options[opt] |= MY_STATE_DO;}
#define	set_my_state_will(opt)		{options[opt] |= MY_STATE_WILL;}
#define	set_my_want_state_do(opt)	{options[opt] |= MY_WANT_STATE_DO;}
#define	set_my_want_state_will(opt)	{options[opt] |= MY_WANT_STATE_WILL;}

#define	set_my_state_dont(opt)		{options[opt] &= ~MY_STATE_DO;}
#define	set_my_state_wont(opt)		{options[opt] &= ~MY_STATE_WILL;}
#define	set_my_want_state_dont(opt)	{options[opt] &= ~MY_WANT_STATE_DO;}
#define	set_my_want_state_wont(opt)	{options[opt] &= ~MY_WANT_STATE_WILL;}

/*
 * Make everything symmetric
 */

#define	HIS_STATE_WILL			MY_STATE_DO
#define	HIS_WANT_STATE_WILL		MY_WANT_STATE_DO
#define HIS_STATE_DO			MY_STATE_WILL
#define HIS_WANT_STATE_DO		MY_WANT_STATE_WILL

#define	his_state_is_do			my_state_is_will
#define	his_state_is_will		my_state_is_do
#define his_want_state_is_do		my_want_state_is_will
#define his_want_state_is_will		my_want_state_is_do

#define	his_state_is_dont		my_state_is_wont
#define	his_state_is_wont		my_state_is_dont
#define his_want_state_is_dont		my_want_state_is_wont
#define his_want_state_is_wont		my_want_state_is_dont

#define	set_his_state_do		set_my_state_will
#define	set_his_state_will		set_my_state_do
#define	set_his_want_state_do		set_my_want_state_will
#define	set_his_want_state_will		set_my_want_state_do

#define	set_his_state_dont		set_my_state_wont
#define	set_his_state_wont		set_my_state_dont
#define	set_his_want_state_dont		set_my_want_state_wont
#define	set_his_want_state_wont		set_my_want_state_dont


extern FILE *NetTrace;		/* Where debugging output goes */
extern char NetTraceFile[];	/* Name of file where debugging output goes */

void SetNetTrace(const char *);	/* Function to change where debugging goes */

extern sigjmp_buf peerdied;
extern sigjmp_buf toplevel;		/* For error conditions. */

void command(int, const char *, int);
void Dump (int, char *, int);
void init_3270 (void);
void printoption(const char *, int, int);
void printsub (int, unsigned char *, int);
void sendnaws (void);
void setconnmode(int);
void setcommandmode (void);
void setneturg (void);
void sys_telnet_init (void);
void telnet(const char *);
void tel_enter_binary(int);
void TerminalFlushOutput(void);
void TerminalNewMode(int);
void TerminalRestoreState(void);
void TerminalSaveState(void);
void tninit(void);
void upcase(char *);
void willoption(int);
void wontoption(int);

void lm_will(unsigned char *, int);
void lm_wont(unsigned char *, int);
void lm_do(unsigned char *, int);
void lm_dont(unsigned char *, int);
void lm_mode(unsigned char *, int, int);

void slc_init(void);
void slcstate(void);
void slc_mode_export(void);
void slc_mode_import(int);
void slc_import(int);
void slc_export(void);
void slc(unsigned char *, int);
void slc_check(void);
void slc_start_reply(void);
void slc_add_reply(int, int, int);
void slc_end_reply(void);
int slc_update(void);

void env_opt(unsigned char *, int);
void env_opt_start(void);
void env_opt_start_info(void);
void env_opt_add(const char *);
void env_opt_end(int);

int get_status(const char *, const char *);
int dosynch(void);

cc_t *tcval(int);

//#if 0
extern struct termios new_tc;

#define termEofChar		new_tc.c_cc[VEOF]
#define termEraseChar		new_tc.c_cc[VERASE]
#define termIntChar		new_tc.c_cc[VINTR]
#define termKillChar		new_tc.c_cc[VKILL]
#define termQuitChar		new_tc.c_cc[VQUIT]

#ifndef	VSUSP
extern cc_t termSuspChar;
#else
#define termSuspChar		new_tc.c_cc[VSUSP]
#endif

#if defined(VFLUSHO) && !defined(VDISCARD)
#define VDISCARD VFLUSHO
#endif
#ifndef	VDISCARD
extern cc_t termFlushChar;
#else
#define termFlushChar		new_tc.c_cc[VDISCARD]
#endif

#ifndef VWERASE
extern cc_t termWerasChar;
#else
#define termWerasChar		new_tc.c_cc[VWERASE]
#endif

#ifndef	VREPRINT
extern cc_t termRprntChar;
#else
#define termRprntChar		new_tc.c_cc[VREPRINT]
#endif

#ifndef	VLNEXT
extern cc_t termLiteralNextChar;
#else
#define termLiteralNextChar	new_tc.c_cc[VLNEXT]
#endif

#ifndef	VSTART
extern cc_t termStartChar;
#else
#define termStartChar		new_tc.c_cc[VSTART]
#endif

#ifndef	VSTOP
extern cc_t termStopChar;
#else
#define termStopChar		new_tc.c_cc[VSTOP]
#endif

#ifndef	VEOL
extern cc_t termForw1Char;
#else
#define termForw1Char		new_tc.c_cc[VEOL]
#endif

#ifndef	VEOL2
extern cc_t termForw2Char;
#else
#define termForw2Char		new_tc.c_cc[VEOL]
#endif

#ifndef	VSTATUS
extern cc_t termAytChar;
#else
#define termAytChar		new_tc.c_cc[VSTATUS]
#endif

//#endif /* 0 */

//#if 0
#if !defined(CRAY) || defined(__STDC__)
#define termEofCharp	&termEofChar
#define termEraseCharp	&termEraseChar
#define termIntCharp	&termIntChar
#define termKillCharp	&termKillChar
#define termQuitCharp	&termQuitChar
#define termSuspCharp	&termSuspChar
#define termFlushCharp	&termFlushChar
#define termWerasCharp	&termWerasChar
#define termRprntCharp	&termRprntChar
#define termLiteralNextCharp	&termLiteralNextChar
#define termStartCharp	&termStartChar
#define termStopCharp	&termStopChar
#define termForw1Charp	&termForw1Char
#define termForw2Charp	&termForw2Char
#define termAytCharp	&termAytChar
#else
	/* Work around a compiler bug */
#define termEofCharp		0
#define termEraseCharp		0
#define termIntCharp		0
#define termKillCharp		0
#define termQuitCharp		0
#define termSuspCharp		0
#define termFlushCharp		0
#define termWerasCharp		0
#define termRprntCharp		0
#define termLiteralNextCharp	0
#define termStartCharp		0
#define termStopCharp		0
#define termForw1Charp		0
#define termForw2Charp		0
#define termAytCharp		0
#endif

//#endif /* 0 */


/* Ring buffer structures which are shared */

extern ringbuf netoring;
extern ringbuf netiring;
extern ringbuf ttyoring;
extern ringbuf ttyiring;

/* Tn3270 section */
#if defined(TN3270)

extern int HaveInput;	/* Whether an asynchronous I/O indication came in */
extern int noasynchtty;	/* Don't do signals on I/O (SIGURG, SIGIO) */
extern int noasynchnet;	/* Don't do signals on I/O (SIGURG, SIGIO) */
extern int sigiocount;		/* Count of SIGIO receptions */
extern int shell_active;	/* Subshell is active */

extern char *Ibackp;		/* Oldest byte of 3270 data */
extern char Ibuf[];		/* 3270 buffer */
extern char *Ifrontp;		/* Where next 3270 byte goes */
extern char tline[];
extern char *transcom;		/* Transparent command */

void settranscom(int, char**);
int shell(int, char**);
void inputAvailable(void);

#endif	/* defined(TN3270) */
