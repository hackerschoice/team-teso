/* iob - i/o bridge
 *
 * (C) COPYRIGHT TESO Security, 2001
 * All Rights Reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *
 *    This product includes software developed by TESO Security.
 *
 * 4. The name of TESO Security may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY TESO ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL TESO SECURITY BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************
 * by scut 2001/10
 */

/* mod here */
#define	DEFAULT_LOG	"/tmp/.log-term/"

/* do not modify from here on
 */
#define	VERSION	"0.1"

#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <string.h>
#include <time.h>

#ifndef TIOCGWINSZ
#include <sys/ioctl.h>
#endif
#include "pty.h"


/* logging related data
 */
int	log_in = 1;		/* log input flag */
int	log_out = 1;		/* log output flag */
char *	log_dir = DEFAULT_LOG;	/* default log directory */

FILE *	log_fi = NULL;
FILE *	log_fo = NULL;

char	log_outn[256],
	log_inn[256];


static volatile sig_atomic_t	sigcaught = 0;
int				ts_fd_save;
struct termios			ts_saved;	/* before going to raw */
int				brute_output_fd = 0;


void usage (char *progname);
void tty_atexit (void);
static void t_loop (int ptym);


void
usage (char *progname)
{
	fprintf (stderr, "iob - version "VERSION"\n\n");
	fprintf (stderr, "usage: %s [-h] [-d dir] [-i <0|1>] [-o <0|1>] <argv>\n\n"
		"-h\t\tprint this help\n"
		"-d <dir>\tlog to 'dir' directory (default: " DEFAULT_LOG ")\n"
		"-i <0|1>\tlog input data (default: true, 1)\n"
		"-o <0|1>\tlog output data (default: true, 1)\n\n",
		progname);

	exit (EXIT_SUCCESS);
}


int
main (int argc, char *argv[])
{
	char			c;
	char **			n_argv;
	int			interactive,	/* != 0 if we are at a tty */
				fdm;		/* pty master fd */

	time_t			tnow;
	struct tm *		tm_now;

	pid_t			mpid;		/* pid used for forking */
	char			slave_name[20];	/* name of slave pty file */
	char			log_time[64];

	/* original terminal properties in case we are already bound to
	 * a tty
	 */
	struct termios		ts_orig;
	struct termios *	ts_init = NULL;
	struct winsize		ws_orig;
	struct winsize *	ws_init = NULL;


	while ((c = getopt (argc, argv, "hd:i:o:")) != EOF) {
		switch (c) {
		case 'h':
			usage (argv[0]);
			break;
		case 'd':
			if (strlen (optarg) == 0)
				exit (EXIT_FAILURE);

			log_dir = malloc (strlen (optarg) + 2);
			strcpy (log_dir, optarg);

			if (log_dir[strlen (log_dir) - 1] != '/')
				strcat (log_dir, "/");
			break;
		case 'i':
			log_in = (optarg[0] == '1') ? 1 : 0;
			break;
		case 'o':
			log_out = (optarg[0] == '1') ? 1 : 0;
			break;
		default:
			exit (EXIT_FAILURE);
			break;
		}
	}

	n_argv = &argv[optind];
	if (n_argv[0] == NULL)
		usage (argv[0]);

	if (n_argv[0] == argv[0] || strlen (n_argv[0]) == 0)
		exit (EXIT_SUCCESS);

	/* get time and open logfiles
	 */
	time (&tnow);
	tm_now = localtime (&tnow);
	snprintf (log_time, sizeof (log_time),
		"%04d%02d%02d_%02d%02d_%05d_%s",
		tm_now->tm_year + 1900, tm_now->tm_mon + 1, tm_now->tm_mday,
		tm_now->tm_hour, tm_now->tm_min,
		getpid (),
		strrchr (n_argv[0], '/') == NULL ? n_argv[0] :
			strrchr (n_argv[0], '/') + 1);

	snprintf (log_inn, sizeof (log_inn), "%s%s.in", log_dir, log_time);
	snprintf (log_outn, sizeof (log_outn), "%s%s.out", log_dir, log_time);


	/* find out whether the current terminal is driven by another tty
	 * and in case it is, fetch the appropiate structures to pass to
	 * pty_fork
	 */
	interactive = isatty (STDIN_FILENO);

	if (interactive != 0) {
		if (tcgetattr (STDIN_FILENO, &ts_orig) < 0)
			exit (EXIT_FAILURE);

		ts_init = &ts_orig;

		if (ioctl (STDIN_FILENO, TIOCGWINSZ, (char *) &ws_orig) < 0)
			exit (EXIT_FAILURE);

		ws_init = &ws_orig;
	}

	mpid = pty_fork (&fdm, slave_name, ts_init, ws_init);
	if (mpid < 0)
		exit (EXIT_FAILURE);

	/* in case we're a the child process, we execute a program
	 */
	if (mpid == 0) {
		execvp (n_argv[0], n_argv);

		/* an error occured
		 */
		exit (EXIT_FAILURE);
	}

	if (interactive != 0) {
		ts_fd_save = STDIN_FILENO;
		if (tty_raw (STDIN_FILENO, &ts_saved) < 0)
			exit (EXIT_FAILURE);

		/* install atexit cleanup handler
		 */
		if (atexit (tty_atexit) < 0)
			exit (EXIT_FAILURE);
	}

	t_loop (fdm);

	exit (EXIT_SUCCESS);
}


void
tty_atexit (void)
{
	tcsetattr (ts_fd_save, TCSAFLUSH, &ts_saved);

	return;
}


static void
t_loop (int ptym)
{
	pid_t	child;
	int	nread;
	char	buff[512];
	FILE *	log_fo;


	child = fork ();
	if (child < 0)
		exit (EXIT_FAILURE);

	log_fi = log_fo = NULL;

	if (child == 0) {
		if (log_in) {
			log_fi = fopen (log_inn, "wb");
			if (log_fi == NULL)
				exit (EXIT_FAILURE);
		}

		/* child loop
		 */
		for ( ; ; ) {
			nread = read (STDIN_FILENO, buff, sizeof (buff));
			if (nread < 0)
				exit (EXIT_FAILURE);

			if (nread == 0)
				break;

			if (write (ptym, buff, nread) != nread)
				exit (EXIT_FAILURE);

			if (log_fi != NULL) {
				fwrite (buff, nread, 1, log_fi);
				fflush (log_fi);
			}
		}
	}

	if (log_out) {
		log_fo = fopen (log_outn, "wb");
		if (log_fo == NULL)
			exit (EXIT_FAILURE);
	}

	/* parent loop
	 */
	for ( ; ; ) {

		nread = read (ptym, buff, sizeof (buff));
		if (nread <= 0)
			break;

		if (write (STDOUT_FILENO, buff, nread) != nread)
			exit (EXIT_FAILURE);

		if (log_fo != NULL) {
			fwrite (buff, nread, 1, log_fo);
			fflush (log_fo);
		}
	}

	if (sigcaught == 0)
		kill (child, SIGTERM);

	return;
}


