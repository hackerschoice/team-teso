
/* zodiac - output module
 *
 * by scut / teso
 *
 * buy "Programming with Curses" if you mind understanding this :)
 */

#define	OUTPUT_MAIN

#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <ncurses.h>
#include "common.h"
#include "output.h"
#include "zodiac.h"

mscr *
out_init (void)
{
	mscr	*nm = xcalloc (1, sizeof (mscr));
	pthread_mutex_init (&nm->outm, NULL);

	initscr ();		/* initialize curses, get termcaps etc. */
	crmode ();		/* cooked raw (control char's to kernel, rest to us */
	echo ();		/* echo inputs */
	nl ();			/* newline on wraps */
	meta (stdscr, TRUE);
	keypad (stdscr, TRUE);
	scrollok (stdscr, FALSE);
	attrset (A_NORMAL);

	if (stdscr->_maxx < 79 || stdscr->_maxy < 20)
		return (NULL);

	m_drawbox (stdscr, 0, 0, stdscr->_maxy, stdscr->_maxx);
	move (0, 1);
	printw ("= zodiac "VERSION" = by "AUTHORS" =");
	refresh ();

	/* create configuration, process and udp sniff window */
	nm->winsh = m_subwin (9, stdscr->_maxx, 1, 0, "console");
	nm->winproc = m_subwin (10, stdscr->_maxx / 2, 11, 0, "process");
	nm->winid = m_subwin (10, stdscr->_maxx / 2 + 1, 11, stdscr->_maxx / 2, "id");
	nm->windns = m_subwin (stdscr->_maxy - 21, stdscr->_maxx, 21, 0, "dns packets");

	if (nm->winsh == NULL || nm->winproc == NULL || nm->windns == NULL)
		return (NULL);

	touchwin (stdscr);
	move (0, 0);
	refresh ();

	return (nm);
}

void
m_printfnr (mscr *screen, WINDOW *win, char *str, ...)
{
	va_list	vl;

	pthread_mutex_lock (&screen->outm);
	va_start (vl, str);
	vw_printw (win, str, vl);
	va_end (vl);

	pthread_mutex_unlock (&screen->outm);

	return;
}

void
m_printf (mscr *screen, WINDOW *win, char *str, ...)
{
	va_list	vl;

	pthread_mutex_lock (&screen->outm);
	va_start (vl, str);
	vw_printw (win, str, vl);
	va_end (vl);

	wrefresh (win);
	pthread_mutex_unlock (&screen->outm);

	return;
}


/* create a subwin from stdscr, putting a nice border around it and set a
 * title
 */

WINDOW *
m_subwin (int lines, int cols, int y1, int x1, char *title)
{
	WINDOW	*nw;

	nw = subwin (stdscr, lines - 2, cols - 2, y1 + 1, x1 + 1);
	if (nw == NULL)
		return (NULL);

	meta (nw, TRUE);
	keypad (nw, TRUE);
	scrollok (nw, TRUE);

	m_drawbox (stdscr, y1, x1, y1 + lines, x1 + cols);

	if (title != NULL) {
		move (y1, x1 + 1);
		printw ("= %s =", title);
	}
	wmove (nw, 0, 0);

	return (nw);
}

void
m_drawbox (WINDOW *win, int y1, int x1, int y2, int x2)
{
	int	x, y;

	if (y1 >= y2 || x1 >= x2)
		return;

	for (y = y1, x = x2 - 1; x > x1; --x) {
		wmove (win, y, x);
		waddch (win, '-');
	}
	for (y = y2 - 1; y > y1; --y) {
		wmove (win, y, x1);
		waddch (win, '|');
		wmove (win, y, x2);
		waddch (win, '|');
	}
	for (y = y2, x = x2 - 1; x > x1; --x) {
		wmove (win, y, x);
		waddch (win, '-');
	}
	wmove (win, y1, x1);
	waddch (win, '+');
	wmove (win, y1, x2);
	waddch (win, '+');
	wmove (win, y2, x1);
	waddch (win, '+');
	wmove (win, y2, x2);
	waddch (win, '+');

	return;
}

