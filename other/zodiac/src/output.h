
/* zodiac - output module
 * include file
 *
 * by scut / teso
 *
 * buy "Programming with Curses" if you mind understanding this :)
 */

#ifndef	Z_OUTPUT_H
#define	Z_OUTPUT_H

#include <ncurses.h>
#include <pthread.h>

typedef struct mscr {
	pthread_mutex_t	outm;	/* output mutex */
	WINDOW	*winsh;		/* configuration window */
	WINDOW	*winproc;	/* process / status window */
	WINDOW	*winid;		/* dns ID window */
	WINDOW	*windns;	/* incoming DNS packets window */
} mscr;

mscr	*out_init (void);
void	m_printfnr (mscr *screen, WINDOW *win, char *str, ...);
void	m_printf (mscr *screen, WINDOW *win, char *str, ...);
WINDOW	*m_subwin (int lines, int cols, int y1, int x1, char *title);
void	m_drawbox (WINDOW *win, int y1, int x1, int y2, int x2);

#endif

