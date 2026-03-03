/* zylyx - file find
 *
 * screen and output routines
 * header file
 *
 * by team teso
 */

#ifndef	_ZYL_SCREEN
#define	_ZYL_SCREEN

#include <pthread.h>

#ifndef	_ZYL_SCR_MAIN
extern pthread_mutex_t	screen_mutex;
#endif


#define	COL_SPICY	0x01
#define	COL_MSPICY	0x02
#define	COL_LSPICY	0x03
#define	COL_TEXT	0x04
#define	COL_STEXT	0x05
#define	COL_PRX_INACT	0x10

void	scr_init (void);
void	scr_prg_init (void);
void	scr_init_col (void);
void	scr_banner (void);
int	scr_rprintf (int x, int y, const char *str, ...);
void	scr_rprint (int x, int y, char *str);
void	scr_cprint (int x, int y, char *str);
void	scr_print (char *str1);
void	scr_build_box (int x1, int y1, int x2, int y2);
void	scr_build_sline_v (int x, int y1, int y2, char start, char fill, char end,
		int objhigh, int objmed, int objlow);
void	scr_build_sline_h (int y, int x1, int x2, char start, char fill, char end,
		int objhigh, int objmed, int objlow);
void	scr_build_line_v (int obj, int x, int y1, int y2, char start, char fill, char end);
void	scr_build_line_h (int obj, int y, int x1, int x2, char start, char fill, char end);
void	scr_exit (void);
void	scr_init_col (void);

#endif

