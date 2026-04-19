/* zylyx - file find
 *
 * screen and output module
 *
 * by team teso
 */

#define	_ZYL_SCR_MAIN

#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <slang.h>
#include "screen.h"
#include "zylyx.h"


pthread_mutex_t	screen_mutex;

void
scr_init (void)
{
	int	n;

	pthread_mutex_init (&screen_mutex, NULL);
	SLtt_get_terminfo ();
	SLang_init_tty (-1, 0, 0);
	n = SLsmg_init_smg ();
	if (n == -1) {
		fprintf (stderr, "SLsmg_init_smg failed\n");
		exit (EXIT_FAILURE);
	}
	SLsmg_cls ();
	scr_init_col ();
	SLsmg_refresh ();

	return;
}


void
scr_init_col (void)
{
	/* give us some sneezy colors, oh yeah
	 */

	SLtt_set_color (COL_SPICY, NULL, "white", "black");
	SLtt_set_color (COL_MSPICY, NULL, "brightblue", "black");
	SLtt_set_color (COL_LSPICY, NULL, "blue", "black");
	SLtt_set_color (COL_TEXT, NULL, "gray", "black");
	SLtt_set_color (COL_STEXT, NULL, "brightgreen", "black");
	SLtt_set_color (COL_PRX_INACT, NULL, "green", "black");

	return;
}


void
scr_prg_init (void)
{
	scr_build_box (0, 0, SLtt_Screen_Cols - 1, 6);
	scr_build_box (0, 6, SLtt_Screen_Cols - 1, SLtt_Screen_Rows - 1);

	scr_banner ();

	SLsmg_refresh ();

	return;
}


void
scr_banner (void)
{
	scr_cprint (2, 1, ":05zylyx v"VERSION":01 - :05file find:01 - :02"AUTHORS"\n");

	scr_cprint (2, 3, ":05o :02opening connection  :02c connected  :04- :02connection failed\n");
	scr_cprint (2, 4, ":02g :02try to get file  :02r receiving  :03j :02junk  :04f :02file not found\n");
	scr_cprint (2, 5, ":04t :02timeouted  :01! :02file found\n");

	return;
}


int
scr_rprintf (int x, int y, const char *str, ...)
{
	char	tmp[1025];
	va_list	vl;
	int	i;

	va_start (vl, str);
	memset (tmp, '\0', sizeof (tmp));
	i = vsnprintf (tmp, sizeof (tmp) - 1, str, vl);
	va_end (vl);

	scr_rprint (x, y, tmp);
	SLsmg_refresh ();

	return (i);
}


void
scr_rprint (int x, int y, char *str)
{
	scr_cprint (x, y, str);
	SLsmg_refresh ();
}


void
scr_cprint (int x, int y, char *str)
{
	pthread_mutex_lock (&screen_mutex);
	SLsmg_gotorc (y, x);
	scr_print (str);
	pthread_mutex_unlock (&screen_mutex);
}


void
scr_print (char *str1)
{
	char	*str = strdup (str1);
	char	*prc = str;	/* process pointer */
	char	*print_str;
	int	color;

	if (str[0] == ':') {
		if (sscanf (str + 1, "%d", &color) != 1)
			goto p_fail;
		SLsmg_set_color (color);
		prc += 3;
	}

	while ((print_str = strsep (&prc, ":")) != NULL) {
		SLsmg_write_string (print_str);
		if (prc == NULL)
			goto p_fail;
		if (sscanf (prc, "%d", &color) != 1)
			goto p_fail;
		SLsmg_set_color (color);
		prc += 2;
	}

p_fail:
	free (str);

	return;
}


void
scr_build_box (int x1, int y1, int x2, int y2)
{
	pthread_mutex_lock (&screen_mutex);

	scr_build_sline_v (x1, y1, ((y2 - y1) / 2) + y1, '+', '|', '+', COL_SPICY, COL_MSPICY, COL_LSPICY);
	scr_build_sline_v (x2, y1, ((y2 - y1) / 2) + y1, '+', '|', '+', COL_SPICY, COL_MSPICY, COL_LSPICY);
	scr_build_sline_h (y1, x1 + 1, ((x2 - x1 - 2) / 2) + x1, '-', '-', '-', COL_SPICY, COL_MSPICY, COL_LSPICY);
	scr_build_sline_h (y2, x1 + 1, ((x2 - x1 - 2) / 2) + x1, '-', '-', '-', COL_SPICY, COL_MSPICY, COL_LSPICY);

	scr_build_sline_v (x1, y2, ((y2 - y1) / 2) + y1, '|', '|', '+', COL_SPICY, COL_MSPICY, COL_LSPICY);
	scr_build_sline_v (x2, y2, ((y2 - y1) / 2) + y1, '|', '|', '+', COL_SPICY, COL_MSPICY, COL_LSPICY);
	scr_build_sline_h (y1, x2 - 1, ((x2 - x1) / 2) + x1, '-', '-', '-', COL_SPICY, COL_MSPICY, COL_LSPICY);
	scr_build_sline_h (y2, x2 - 1, ((x2 - x1) / 2) + x1, '-', '-', '-', COL_SPICY, COL_MSPICY, COL_LSPICY);

	pthread_mutex_unlock (&screen_mutex);

	return;
}


void
scr_build_sline_v (int x, int y1, int y2, char start, char fill, char end,
	int objhigh, int objmed, int objlow)
{
	int	ly2, ly3;

	if (y1 > y2) {
		int	obj_tmp;

		y2 ^= y1;
		y1 ^= y2;
		y2 ^= y1;

		obj_tmp = objhigh;
		objhigh = objlow;
		objlow = objmed;
		objmed = obj_tmp;

		ly2 = ((y2 - y1) - ((y2 - y1) / 8)) + y1;
		ly3 = ((y2 - y1) - ((y2 - y1) / 4)) + y1;
	} else {
		ly2 = ((y2 - y1) / 8) + y1;
		ly3 = ((y2 - y1) / 4) + y1;
	}

	SLsmg_set_color (objhigh);
	SLsmg_gotorc (y1, x);
	SLsmg_write_char (start);

	for (++y1 ; y1 < y2 ; ++y1) {
		if (y1 == ly2) {
			SLsmg_set_color (objmed);
		} else if (y1 == ly3) {
			SLsmg_set_color (objlow);
		}
		SLsmg_gotorc (y1, x);
		SLsmg_write_char (fill);
	}
	SLsmg_gotorc (y2, x);
	SLsmg_write_char (end);

	return;
}


void
scr_build_sline_h (int y, int x1, int x2, char start, char fill, char end,
	int objhigh, int objmed, int objlow)
{
	int	lx2, lx3;

	if (x1 > x2) {
		int	obj_tmp;

		x2 ^= x1;
		x1 ^= x2;
		x2 ^= x1;
		obj_tmp = objhigh;
		objhigh = objlow;
		objlow = objmed;
		objmed = obj_tmp;
		lx2 = ((x2 - x1) - ((x2 - x1) / 8)) + x1;
		lx3 = ((x2 - x1) - ((x2 - x1) / 4)) + x1;
	} else {
		lx2 = ((x2 - x1) / 8) + x1;
		lx3 = ((x2 - x1) / 4) + x1;
	}

	SLsmg_set_color (objhigh);
	SLsmg_gotorc (y, x1);
	SLsmg_write_char (start);

	for (++x1 ; x1 < x2 ; ++x1) {
		if (x1 == lx2) {
			SLsmg_set_color (objmed);
		} else if (x1 == lx3) {
			SLsmg_set_color (objlow);
		}
		SLsmg_gotorc (y, x1);
		SLsmg_write_char (fill);
	}
	SLsmg_gotorc (y, x2);
	SLsmg_write_char (end);

	return;
}


void
scr_build_line_v (int obj, int x, int y1, int y2, char start, char fill, char end)
{
	SLsmg_set_color (obj);
	SLsmg_gotorc (y1, x);
	SLsmg_write_char (start);

	for (++y1 ; y1 < y2 ; ++y1) {
		SLsmg_gotorc (y1, x);
		SLsmg_write_char (fill);
	}

	SLsmg_gotorc (y2, x);
	SLsmg_write_char (end);

	return;
}


void
scr_build_line_h (int obj, int y, int x1, int x2, char start, char fill, char end)
{
	SLsmg_set_color (obj);
	SLsmg_gotorc (y, x1);
	SLsmg_write_char (start);

	for (++x1 ; x1 < x2 ; ++x1) {
		SLsmg_gotorc (y, x1);
		SLsmg_write_char (fill);
	}

	SLsmg_gotorc (y, x2);
	SLsmg_write_char (end);

	return;
}


void
scr_exit (void)
{
	SLsmg_reset_smg ();
	SLang_reset_tty ();

	return;
}

