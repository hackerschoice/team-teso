/* fornax - distributed network
 *
 * by team teso
 *
 * function routines
 */

#include <stdio.h>
#include <string.h>
#include "functions.h"
#include "functionlist.h"
#include "symbol.h"


int	fnc_debug (sym_elem **stab);

function 	gl_fnc[] = {
	/* primitives */
	{ "nop",		NULL },
	{ "debug",		fnc_debug },

	/* network */
	{ "net.listen",		f_listen },

	/* fornax system */
	{ "sys.self",		node_self },

	/* time management */
	{ "time.schedule",	tt_schedule },
	{ "time.erase",		tt_erase },

	/* end of list */
	{ NULL,		NULL },
};


fnc_handler
fnc_find (function ftab[], char *name)
{
	int	stp_p;	/* step pointer */

	for (stp_p = 0 ; ftab[stp_p].name != NULL ; ++stp_p) {
		if (strcasecmp (ftab[stp_p].name, name) == 0)
			return (ftab[stp_p].f_handler);
	}

	return (NULL);
}


int
fnc_debug (sym_elem **stab)
{
	int	n;

	if (stab == NULL)
		return (0);

	for (n = 0 ; stab[n] != NULL ; ++n) {
		printf ("%s . %s\n", (stab[n]->key == NULL) ? "NULL" : stab[n]->key,
			(stab[n]->value == NULL) ? "NULL" : stab[n]->value);
	}

	return (0);
}

