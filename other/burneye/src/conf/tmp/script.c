/* fornax - distributed network
 *
 * by team teso
 *
 * scripting capabilities routines
 */

#include <stdio.h>
#include "branch.h"
#include "call.h"
#include "compiler.h"
#include "element.h"
#include "functions.h"
#include "script.h"
#include "symbol.h"

sym_elem **	gl_ns = NULL;
extern function	gl_fnc[];


/* static functions
 */

void	scr_elem_exec (element **el);
static void	scr_call (call *c);
static void	scr_branch (branch * br);


/* scr_elem_exec
 *
 * execute the element list pointed to by `el'
 *
 * return in any case
 */

void
scr_elem_exec (element **el)
{
	int		el_ptr;
	element *	ec;

	if (el == NULL || el[0] == NULL)
		return;

	for (el_ptr = 0 ; el[el_ptr] != NULL ; ++el_ptr) {
		ec = el[el_ptr];

		switch (ec->type) {
		case (ELEM_TYPE_CALL):
			scr_call ((call *) ec->data);
			break;

		case (ELEM_TYPE_BRANCH):
			scr_branch ((branch *) ec->data);
			break;

		/* in case it is a set element, just add the symbol element
		 * to the global namespace
		 */
		case (ELEM_TYPE_SET):
			gl_ns = scr_ns_add (gl_ns, (sym_elem *) ec->data);
			break;

		/* should never happen
		 */
		default:
			break;
		}
	}

	return;
}


/* scr_call
 *
 * make a call, just like et did when he phoned home. well, not really, but
 * quite similar
 *
 * return in any case
 */

static void
scr_call (call *c)
{
	fnc_handler	f_h;

	/* nothing to execute today, baby
	 */
	if (c == NULL || c->name == NULL)
		return;

	f_h = fnc_find (gl_fnc, c->name);

	/* no function found or nop -> return
	 */
	if (f_h == NULL)
		return;

	(void) f_h (c->parameters);

	return;
}


static void
scr_branch (branch * br)
{
	if (cond_verify (br->cond) == 1) {
		scr_elem_exec (br->b_true);
	} else {
		scr_elem_exec (br->b_false);
	}

	return;
}


sym_elem **
scr_ns_add (sym_elem **ns, sym_elem *elem)
{
	return (sym_elem_add (ns, elem));
}


int
scr_exec (char *script)
{
	element **	scr;

	scr = cp_compile (script, strlen (script));
	if (scr == NULL)
		return (0);

	scr_elem_exec (scr);

	elem_list_free (scr);

	return (1);
}


element **
scr_compile (char *script)
{
	element **	scr = NULL;

	if (script != NULL)
		scr = cp_compile (script, strlen (script));

	return (scr);
}


