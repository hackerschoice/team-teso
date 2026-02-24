/* fornax - distributed network
 *
 * by team teso
 *
 * scripting element routines
 */

#include <string.h>
#include <stdlib.h>
#include "../../shared/common.h"
#include "call.h"
#include "branch.h"
#include "element.h"
#include "symbol.h"


/* static function declarations
 */
static int	elem_count (element **el);


void
elem_list_free (element **el)
{
	if (el == NULL)
		return;

	while (elem_count (el) > 0) {
		elem_free (el[0]);
		memmove (&el[0], &el[1], (elem_count (&el[1]) + 1) * sizeof (element *));
	}

	if (el != NULL)
		free (el);
}


static int
elem_count (element **el)
{
	int	count;

	if (el == NULL)
		return (0);

	for (count = 0 ; el[count] != NULL ; ++count)
		;

	return (count);
}


element **
elem_add (element **el, element *e)
{
	int	ec = elem_count (el);

	el = xrealloc (el, (ec + 2) * sizeof (element *));
	el[ec] = e;
	el[ec + 1] = NULL;

	return (el);
}


element *
elem_create (void)
{
	element *	new = xcalloc (1, sizeof (element));

	return (new);
}


void
elem_free (element *e)
{
	switch (e->type) {
	case (ELEM_TYPE_CALL):
		call_free ((call *) e->data);
		break;
	case (ELEM_TYPE_BRANCH):
		br_free ((branch *) e->data);
		break;
	case (ELEM_TYPE_SET):
		sym_elem_free ((sym_elem *) e->data);
		break;
	default:
		break;
	}

	free (e);

	return;
}


element *
elem_set_type (element *e, int type)
{
	e->type = type;

	return (e);
}


element *
elem_set_data (element *e, void *data)
{
	e->data = data;

	return (e);
}


