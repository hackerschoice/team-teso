/* fornax - distributed network
 *
 * by team teso
 *
 * scripting call routines
 */


#include <stdlib.h>
#include "../../shared/common.h"
#include "symbol.h"
#include "call.h"


call *
call_create (void)
{
	call *	new = xcalloc (1, sizeof (call));

	return (new);
}


void
call_free (call *c)
{
	if (c == NULL)
		return;

	sym_free (c->parameters);
	if (c->name != NULL)
		free (c->name);
	free (c);

	return;
}


call *
call_set_name (call *c, char *name)
{
	c->name = name;

	return (c);
}


call *
call_set_parameters (call *c, sym_elem **par)
{
	c->parameters = par;

	return (c);
}


