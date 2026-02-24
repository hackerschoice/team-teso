/* fornax - distributed network
 *
 * by team teso
 *
 * scripting branching routines
 */

#include <stdlib.h>
#include "../../shared/common.h"
#include "condition.h"
#include "branch.h"


branch *
br_create (void)
{
	branch *	new = xcalloc (1, sizeof (branch));

	return (new);
}


void
br_free (branch *br)
{
	elem_list_free (br->b_true);
	elem_list_free (br->b_false);
	cond_free (br->cond);
	free (br);

	return;
}


branch *
br_set_condition (branch *br, condition *cond)
{
	br->cond = cond;

	return (br);
}


branch *
br_set_block_if (branch *br, element **bl)
{
	br->b_true = bl;

	return (br);
}


branch *
br_set_block_else (branch *br, element **bl)
{
	br->b_false = bl;

	return (br);
}


