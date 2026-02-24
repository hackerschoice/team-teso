/* fornax - distributed network
 *
 * by team teso
 *
 * scripting condition routines
 */

#include <stdlib.h>
#include <string.h>
#include "../../shared/common.h"
#include "condition.h"
#include "symbol.h"

extern sym_elem **	gl_ns;


int
cond_verify (condition *cnd)
{
	/* condition is invalid and hence cannot be met
	 */
	if (cnd->cond1 == NULL && cnd->val1 == NULL)
		return (0);

	/* pair condition
	 */
	if (cnd->cond1 != NULL) {
		int	c1_ret, c2_ret;

		c1_ret = cond_verify (cnd->cond1);
		c2_ret = cond_verify (cnd->cond2);

		if (cnd->logoper == LO_OR) {
			return ((c1_ret == 1 || c2_ret == 1) ? 1 : 0);
		} else if (cnd->logoper == LO_AND) {
			return ((c1_ret == 1 && c2_ret == 1) ? 1 : 0);
		}

		/* shouldn't happen
		 */
		return (0);
	} else {
		int	eq_val = 0;
		char *	val1_s;
		char *	val2_s;

		/* normal equality test (broken-down-case)
		 * first substitute each side then compare according to the
		 * equality operator
		 */
		val1_s = (char *) sym_resolve (gl_ns, cnd->val1);
		val2_s = sym_subst (gl_ns, cnd->val2);

		switch (cnd->eqop) {
		case (EQ_EQUAL):
			eq_val = (strcasecmp (val1_s, val2_s) == 0) ? 1 : 0;
			break;
		case (EQ_NOTEQ):
			eq_val = (strcasecmp (val1_s, val2_s) == 0) ? 0 : 1;
			break;
		/* to be implemented
		 */
		case (EQ_GREATEQ):
		case (EQ_LOWEREQ):
			break;
		default:
			break;
		}

		free (val2_s);

		return (eq_val);
	}
}


condition *
cond_create (void)
{
	condition *	new = xcalloc (1, sizeof (condition));

	return (new);
}


void
cond_free (condition *c)
{
	if (c->val1 != NULL)
		free (c->val1);
	if (c->val2 != NULL)
		free (c->val2);
	if (c->cond1 != NULL)
		cond_free (c->cond1);
	if (c->cond2 != NULL)
		cond_free (c->cond2);
	free (c);

	return;
}


condition *
cond_set_cond1 (condition *c, condition *c1)
{
	c->cond1 = c1;

	return (c);
}


condition *
cond_set_cond2 (condition *c, condition *c2)
{
	c->cond2 = c2;

	return (c);
}


condition *
cond_set_logoper (condition *c, int lo)
{
	c->logoper = lo;

	return (c);
}


condition *
cond_set_eqop (condition *c, int eo)
{
	c->eqop = eo;

	return (c);
}


condition *
cond_set_val1 (condition *c, char *val)
{
	c->val1 = val;

	return (c);
}


condition *
cond_set_val2 (condition *c, char *val)
{
	c->val2 = val;

	return (c);
}



