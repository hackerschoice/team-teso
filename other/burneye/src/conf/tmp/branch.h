/* fornax - distributed network
 *
 * by team teso
 *
 * scripting branching includes
 */

#ifndef	FNX_BRANCH_H
#define	FNX_BRANCH_H

#include "condition.h"
#include "element.h"


typedef struct {
	condition *	cond;
	element **	b_true;
	element **	b_false;
} branch;


/* br_create
 *
 * branch constructor. create a new branch structure
 *
 * return a pointer to the new structure
 */

branch *	br_create (void);


/* br_free
 *
 * free the whole branch pointed to by `br'
 *
 * return in any case
 */

void	br_free (branch *br);


/* br_set_condition
 *
 * set condition `cond' for branch `br'
 *
 * return pointer to structure
 */

branch *	br_set_condition (branch *br, condition *cond);


/* br_set_block_if
 *
 * set block `bl' for branch `br' on true case
 *
 * return pointer to structure
 */

branch *	br_set_block_if (branch *br, element **bl);


/* br_set_block_else
 *
 * set block `bl' for branch `br' on false case
 *
 * return pointer to structure
 */

branch *	br_set_block_else (branch *br, element **bl);


#endif


