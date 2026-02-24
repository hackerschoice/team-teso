/* fornax - distributed network
 *
 * by team teso
 *
 * scripting call includes
 */

#ifndef	FNX_CALL_H
#define	FNX_CALL_H

#include "symbol.h"


typedef struct {
	char *		name;
	sym_elem **	parameters;
} call;


/* call_create
 *
 * call constructor.
 *
 * return a pointer to a new call structure
 */

call *	call_create (void);


/* call_free
 *
 * free a call structure pointed to by `c' completely, including any symbol
 * information
 *
 * return in any case
 */

void	call_free (call *c);


/* call_set_name
 *
 * set the name `name' for a call structure pointed to by `c'
 *
 * return pointer to the structure
 */

call *	call_set_name (call *c, char *name);


/* call_set_parameters
 *
 * set parameters `par' for a call structure pointed to by `c'
 *
 * return pointer to the structure
 */

call *	call_set_parameters (call *c, sym_elem **par);


#endif

