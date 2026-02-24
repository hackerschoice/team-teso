/* fornax - distributed network
 *
 * by team teso
 *
 * function definitions
 */

#ifndef	FNX_FUNCTION_H
#define	FNX_FUNCTION_H

#include "symbol.h"

typedef int (* fnc_handler)(sym_elem **par);

typedef struct {
	char *		name;		/* symbolic function name */
	fnc_handler	f_handler;	/* function handler */
} function;


/* fnc_find
 *
 * find a function with the function name `name' from the function table
 * pointed to by `ftab'
 *
 * return fnc_handler pointer on success
 * return NULL on failure
 */

fnc_handler	fnc_find (function ftab[], char *name);


#endif


