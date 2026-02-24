/* fornax - distributed network
 *
 * by team teso
 *
 * scripting capabilities
 */

#ifndef	FNX_SCRIPT_H
#define	FNX_SCRIPT_H

#include "element.h"
#include "symbol.h"


/* scr_exec
 *
 * compile and execute a script pointed to by `script'. after execution,
 * free the compiled script
 *
 * return 1 if the execution was successful (ie compilation succeeded)
 * return 0 on error (compilation/interpreter failed)
 */

int	scr_exec (char *script);


/* scr_ns_add
 *
 * add a symbol element `elem' to the namespace pointed to by `ns'
 *
 * return pointer to modified namespace
 */

sym_elem **	scr_ns_add (sym_elem **ns, sym_elem *elem);


/* scr_compile
 *
 * compile a script pointed to by `script'
 *
 * return a pointer to the readily compiled parse tree on success
 * return NULL on failure
 */

element **	scr_compile (char *script);


#endif


