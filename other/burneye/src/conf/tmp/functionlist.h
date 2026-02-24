/* fornax - distributed network
 *
 * by team teso
 *
 * script functions
 */

#ifndef	FNX_FUNCTIONLIST_H
#define	FNX_FUNCTIONLIST_H

#include "symbol.h"

int	f_listen (sym_elem **sl);	/* net.listen */
int	node_self (sym_elem **stab);	/* sys.self */
int	tt_schedule (sym_elem **stab);	/* time.schedule */
int	tt_erase (sym_elem **stab);	/* time.erase */

#endif


