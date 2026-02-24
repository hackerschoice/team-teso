/* shellkit.h - main shellcode kit definition file
 *
 * everything is merged here.
 *
 * team teso
 */

#ifndef	SHELLKIT_H
#define	SHELLKIT_H

#include "shellcode.h"

/* individual architectures */
#include "hppa_hpux.h"
#include "mips_irix.h"
#include "sparc_solaris.h"
#include "x86_bsd.h"
#include "x86_linux.h"

arch *	shellcodes[] = {
	&hppa_hpux,
	&mips_irix,
	&sparc_solaris,
	&x86_bsd,
	&x86_linux,
	NULL,
};


#endif

