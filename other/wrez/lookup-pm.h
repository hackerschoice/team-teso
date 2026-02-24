
#ifndef	LOOKUP_H
#define	LOOKUP_H

#include <elf.h>

/* generic type definition to be used when the peek-mem feature is required
 *
 * on all functions, the `pf' parameter is the function that peeks into the
 * memory at the given address, returning the 32 bit word at its place
 */
typedef unsigned int (* peekmemfunc)(void *);


/* lib_ismapped
 *
 * walk through the list of all mapped libraries and perform a strstr
 * substring search on the library name with the string `str' as needle.
 *
 * example:  if (lib_ismapped (0x08048000, "libc.so")) {
 *
 * return 0 if the library is not mapped
 * return 1 if the library is mapped
 */

int
lib_ismapped (peekmemfunc pf, void *mybase, char *str);


/* symbol_resolve
 *
 * try to resolve the function symbol with the name `sym_name' within the
 * current executeable. the base address (first byte of .text, first byte of
 * first PT_LOAD segment) is needed to locate the tables necessary for the
 * lookup. it is normally 0x08048000 for a gcc compiled linux binary.
 *
 * return pointer to function named `sym_name' on success
 * return NULL in case of failure (symbol was not found)
 */

void *
symbol_resolve (peekmemfunc pf, void *mybase, char *sym_name);


/* got_funcloc
 *
 * try to locate the function `name's got entry address. the executeable base
 * must be given through `mybase'. this is where the elf header is supposed to
 * be. the difference of this function to symbol_resolve is that you can only
 * find functions used by the host program with this one, while symbol_resolve
 * will locate any mapped one. also, this function returns a pointer to the
 * GOT address, not the address itself. by changing the GOT entry you can
 * redirect the execution of the host process. but be advised, that the code
 * you are redirecting it to has to be mapped.
 *
 * return NULL on failure (function not found, insufficient dynamic info)
 *     this is often the case, when the host program does not use the function
 * return pointer to GOT entry on success. [retval] is the address itself.
 */

Elf32_Word *
got_funcloc (peekmemfunc pf, void *mybase, char *name);

Elf32_Word *
got_funcloc_dyn (peekmemfunc pf, Elf32_Dyn *dyno, Elf32_Addr loadbase,
	char *name);


/* got_funcloc_array
 *
 * build an array of GOT locations through all available link maps. the base
 * of the current elf is needed (`mybase'). the name of the function symbol
 * to be resolved is `name', and the array will be put at `darr', where no
 * more than `darr_len' entries will be put. if `substr' is non-NULL, only
 * libraries with a full pathname containing `substr' will be processed.
 *
 * return the number (< darr_len) of entires stored, 0 for none
 */

int
got_funcloc_array (peekmemfunc pf, void *mybase, char *name,
	Elf32_Word *darr[], int darr_len, char *substr);

#endif

