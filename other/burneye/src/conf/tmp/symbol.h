/* fornax - distributed network
 *
 * by team teso
 *
 * symbol management include file
 */

#ifndef	FNX_SYMBOL_H
#define	FNX_SYMBOL_H

typedef struct	sym_elem {
	char		*key;	/* string of variable name */
	char		*value;	/* NULL or string */
} sym_elem;


/* sym_subst
 *
 * substitute symbol information contained in string `str' using the global
 * symbol table
 *
 * return newly allocated char pointer
 */

char *	sym_subst (sym_elem **stab, char *str);


/* sym_elem_create
 *
 * symbol element constructor. create a new symbol element and set values
 * to `key' and `value'
 *
 * return pointer to new sym_elem structure
 */

sym_elem *	sym_elem_create (char *key, char *value);


/* sym_elem_free
 *
 * free symbol element pointed to by `se'
 *
 * return in any case
 */

void	sym_elem_free (sym_elem *se);


/* sym_elem_add
 *
 * add a symbol element pointed to by `elem' to the symbol table pointed to
 * by `tab'. if the table doesn't exist yet, just create it
 *
 * return in any case
 */

sym_elem **	sym_elem_add (sym_elem **tab, sym_elem *elem);


/* sym_remove
 *
 * remove a symbol with the key `key' from the symbol table pointed to by
 * `tab'
 *
 * return in any case
 */

sym_elem **	sym_remove (sym_elem **tab, char *key);


/* sym_add
 *
 * create a new symbol table entry in the table `tab'. if `tab' is empty or
 * is a NULL pointer create a new table. add the key `key' with the value
 * `value' to this table. if it already exists within the table overwrite it.
 * if `value' is a NULL pointer remove the element from the table, freeing
 * the table if it was the last symbol entry.
 *
 * return pointer to modified list
 */

sym_elem **	sym_add (sym_elem **tab, char *key, char *value);


/* sym_resolve
 *
 * find the character value associated to the key `key' in the symbol table
 * `stab'
 *
 * return pointer to ASCIIZ value on success
 * return NULL on failure
 */

const char *	sym_resolve (sym_elem **stab, char *key);


/* sym_free
 *
 * free a symbol table pointed to by `stab'
 *
 * return in any case
 */

void	sym_free (sym_elem **stab);


#endif

