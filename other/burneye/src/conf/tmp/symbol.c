/* fornax - distributed network
 *
 * by team teso
 *
 * symbol management routines
 */

#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "../../shared/common.h"
#include "symbol.h"

static int		sym_count (sym_elem **tab);
static sym_elem *	sym_elem_bykey (sym_elem **tab, char *key);
static sym_elem **	sym_elem_remove (sym_elem **tab, sym_elem *se);


/* sym_count
 *
 * count the number of elements within the symbol table pointed to by `tab'
 *
 * return the number of entries
 */

static int
sym_count (sym_elem **tab)
{
	int	count;

	if (tab == NULL)
		return (0);

	for (count = 0 ; tab[count] != NULL ; ++count)
		;

	return (count);
}


/* sym_elem_bykey
 *
 * search the symbol table for a structure element which matches the key value
 * of `key'. if `key' is NULL return the first element.
 *
 * return pointer to first found element on success
 * return NULL if element was not found
 */

static sym_elem *
sym_elem_bykey (sym_elem **tab, char *key)
{
	int		walker;

	if (tab == NULL)
		return (NULL);

	if (key == NULL)
		return (tab[0]);

	for (walker = 0 ; tab[walker] != NULL ; ++walker) {
		if (strcasecmp (tab[walker]->key, key) == 0)
			return (tab[walker]);
	}

	return (NULL);
}


/* sym_elem_remove
 *
 * remove an element pointed to by `se' from the symbol table pointed to by
 * `tab'
 *
 * return in any case
 */

static sym_elem **
sym_elem_remove (sym_elem **tab, sym_elem *se)
{
	int	walker;

	if (tab == NULL)
		return (NULL);

	for (walker = 0 ; tab != NULL && tab[walker] != NULL ;) {
		if (tab[walker] == se) {
			sym_elem_free (se);

			memmove (&tab[walker], &tab[walker + 1],
				(sym_count (&tab[walker + 1]) + 1) *
				(sizeof (sym_elem *)));

			tab = xrealloc (tab, (sym_count (tab) + 1) *
				sizeof (sym_elem *));
			tab[sym_count (tab)] = NULL;
		} else {
			++walker;
		}
	}

	return (tab);
}


char *
sym_subst (sym_elem **stab, char *str)
{
	int	var_count = 0;	/* variable-in-str counter */
	char *	stp_p;		/* step pointer */
	char *	new = NULL;	/* created string */

	if (str == NULL)
		return (NULL);

	/* count variables
	 */
	for (stp_p = str ; *stp_p != '\x00' ; ++stp_p) {
		if (*stp_p == '$')
			var_count += 1;
	}

	/* if string doesn't contain anything to substitute, just return a copy
	 */
	if (var_count == 0)
		return (xstrdup (str));

	for (stp_p = str ; *stp_p != '\x00' ; ++stp_p) {
		if (*stp_p == '$') {
			int	n;
			char	var_name[256];
			char *	var_content = NULL;

			memset (var_name, '\x00', sizeof (var_name));

			/* extract variable name
			 */
			for (n = 1 ; isalnum (stp_p[n]) != 0 ; ++n) {
				var_name[n - 1] = stp_p[n];
			}
			stp_p += (n - 1);
			if (strlen (var_name) > 0)
				var_content = (char *) sym_resolve (stab, var_name);

			if (var_content != NULL)
				alloccat (&new, var_content);
		} else {
			int	nv_len;	/* no variable length */

			for (nv_len = 1 ; stp_p[nv_len] != '$' &&
				stp_p[nv_len] != '\x00' ; ++nv_len)
				;
			allocncat (&new, stp_p, nv_len);
			stp_p += (nv_len - 1);
		}
	}

	return (new);
}


void
sym_elem_free (sym_elem *se)
{
	free (se->key);
	free (se->value);
	free (se);

	return;
}


sym_elem *
sym_elem_create (char *key, char *value)
{
	sym_elem *	new = xcalloc (1, sizeof (sym_elem));

	new->key = key;
	new->value = value;

	return (new);
}


sym_elem **
sym_elem_add (sym_elem **tab, sym_elem *elem)
{
	int		count;


	/* if table is empty or the symbol is not within table
	 */
	if (tab == NULL || sym_resolve (tab, elem->key) == NULL) {
		count = sym_count (tab);
		tab = xrealloc (tab, sizeof (sym_elem *) * (count + 2));
		tab[count] = elem;
		tab[count + 1] = NULL;
	} else {
		sym_elem *	elem_dupe;

		/* find element, then free the old data, overwritting it with
		 * the new value
		 */
		elem_dupe = sym_elem_bykey (tab, elem->key);
		free (elem_dupe->key);
		free (elem_dupe->value);
		elem_dupe->key = elem->key;
		elem_dupe->value = elem->value;
		free (elem);
	}

	return (tab);
}


sym_elem **
sym_remove (sym_elem **tab, char *key)
{
	sym_elem *	se;

	/* if there is nothing to remove, return at once
	 */

	if (tab == NULL)
		return (NULL);

	/* if tab is not NULL but no element is within the table
	 * then just free the table
	 */
	se = sym_elem_bykey (tab, key);
	if (se == NULL) {
		if (sym_count (tab) == 0) {
			free (tab);
			tab = NULL;
		}

		return (tab);
	}

	tab = sym_elem_remove (tab, se);

	return (tab);
}


sym_elem **
sym_add (sym_elem **tab, char *key, char *value)
{
	sym_elem *	new;


	if (key == NULL)
		return (tab);

	if (value == NULL) {
		tab = sym_remove (tab, key);
		return (tab);
	}

	new = sym_elem_create (key, value);
	tab = sym_elem_add (tab, new);

	return (tab);
}


const char *
sym_resolve (sym_elem **stab, char *key)
{
	int		walker;

	if (stab == NULL || key == NULL)
		return (NULL);

	for (walker = 0 ; stab[walker] != NULL ; ++walker) {
		if (strcasecmp (stab[walker]->key, key) == 0)
			return (stab[walker]->value);
	}

	return (NULL);
}


void
sym_free (sym_elem **stab)
{
	if (stab == NULL)
		return;

	/* while there are elements free the first element
	 */
	while (stab != NULL) {
		stab = sym_remove (stab, NULL);
	}

	return;
}


