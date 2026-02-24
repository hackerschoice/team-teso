/* fornax - distributed network
 *
 * by team teso
 *
 * scripting element includes
 */

#ifndef	FNX_ELEMENT_H
#define	FNX_ELEMENT_H


#define	ELEM_TYPE_CALL		1
#define	ELEM_TYPE_BRANCH	2
#define	ELEM_TYPE_SET		3

typedef struct {
	int		type;
	void *		data;
} element;


/* elem_list_free
 *
 * free a list of elements pointed to by `el'
 *
 * return in any case
 */

void	elem_list_free (element **el);


/* elem_add
 *
 * add element pointed to by `e' to the element list pointed to by `el'. if the
 * element list is empty, create a new one
 *
 * return a pointer to the modified/created element list
 */

element **	elem_add (element **el, element *e);


/* elem_create
 *
 * element constructor. create a new element structure
 *
 * return a pointer to the new structure
 */

element *	elem_create (void);


/* elem_free
 *
 * free the whole element pointed to by `e'
 *
 * return in any case
 */

void	elem_free (element *e);


/* elem_set_type
 *
 * set element type `type' for element pointed to by `e'
 *
 * return pointer to structure
 */

element *	elem_set_type (element *e, int type);


/* elem_set_data
 *
 * set element data to `data' for element pointed to by `e'
 *
 * return pointer to structure
 */

element *	elem_set_data (element *e, void *data);


#endif


