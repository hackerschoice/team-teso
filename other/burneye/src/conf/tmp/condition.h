/* fornax - distributed network
 *
 * by team teso
 *
 * scripting condition includes
 */

#ifndef	FNX_CONDITION_H
#define	FNX_CONDITION_H


#define	LO_OR		1
#define	LO_AND		2

#define	EQ_EQUAL	1
#define	EQ_GREATEQ	2
#define	EQ_LOWEREQ	3
#define	EQ_NOTEQ	4


typedef struct condition {
	struct condition *	cond1;
	int			logoper;
	struct condition *	cond2;

	char *			val1;
	int			eqop;
	char *			val2;
} condition;


/* cond_verify
 *
 * verify whether a condition is met or not
 *
 * return 1 if the condition is met
 * return 0 if not or an error was experienced during parsing
 */

int	cond_verify (condition *cnd);


/* cond_create
 *
 * condition constructor. create a new condition structure
 *
 * return a pointer to the new structure
 */

condition *	cond_create (void);


/* cond_free
 *
 * free the whole condition pointed to by `c'
 *
 * return in any case
 */

void	cond_free (condition *c);


/* cond_set_cond1
 *
 * set subcondition condition `c1' for condition `c'
 *
 * return pointer to structure
 */

condition *	cond_set_cond1 (condition *c, condition *c1);


/* cond_set_cond2
 *
 * set subcondition condition `c2' for condition `c'
 *
 * return pointer to structure
 */

condition *	cond_set_cond2 (condition *c, condition *c2);


/* cond_set_logoper
 *
 * set logical operator `lo' for the two subconditions in condition `c'.
 *
 * return pointer to structure
 */

condition *	cond_set_logoper (condition *c, int lo);


/* cond_set_eqop
 *
 * set equeality operator `eo' for the comparison in condition `c'.
 *
 * return pointer to structure
 */

condition *	cond_set_eqop (condition *c, int eo);


/* cond_set_val1
 *
 * set first value `val' in condition `c'
 *
 * return pointer to structure
 */

condition *	cond_set_val1 (condition *c, char *val);


/* cond_set_val2
 *
 * set second value `val' in condition `c'
 *
 * return pointer to structure
 */

condition *	cond_set_val2 (condition *c, char *val);


#endif


