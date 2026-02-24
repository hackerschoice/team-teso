/* fornax distributed packet network
 *
 * by team teso
 *
 * scripting compiler routines
 */

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include "../../shared/common.h"
#include "branch.h"
#include "call.h"
#include "compiler.h"
#include "condition.h"
#include "element.h"
#include "script.h"
#include "symbol.h"


extern int	yydebug;
extern FILE *	yyout;

element **	gl_script;

char *		cp_input_ptr;
int		cp_input_lim;

jmp_buf		cp_yy_error_jmp;

extern int	yyparse (void);


/* yacc functions
 */

int
yyerror (char *str)
{
	/* to handle that errors, go to compiler
	 */
	longjmp (cp_yy_error_jmp, 1);

	exit (EXIT_FAILURE);
}


int
yywrap (void)
{
#ifdef YYDEBUG
	printf ("yywrap called\n");
#endif
	return (1);
}


/* input functions
 *
 * cp_input_lim is the number of bytes stored in the buffer pointed to by
 * cp_input_ptr. the pointer and the value of cp_input_lim will change while
 * parsing the input
 */

/* cp_parse
 *
 * parse a action string pointed to by `buf' with a length of `buf_len'
 *
 * return the parsed action structure
 */

element **
cp_compile (char *buf, int buf_len)
{
	gl_script = NULL;
	cp_input_ptr = buf;
	cp_input_lim = buf_len;

#ifdef YYDEBUG
	yydebug = 1;
#endif

	/* set compilation error jump point, if called handle the errors
	 */
	if (setjmp (cp_yy_error_jmp) != 0) {
		if (gl_script != NULL)
			elem_list_free (gl_script);

		return (NULL);
	}

	yyparse ();


	return (gl_script);
}


/* cp_yyinput
 *
 * input functions for the yacc parser to feed strings into it
 *
 * return number of bytes "read"
 */

int
cp_yyinput (char *buf, int size_max)
{
	int	n = 0;

	n = (size_max >= cp_input_lim) ?
		(cp_input_lim) :
		(size_max);

	if (n > 0) {
		memmove (buf, cp_input_ptr, n);
		cp_input_ptr += n;
		cp_input_lim -= n;
	}

	return (n);
}


