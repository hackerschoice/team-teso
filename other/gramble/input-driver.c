/* gramble - grammar ramble
 *
 * team teso
 *
 * main grammar parser driver functions
 */

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "input.h"


extern int yydebug;
extern FILE * yyout;
extern int yyparse (void);


void *	in_grammar = NULL;	/* parser return */

char *	in_input_ptr;
int	in_input_lim;

jmp_buf	in_yy_error_jmp;	/* to catch errors in parser */


/* overridden yacc functions
 */

int
yyerror (char *str)
{
	longjmp (in_yy_error_jmp, 1);

	exit (EXIT_FAILURE);
}


int
yywrap (void)
{
	return (1);
}


/*** driver interface
 */

/* in_parse
 *
 * parse a grammar from buffer pointed to by 'buf', which is 'buf_len' bytes
 * long.
 *
 * return NULL on failure
 * return pointer to grammar on success
 */

void *	/* FIXME: real pointer */
in_parse (char *buf, int buf_len)
{
	in_grammar = NULL;


	in_input_ptr = buf;
	in_input_lim = buf_len;

	if (setjmp (in_yy_error_jmp) != 0) {
		if (in_grammar != NULL)
			return (NULL);

		/* FIXME: free all associated memory */
		/* freebla (in_grammar) */
		return (NULL);
	}

	yyparse ();

	return (in_grammar);
}


/* in_yyinput
 *
 * override yyinput functionality to allow more flexible parsing. internally
 * used, never called by outsiders.
 *
 * return number of bytes read
 */

int
in_yyinput (char *buf, int size_max)
{       
	int	n = 0;

	n = (size_max >= in_input_lim) ? in_input_lim : size_max;
	if (n > 0) {
		memmove (buf, in_input_ptr, n);
		in_input_ptr += n;
		in_input_lim -= n;
	}

	return (n);
}

