/* gramble - grammar ramble
 *
 * team teso
 *
 * grammar parser
 */

%{
#include <stdio.h>
#include <stdlib.h>
#include "input.h"

extern void *	in_grammar;

%}


%union {
	unsigned int	uint;	/* unsigned number (length) */
	unsigned char *	str;	/* generic ASCIIZ string pointer */
	void *		ugly;
}


%token	<str>	STR NSSTR NTERM TERM FILTER NEGFILTER SIZE
%token	<uint>	NUM

/* use % type here */
%type	<ugly>	prod prodr prodrelem poptl popt

%start	prodlist

%%

prodlist:
	prodlist prod
{
	in_grammar = NULL;
}
	| prod
{
	in_grammar = NULL;
}
	;

prod:	NTERM ':' prodr
{
	$$ = NULL;
}
	;

/* prodr, right side of a production */
prodr:	prodr prodrelem
{
	$$ = NULL;
}
	| prodrelem
{
	$$ = NULL;
}
	;

/* prodr, right side of a production */
prodrelem:	'[' prodr ']' poptl
{
	$$ = NULL;
}
	| NTERM
{
	$$ = NULL;
}
	| TERM
{
	$$ = NULL;
}
	;

/* production option list */
poptl:	poptl '(' popt ')'
{
	$$ = NULL;
}
	|
{
	$$ = NULL;
}
	;

popt:	FILTER ':' '/' NSSTR '/'
{
	fprintf (stderr, "FILTER: %s with /%s/\n", $1, $4);
	$$ = NULL;
}
	| NEGFILTER ':' '/' NSSTR '/'
{
	$$ = NULL;
}
	| SIZE ':' NUM '-' NUM
{
	$$ = NULL;
}
	;


%%

/* TODO: includes in parser come here
 */


