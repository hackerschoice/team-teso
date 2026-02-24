/* fornax - distributed packet network
 *
 * by team teso
 *
 * yacc command parser
 */

%{
#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include "branch.h"
#include "call.h"
#include "compiler.h"
#include "condition.h"
#include "element.h"
#include "symbol.h"

extern element **	gl_script;

%}


%union {
	int		eq;		/* equality test operator */
	int		logoper;	/* logical operator */
	char *		str;		/* generic string pointer */
	element **	pp_element;
	element *	p_element;
	call *		p_call;
	branch *	p_branch;
	condition *	p_condition;
	sym_elem *	p_sym_elem;
	sym_elem **	pp_sym_elem;
}


%token	<eq>		EQ
%token	<eq>		EQ_OP
%token	<logoper>	LOG_OPER
%token	<str>		STRING
%token	<str>		ASTRING
%token	<str>		VARIABLE
%token	<str>		SET
%token	<str>		IF
%token	<str>		ELSE
%token	<str>		EXPR_BLOCK_BEGIN
%token	<str>		EXPR_BLOCK_END

%type	<pp_element>	script
%type	<pp_element>	block
%type	<pp_element>	elementlist
%type	<p_element>	element
%type	<p_call>	call
%type	<p_branch>	branch
%type	<p_condition>	condition
%type	<p_sym_elem>	set
%type	<pp_sym_elem>	setlist

%%


script:
		block
	{
		gl_script = $1;
	}

	;

/* a block is a list of expression elements. the block is started with a
 * `{' bracket and terminated by a `}' bracket. the simplest block just
 * consists out of "{}"
 */

block:
		EXPR_BLOCK_BEGIN elementlist EXPR_BLOCK_END
	{
		$$ = $2;
	}

	|	EXPR_BLOCK_BEGIN EXPR_BLOCK_END
	{
		$$ = NULL;
	}

	;

/* an elementlist is a concatation of single elements, which could be either
 * expressions, settings or blocks
 */

elementlist:
		elementlist element
	{
#ifdef DEBUG
		printf ("element %08x added to elementlist %08x\n", $2, $1);
#endif
		$$ = elem_add ($1, $2);
	}

	|	element
	{
#ifdef DEBUG
		printf ("element %08x added to elementlist NULL\n", $1);
#endif
		$$ = NULL;
		$$ = elem_add ($$, $1);
	}

	;


/* an element is actually the gut of a program. elements are the pieces that
 * are executed in a linear way, but an element can contain a block of other
 * elements *shrug*
 */

element:
		call
	{
#ifdef DEBUG
		printf ("call element %08x experienced \n", $1);
#endif
		$$ = elem_create ();
		$$ = elem_set_type ($$, ELEM_TYPE_CALL);
		$$ = elem_set_data ($$, $1);
	}

	|	branch
	{
#ifdef DEBUG
		printf ("branch element %08x experienced \n", $1);
#endif
		$$ = elem_create ();
		$$ = elem_set_type ($$, ELEM_TYPE_BRANCH);
		$$ = elem_set_data ($$, $1);
	}

	|	set
	{
#ifdef DEBUG
		printf ("set element %08x experienced \n", $1);
#endif
		$$ = elem_create ();
		$$ = elem_set_type ($$, ELEM_TYPE_SET);
		$$ = elem_set_data ($$, $1);
	}

	;

call:
		STRING '(' setlist ')'
	{
#ifdef DEBUG
		printf ("call with parameters to symbol \"%s\" experienced \n", $1);
#endif
		$$ = call_create ();
		$$ = call_set_name ($$, $1);
		$$ = call_set_parameters ($$, $3);
	}

	|	STRING '(' ')'
	{
#ifdef DEBUG
		printf ("call without parameters to symbol \"%s\" experienced \n", $1);
#endif
		$$ = call_create ();
		$$ = call_set_name ($$, $1);
		$$ = call_set_parameters ($$, NULL);
	}

	;

setlist:
		setlist set
	{
#ifdef DEBUG
		printf ("symbol %08x added to symbol table at %08x\n", $2, $1);
#endif
		$$ = sym_elem_add ($1, $2);
	}

	|	set
	{
#ifdef DEBUG
		printf ("symbol %08x added to NULL symbol table\n", $1);
#endif
		$$ = NULL;
		$$ = sym_elem_add ($$, $1);
	}

	;

set:
		STRING EQ ASTRING
	{
#ifdef DEBUG
		printf ("symbol pair (%s = \"%s\") created\n", $1, $3);
#endif
		$$ = sym_elem_create ($1, $3);
	}

	;

branch:
		IF '(' condition ')' block
	{
#ifdef DEBUG
		printf ("if block with condition at %08x and block at %08x created\n", $3, $5);
#endif
		$$ = br_create ();
		$$ = br_set_condition ($$, $3);
		$$ = br_set_block_if ($$, $5);
		$$ = br_set_block_else ($$, NULL);
	}

	|	IF '(' condition ')' block ELSE block
	{
#ifdef DEBUG
		printf ("if block with condition at %08x and blocks at %08x/%08x created\n", $3, $5, $7);
#endif
		$$ = br_create ();
		$$ = br_set_condition ($$, $3);
		$$ = br_set_block_if ($$, $5);
		$$ = br_set_block_else ($$, $7);
	}

	;

condition:
		'(' condition LOG_OPER condition ')'
	{
#ifdef DEBUG
		printf ("condition1 at %08x LOG_OPER condition2 at %08x created\n", $2, $4);
#endif
		$$ = cond_create ();
		$$ = cond_set_cond1 ($$, $2);
		$$ = cond_set_logoper ($$, $3);
		$$ = cond_set_cond2 ($$, $4);
		$$ = cond_set_val1 ($$, NULL);
		$$ = cond_set_val2 ($$, NULL);
	}

	|	STRING EQ_OP ASTRING
	{
#ifdef DEBUG
		printf ("%s EQ_OP \"%s\"\n", $1, $3);
#endif
		$$ = cond_create ();
		$$ = cond_set_cond1 ($$, NULL);
		$$ = cond_set_cond1 ($$, NULL);
		$$ = cond_set_val1 ($$, $1);
		$$ = cond_set_eqop ($$, $2);
		$$ = cond_set_val2 ($$, $3);
	}

	;

%%

#include "script.h"
#include "branch.h"
#include "call.h"
#include "compiler.h"
#include "condition.h"
#include "element.h"
#include "symbol.h"


