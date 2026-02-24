/* fornax - distributed packet network
 *
 * by team teso
 *
 * lex command lexical analyzer
 */


%{
#undef	yywrap

#include <string.h>
#include "../../shared/common.h"
#include "branch.h"
#include "call.h"
#include "compiler.h"
#include "condition.h"
#include "element.h"
#include "symbol.h"
#include "y.tab.h"

#undef	ECHO
#undef	YY_INPUT
#define	YY_INPUT(b, r, ms) (r = cp_yyinput (b, ms))

%}

%%

[\n\t ]+	;	 /* strip any whitespaces */

\{	{
		return (EXPR_BLOCK_BEGIN);
	}

\}	{
		return (EXPR_BLOCK_END);
	}

\"[^\"]*\"	{
			yylval.str = xstrdup (yytext + 1);
			yylval.str[strlen (yylval.str) - 1] = '\x00';

			return (ASTRING);
		}

[iI][fF]	{
			return (IF);
		}

[eE][lL][sS][eE]	{
				return (ELSE);
			}

\$[a-zA-Z\_]+[a-zA-Z0-9\_]*	{
					yylval.str = xstrdup (yytext);

					return (VARIABLE);
				}

(\&\&)|(\|\|)	{
			if (strcmp (yytext, "&&") == 0)
				yylval.logoper = LO_AND;
			else if (strcmp (yytext, "||") == 0)
				yylval.logoper = LO_OR;

			return (LOG_OPER);
		}

(\=\=)|(\>\=)|(\<\=)|(\!\=)	{
					if (strcmp (yytext, "==") == 0)
						yylval.eq = EQ_EQUAL;
					else if (strcmp (yytext, ">=") == 0)
						yylval.eq = EQ_GREATEQ;
					else if (strcmp (yytext, "<=") == 0)
						yylval.eq = EQ_LOWEREQ;
					else if (strcmp (yytext, "!=") == 0)
						yylval.eq = EQ_NOTEQ;

					return (EQ_OP);
				}

[a-zA-Z0-9\.\_]+	{
				yylval.str = xstrdup (yytext);

				return (STRING);
			}

[=]		{
			return (EQ);
		}

.	return (yytext[0]);


