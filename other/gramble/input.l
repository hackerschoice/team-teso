/* gramble - gammar ramble
 *
 * team teso
 *
 * grammar lexer
 */

%{
#undef	yywrap

#include <string.h>
#include "y.tab.h"
#include "input.h"

#undef	ECHO
#undef	YY_INPUT
#define	YY_INPUT(b, r, ms) (r = in_yyinput (b, ms))

%}

%%

[\n\t ]+ ;

\"[^\"]*\" {
	yylval.str = strdup (yytext + 1);
	yylval.str[strlen (yylval.str) - 1] = '\0';

	return (TERM);
}

[0-9]+ {
	sscanf (yytext, "%u", &yylval.uint);

	return (NUM);
}

0x[0-9abcdef]+ {
	sscanf (yytext, "0x%x", &yylval.uint);

	return (NUM);
}

[^\/]/\/ {
	yylval.str = strdup (yytext);

	return (NSSTR);
}

filter {
	return (FILTER);
}

\~filter {
	return (NEGFILTER);
}

size {
	return (SIZE);
}

