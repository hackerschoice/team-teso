/* burneye - configuration file lexer
 *
 * -scut
 */

%{

#include <string.h>
#include "../common.h"

%}

%%

[\n\t ]+	;

\{	{
	return (EXPR_BLOCK_BEGIN);
	}

\}	{
	return (EXPR_BLOCK_END);
	}

\"[^\"]*\"	{
	cflval.str = xstrdup (cftext + 1);
	cflval.str[strlen (cflval.str) - 1] = '\0';

	return (QSTRING);
	}

function	{
	return (FUNCTION);
	}

0x[0123456789abcdef]+	{
	sscanf (cftext, "0x%lx", &cflval.num);

	return (NUM);
	}

[0123456789]+ {
	sscanf (cftext, "%lu", &cflval.num);

	return (NUM);
}

.	return (cftext[0]);


