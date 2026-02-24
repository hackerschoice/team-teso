/* burneye - configuration file parser
 *
 * -scut
 */

%{

%}

%union {
	unsigned char *		str;
	unsigned long int	num;
}

%token	<str>	EXPR_BLOCK_BEGIN
%token	<str>	EXPR_BLOCK_END
%token	<str>	QSTRING
%token	<str>	FUNCTION
%token	<num>	NUM

/* types here */
/* %type <pp_element> script */

%%

configuration:
	
