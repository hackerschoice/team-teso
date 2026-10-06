%{
/* turning the '.section data' into .text section,
 * so all strings are in code. Necessary for shellcodes.
 */
#include <stdio.h>

int datafound = 0;
%}

%%

\.section[^\n]+data	{ 
			  printf(".text\n.align 4\n");
			  printf("main: jmp .L666\n");
			  datafound++;
                        }
\.text		        {
			  if (datafound) 
				  printf(".L666:\n");
		          
		        }
main\:		        {
			  if (!datafound)
				printf("%s", yytext);
		        }
[ \t]	ECHO;
\n	ECHO;
.	ECHO;

%%

int main(int argc, char **argv)
{
	return yylex();
}
