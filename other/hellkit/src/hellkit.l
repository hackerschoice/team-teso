%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int in_main = 0;
int j = 0;
char opcode[1000];
char hellfunction[1000];
int whitespace = 0;
#define NOP 0x90
%}

%start OPCODE ADRESS

%%

^[0-9a-f]+ |
^\ [0-9a-f]+		{ BEGIN ADRESS; }

<ADRESS>[0-9a-f]{2} 	{ 
			  BEGIN OPCODE;
			  if (in_main)
			          opcode[j++] = strtol(yytext, NULL, 16);
			 
		        }
<OPCODE>[0-9a-f]{2}	{
			  if (in_main)
			          opcode[j++] = strtol(yytext, NULL, 16);
			 
		        }
<OPCODE>[ \t]{2,1000}	{ 
			  BEGIN 0;   
			}
<ADRESS>\<[^\n\>]+\>    { 
  			  printf("found %s ", yytext);
			  if (strstr(yytext, hellfunction)) {
				  printf(" -- OK. Do it.\n");
				  in_main = 1;
			  } else {
				  printf(" -- skipping.\n");
				  in_main = 0;
			  }
                        }
.        ;
[ \t]+	 ;	/* skip whitespace */
\n	 ; 	/* skip newline */

%%
