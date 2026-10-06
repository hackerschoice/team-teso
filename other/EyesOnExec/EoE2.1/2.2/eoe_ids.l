%{
#include <stdio.h>
#include "eoe_ids.tab.h"
}%

[0-9]+	return UID;
':'	return ':';
[.]+	{ 
		strncpy(yylval.string, yytext, 1000); 
                return FILENAME;
        }
\n	;

