#include "portscan.h"

/*
 * Think strtok(), done over and over again.
 */

int parse_args(char *string,char **args,const char *delimiters,int maxargs)
{
        int a;
        char *ptr;

        for (a = 0; a < maxargs; a++)
                args[a]=NULL;

        a=0;
        ptr=string;
        while (a < maxargs) {
                if (!*ptr) break;
                args[a++]=ptr;
                while(!strchr(delimiters,*ptr) && *ptr!=0) ptr++;
                if (*ptr == 0)
                        break;
                else
                        *ptr++=0;
        }
        return(a);
}


