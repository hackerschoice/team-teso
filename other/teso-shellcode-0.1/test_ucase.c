#include <ctype.h>
#include "shell_ucase.h"

void minidump()
{
    char *x = shellcode;
    while( *x ) {
	if( isprint( *x ) )
	    printf( "'%c', ", *x );
	else
	    printf( "0x%02x, ", *x );
	x++;
    }
}

char * uppercase( char *str )
{
    while( *str ) { *str = toupper( *str ); str++; } 
}

int main()
{
    int *ret;
    uppercase( shellcode );

    ret = ( int * )&ret + 2;
    *ret = ( int )shellcode;
    return 0;
}
