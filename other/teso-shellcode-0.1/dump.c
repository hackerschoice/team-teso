// small binary-file dumper

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

int main( int argc, char **argv )
{
	FILE *in;
	int i;
	unsigned char c;

	if( argc < 3 ) {
		printf( "dump file array-name\n", argv[ 0 ] );
		exit( 1 );
	}

	if( !( in = fopen( argv[ 1 ], "rb" ) ) ) {
		printf( "can't open %s\n", argv[ 1 ] );
		exit( 1 );
	}

	printf( "static char %s[] = {\n", argv[ 2 ] );
	i = 0;
	while( fread( &c, 1, 1, in ) ) {
		if( isprint( c ) ) printf( "'%c', ", c );
		else printf( "0x%02x, ", c );
		if( !( ++i % 10 ) ) printf( "\n" );
	}
	printf( " 0 };\n" );

	fclose( in );
	return 0;
}

