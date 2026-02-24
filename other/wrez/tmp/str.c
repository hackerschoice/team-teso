
#include <stdio.h>

#define STRINGPTR(dst,string) \
{ \
	register unsigned char * regtmp; \
	\
	__asm__ __volatile__ ( \
		"	call	l0_%=\n\t" \
		"	.ascii	\""##string"\"\n\t" \
		"	.byte	0x00\n\t" \
		"l0_%=:	popl	%%eax\n\t" \
		: "=a" (regtmp)); \
\
	(dst) = regtmp; \
}


int
main (int argc, char *argv[])
{
	char *	foo;

	
	STRINGPTR(foo,"foobarcow");

	printf ("%s\n", foo);
}


