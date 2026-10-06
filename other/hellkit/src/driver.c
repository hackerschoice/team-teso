/*** Driver for stealth's hellkit.
 *** (C) 1999/2000 by Stealth under the terms of the GPL.
 ***/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
   	char cc[1000];
        char *a[] = {"./hellkit", "a.s", NULL};
        
   	if (argc < 2) {
           	printf("%s [c-file]\n", argv[0]);
                exit(0);
        }
        memset(cc, 0, 1000);
        printf("compiling %s ...\n", argv[1]);
	
	/* first compile with special flags */
	sprintf(cc, "cc -S -fPIC -O3 -finline-functions %s -o x.s", argv[1]);
	system(cc);
	memset(cc, 0, 1000);
	
	/* then move strings to .text section */
	printf("turning .data to .text ...\n");
	system("./data2text<x.s>ok.s");
	
	/* 3rd: compile so patched asm-file */
	printf("recompiling ...\n");
	sprintf(cc, "cc ok.s -o x.o");
        system(cc);
        memset(cc, 0, 1000);
	
	printf("objdumping ... \n");
	
	/* disassemble it */
        system("objdump --disassemble x.o --section=.text>a.s");
	printf("analyzing ...\n");
	
	/* and last generate shellcode */
        system("./hellkit<a.s hellcode.c");
	printf("\ncleaning.\n");
	unlink("./a.s");
	unlink("./x.o");
	unlink("./ok.s");
	unlink("./x.s");
	printf("Current hellcode can be found in hellcode.c\n");
        return 0;
}

