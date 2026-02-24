/*
 * Sample vulnerable program for HP-UX buffer overflows case study
 */
#include <stdio.h>
#include <stdlib.h>


unsigned long get_sp(void)
{
   __asm__("copy %sp,%ret0 \n");
}

void baz(char *argument) {
    char badbuf[200];

	printf("badbuf ptr is: %p\n",badbuf);
	strcpy(badbuf,argument);
}

void foo(char *arg) {

    baz(arg);

}

int main(int argc, char **argv) {
char *param;

printf("vuln stack is: 0x%X\n",get_sp());
param=getenv("VULNBUF");
foo(param);

return 0;
}
