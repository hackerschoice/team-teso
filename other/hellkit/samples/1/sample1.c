#include "../../lib/int80.h"
#define NULL (void*)0

int main()
{
	char *a[]={"/bin/sh", NULL};
   	write(1, "Shell!\n", 7);
	execve(*a, a, NULL);
        return 0;
}

