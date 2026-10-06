#include "shell_normal.h"

int main()
{
    int *ret;
    ret = ( int * )&ret + 2;
    *ret = ( int )shellcode;
    return 0;
}
