/*
 * call_syscall.c:
 * you can figure it out ;)
 * written by palmers / teso
 */
#include <stdio.h>
#include <errno.h>
#include <asm/unistd.h>

#define __NR_evilmalloc		251

int main ()
{
  int x = 1024;
  void *xx = NULL;

  _syscall1 (void *, evilmalloc, int, x);
  xx = evilmalloc (x);
  if ((unsigned int) xx == 0xffffffff)
    printf ("evilmalloc failed?\n");
  printf ("evilmalloc: %d bytes at %p\n", x, (unsigned int) xx);
  return 0;
}

