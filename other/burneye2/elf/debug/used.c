
#include <stdio.h>
#include <stdlib.h>

int
main (int argc, char *argv[])
{
  unsigned int n, f;

  if (argc >= 2)
	n = atoi (argv[1]);
  else
	n = 200;

  for (f = 1 ; f < (n / 2) ; ++f)
    if (n % f == 0)
      printf ("factor: %d\n", f);

  return (0);
}


