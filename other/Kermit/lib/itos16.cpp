/*
 * itos16.cpp:
 * written by palmers / teso
 */
#include <itos16.hpp>
#include <iostream>

  string itos16 (unsigned int x)
  {
    char		t[] = "0123456789abcdef";
    string		y;
    unsigned int	a,
			base = 1,
			z = 0;

    while (base < x && z++ < 7)
      base *= 16;

    if (z != 8 && z != 0)
      base /= 16;

    while (base != 1)
      {
        a = 0;
        while (x >= base)
          {
	    a++;
	    x -= base;
          }
        y += t[a];
        base /= 16;
      }
    y += t[x];
    return y;
  }

