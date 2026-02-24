/*
 * stoi16.cpp:
 * written by palmers / teso
 */
#include <stoi16.hpp>

  unsigned int stoi16 (string x)
  {
    int			num = 0,
			base = 1,
			z = x.length () - 1;
    unsigned int	y = 0;

    while (z >= 0)
      {
        if (x[z] <= '9' && x[z] >= '0')
          num = x[z] - '0';
        if (x[z] <= 'f' && x[z] >= 'a')
          num = x[z] - 'a' + 10;
        if (x[z] <= 'F' && x[z] >= 'A')
          num = x[z] - 'A' + 10;

        y += num * base;
        base *= 16;
        z--;
      }
    return y;
  }

