#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <kapp.h>


int main(int argc, char **argv)
{
      KApplication *base = new KApplication(argc, argv);

      base->exec(); 
      return 0;
}
 
