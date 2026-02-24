#include <Kermit>
#include <iostream>
#include <fstream>
#include <string>
#define LINE	"12345678,Clean: (73 50 73 50 73 50 73 50), (0 0 0 0 0 0 0 0)"

int main ()
{
  const string dump_f = string ("DUMP_FILE");
/*
  unsigned short x = 8;
  unsigned int y = 0x12345678;
  unsigned char z[] = "\x73\x50\x73\x50\x73\x50\x73\x50";

  Patch *foo = new Patch (z, x, y);
*/
  Patch *foo = new Patch (string (LINE));

  foo->dump (dump_f);
  return 0;
}
