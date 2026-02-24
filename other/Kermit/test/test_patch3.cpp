#include <Kermit>
#include <iostream>
#include <fstream>
#include <string>

int main ()
{
  Patch foo;
  cout << "Enter ..." << endl;
  cin >> foo;

  cout << foo;
//  foo.dump (string ("TEST"));
  return 0;
}
