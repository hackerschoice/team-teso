#include <iostream>
#include <string>
#include <algorithm>

main ()
{
  string a = "Hallo,bla: foo!";
  int x = 0;
  string b;

  cout << count (a.begin (), a.end (), 'l') << endl;
  x = a.find_first_of (",");
  b.resize (x + 1);
  a.copy (b.begin (), x);
  cout << b << endl;
  a.erase (0, x + 1);

  cout << b << endl;
  cout << a << endl;
}
