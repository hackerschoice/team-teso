#include <itos16.hpp>
#include <iostream>


int main ()
{
  cout << itos16 (0x31337) << endl;
  cout << itos16 (0x7) << endl;
  cout << itos16 (0x1) << endl;
  cout << itos16 (0x131337) << endl;
  cout << itos16 (0x1131337) << endl;
  cout << itos16 (0x81131337) << endl;

  return 0;
}
