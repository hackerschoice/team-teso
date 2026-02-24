#include <SystemMap.hpp>
#include <string>
#include <iostream>


int main ()
{
  SystemMap a = SystemMap ("System.map");
  cout.setf (ios::hex, ios::basefield);

  cout << "sys_fork " << a[string ("sys_fork")] << endl;
  cout << "sys_write " << a[string ("sys_write")] << endl;
  cout << "init " << a[string ("init")] << endl;
  return 0;
}
