#include <SymbolTable.hpp>
#include <string>

/*
 * default files:
 * System.map
 * SymbolFind.conf
 * SymbolTableDump
 */
int main ()
{
  unsigned int x = 0;
  SymbolTable *a = NULL;

  cout.setf (ios::hex, ios::basefield);
  a = new SymbolTable ();

  cout << "Starting ..." << endl;
  x = a->getSymbol (string ("sys_exit"));
  cout << "x = " << x << endl;

  cout << a->findSymbol (string ("sys_exit")) << endl;

  x = a->getSymbol (string ("sys_exit"));
  cout << "x = " << x << endl;
  return 0;
}

