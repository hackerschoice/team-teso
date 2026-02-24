#include <Patch.hpp>
#include <SymbolTable.hpp>
#include <rwKernel.hpp>
#include <string>

void bla_foo (char *n, bool a)
{
  if (a == false)
    {
      cout << n << " Failed" << endl;
      abort ();
    }
}


int main ()
{
  bool foo = false;
  Patch *mall = NULL;
  SymbolTable *tab = NULL;
  Addr2AddrList *x = NULL;
  rwKernel *y = NULL;
  unsigned char *tmp = NULL;
  int w = 0;

  unsigned char sys_malloc[] =
	"\x55\x89\xe5\x83\xec\x14\x53\xc7\x45\xfc\xee\xee"
	"\xf8\xf8\xc7\x45\xf8\x00\x00\x00\x00\x83\xc4\xf8"
	"\x6a\x15\x8b\x45\x08\x50\x8b\x5d\xfc\xff\xd3\x83"
	"\xc4\x10\x89\xc0\x89\x45\xf8\x8b\x55\xf8\x89\xd0"
	"\xeb\x06\x8d\xb6\x00\x00\x00\x00\x8b\x5d\xe8\x89"
	"\xec\x5d\xc3\x90";

  y = new rwKernel ();
  genDummyValMap ();
  tab = new SymbolTable (y);


/* look up all needed symbols */
  foo = tab->findSymbol (string ("init"));
  bla_foo ("init", foo);
  foo = tab->findSymbol (string ("kmalloc"));
  bla_foo ("kmalloc", foo);


  cout << "Found all needed symbols, proceeding .." << endl;
  x = genReplaceValMap (tab);
  if (x == NULL)
    {
      cout << "Foo!" << endl;
      abort ();
    }

/* insert malloc function [overwritting init] */
  cout << "Creating patch" << endl;
  mall = new Patch (sys_malloc, 72, tab->getSymbol ("init"));

  cout << "linking" << endl;
  mall->link (x);
  foo = mall->wasChanged ();
  bla_foo ("link", foo);
  cout << "appling now ..." << endl;
  mall->apply (y);
  cout << "done." << endl;
  return 0;
}

