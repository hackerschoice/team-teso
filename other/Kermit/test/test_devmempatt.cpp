#include <DevMemPatt.hpp>
#include <SymbolFingp.hpp>
#include <iostream>


#define PROGRAM		"findsym"
#define AUTHOR		"palmers / teso"
#define VERSION		"0.0.2"


void usage (char *s)
{
  cout << PROGRAM << VERSION << " by " << AUTHOR << endl;
  cout << "Usage: " << s << " [Options] name1 [name2 ... nameN]" << endl;
  cout << "Options:" << endl;
  cout << endl;
  exit (0);
}


int main (int argc, char **argv)
{
  int x = 1;
  DevMemPatt *a = new DevMemPatt ();
  SymbolFingp *b = new SymbolFingp ();

  if (argc < 2)
    usage (argv[0]);

  cout.setf (ios::hex, ios::basefield);
  while (x < argc)
    {
      if (argv[x][0] == '-')
	{
	  switch (argv[x][1])
	    {
	      default:
		cerr << "Illegal option!" << endl;
		usage (argv[0]);
	    }
	}
      else
	{
	  cout << argv[x] << '\t' << a->find_patt (b->getFinger (string (argv[x]))) << endl;
	}
      x++;
    }

  return 0;
}
