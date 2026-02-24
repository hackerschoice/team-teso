/*
 * findsym.cpp:
 * written by palmers / teso
 */
#include <DevMemPatt.hpp>
#include <SymbolFingp.hpp>
#include <iostream>


#define PROGRAM		"findsym"
#define AUTHOR		"palmers / teso"
#define VERSION		"0.0.2"


void usage (char *s)
{
  cout << PROGRAM << VERSION << " by " << AUTHOR << endl;
  cout << "Usage: " << s << " [Options] name0 [name1 ... nameN]" << endl;
  cout << "Options:" << endl;
  cout << "\t-s:\t\t silent mode" << endl;
  cout << "\t-f <file>:\t set config file to <file>" << endl;
  cout << endl;
  exit (0);
}


int main (int argc, char **argv)
{
  bool silent = false;
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
	      case 's':
		if (silent == false)
		  silent = true;
		else
		  silent = false;
		break;
	      case 'f':
		if (b != NULL)
		  delete b;
		b = new SymbolFingp (string (argv[++x]));
		break;
	      default:
		cerr << "Illegal option!" << endl;
		usage (argv[0]);
		break;
	    }
	}
      else
	{
	  if (silent)
	    cout << a->find_patt (b->getFinger (string (argv[x]))) << endl;
	  else
	    cout << argv[x] << '\t' << a->find_patt (b->getFinger (string (argv[x]))) << endl;
	}
      x++;
    }

  delete a;
  delete b;
  return 0;
}
