/*
 * load.cpp:
 * written by palmers / teso
 */
#include <Kermit>
#include <string>
#include <iostream>
#include <fstream>
#include <stack>

#define PROGRAM		"load"
#define VERSION		"0.0.1"
#define AUTHOR		"palmers / teso"

#define LINE_LENGTH	16384


void usage (char *s)
{
  cout << PROGRAM << VERSION << " by " << AUTHOR << endl;
  cout << "Usage: " << s << " [options] <file>" << endl;
  cout << "Options:" << endl;
  cout << "\t-v:\t be verbose" << endl;
  cout << "\t-E:\t proceed even if errors occour" << endl;
  cout << endl;
  exit (0);
}


int main (int argc, char **argv)
{
  bool		verbose = false,
		err_continue = false;
  int		x = 0;
  ifstream	fs;
  char		line[LINE_LENGTH + 1];
  Patch		*tp = NULL;
  rwKernel	*rw = NULL;
  SymbolTable	*st = NULL;
  Addr2AddrList	*a2a = NULL;

  if (argc < 2)
    usage (argv[0]);

  for (x = 1; x < argc; x++)
    {
      if (argv[x][0] == '-')
	{
	  switch (argv[x][1])
	    {
	      case 'v':
		verbose = true;
		break;
	      case 'E':
		err_continue = true;
		break;
	      default:
		cout << "unknow option: " << argv[x] << endl;
		usage (argv[0]);
		break;
	    }
	}
    }

  rw = new rwKernel ();
  genDummyValMap ();
  st = new SymbolTable (rw);
  a2a = genReplaceValMap (st);

  fs.open (argv[argc - 1]);
  if (!fs.is_open ())
    {
      cerr << "failed to open \"" << argv[argc - 1] << "\"" << endl;
      abort ();
    }

  if (verbose)
    cout << "done." << endl;

  while (!fs.eof ())
    {
      fs.getline (line, LINE_LENGTH, '\n');
      tp = new Patch (string (line), rw);

      if (tp->isClean ())
        tp->link (a2a);

      if (tp->isLinked ())
        tp->apply ();
      else if (verbose)
	{
          cout << "#" << x << ": Linking Failed" << endl;
	  if (err_continue)
	    continue;
	  break;
	}
      if (tp->isApplied () && verbose)
         cout << "#" << x << ": Success" << endl;
      else
	{
	  cout << "#" << x << ": Applying Failed" << endl;
	  if (err_continue)
	    continue;
	  break;
	}
      delete tp;
    }
  if (verbose)
    cout << "done." << endl;
  fs.close ();
  return 0;
}
