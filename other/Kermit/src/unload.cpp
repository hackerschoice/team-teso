/*
 * unload.cpp:
 * written by palmers / teso
 */
#include <Kermit>
#include <string>
#include <iostream>
#include <fstream>
#include <stack>

#define PROGRAM		"unload"
#define VERSION		"0.0.1"
#define AUTHOR		"palmers / teso"

#define LINE_LENGTH	16384


void usage (char *s)
{
  cout << PROGRAM << VERSION << " by " << AUTHOR << endl;
  cout << "Usage: " << s << " [options] <file>" << endl;
  cout << "Options:" << endl;
  cout << "\t-l:\t restore in linear order [default: reversed order]" << endl;
  cout << endl;
  exit (0);
}


int main (int argc, char **argv)
{
  bool		linear = false;
  int		x = 0;
  ifstream	fs;
  char		line[LINE_LENGTH + 1];
  Patch		*tp = NULL;
  rwKernel	*rw = NULL;

  if (argc < 2)
    usage (argv[0]);

  for (x = 1; x < argc; x++)
    {
      if (argv[x][0] == '-')
	{
	  switch (argv[x][1])
	    {
	      case 'l':
		linear = true;
		break;
	      default:
		cout << "unknow option: " << argv[x] << endl;
		usage (argv[0]);
		break;
	    }
	}
    }

  fs.open (argv[argc - 1]);
  if (!fs.is_open ())
    {
      cerr << "failed to open \"" << argv[argc - 1] << "\"" << endl;
      abort ();
    }

  if (linear)
    {
      while (!fs.eof ())
	{
          fs.getline (line, LINE_LENGTH, '\n');
          tp = new Patch (string (line), rw);
          tp->remove ();
	  delete tp;
	}
    }
  else
    {
      stack<Patch *> pstack;
      while (!fs.eof ())
	{
          fs.getline (line, LINE_LENGTH, '\n');
          tp = new Patch (string (line), rw);
          pstack.push (tp);
	}

      while (!pstack.empty ())
	{
	  tp = pstack.top ();
	  tp->remove ();
	  delete tp;
	  pstack.pop ();
	}
    }

  return 0;
}
