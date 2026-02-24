/*
 * readsym.cpp:
 * written by palmers / teso
 */
#include <Kermit>
#include <iostream>
#include <fstream>

#define PROGRAM	"writesym"
#define VERSION	"0.1"
#define AUTHOR	"palmers / teso"


void
usage (char *a)
{
  cout << PROGRAM << VERSION << " by " << AUTHOR << endl;
  cout << endl;
  cout << "Usage: " << a << " [options] <d|p> <offset> <length>" << endl;
  cout << "Options:" << endl;
  cout << "\t-x:\t where x is 1, 2, 3: ... " << endl;
  cout << endl;
  exit (0);
}


int
main (int argc, char **argv)
{
  rwKernel		*rw = NULL;
  char			*inBuf = NULL;
  unsigned long		y = 0,
			length = 0,
			out_offset = 0,
			offset = CONF_1GB;
  int			x = 0;

  if (argc < 4)
    usage (argv[0]);

  while (x < argc)
    {
      if (argv[x][0] == '-')
	{
	  switch (argv[x][1])
	    {
            case '1':
              offset = CONF_1GB;
              break;
            case '2':
              offset = CONF_2GB;
              break;
            case '3':
              offset = CONF_3GB;
              break;
	    case 'h':
	      usage (argv[0]);
	      break;
	    default:
	      usage (argv[0]);
	      break;
	    }
	}
      x++;
    }

  if (argv[argc - 3][0] == 'd')
    rw = new rwKernel (DEVMEM, offset);
  else if (argv[argc - 3][0] == 'p')
    rw = new rwKernel (PROCKCORE, offset);

  out_offset = stoi16 (string (argv[argc - 2]));
  length = stoi16 (string (argv[argc - 1]));

  if (length == 0)
    {
      cerr << "HaHa" << endl;
      abort ();
    }

  inBuf = new char[length + 1];

  cin.setf (ios::hex, ios::basefield);
  while (!cin.eof ())
    {
      cin >> x;
      if (y < length)
	inBuf[y++] = (x & 0xff);
    }
  cin.setf (ios::dec, ios::basefield);

  rw->write (inBuf, length, out_offset);
  delete inBuf;
  return 0;
}
