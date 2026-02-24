/*
 * readsym.cpp:
 * written by palmers / teso
 */
#include <Kermit>
#include <iostream>
#include <fstream>

#define PROGRAM	"readsym"
#define VERSION	"0.1"
#define AUTHOR	"palmers / teso"


void dump_c_array (char *arr, char *b, int x)
{
  int y;
  cout.setf (ios::hex, ios::basefield);
  cout << "char " << arr << "[] = {" << endl;
  for (y = 0; y < x; y++)
    {
      cout << "0x" << ((int) b[y] & 0xff);
      if (y != (x - 1))
	cout << ", ";
      if (!(y % 10))
	cout << endl;
    }
  cout << endl << "};" << endl;
  cout.setf (ios::dec, ios::basefield);
}


void dump (char *a, int x)
{
  int y;
  cout.setf (ios::hex, ios::basefield);

  for (y = 0; y < x; y++)
    {
      if ((a[y] & 0xff) < 16)
	cout << '0';
      cout << ((int) a[y] & 0xff) << ' ';
    }
  cout.setf (ios::dec, ios::basefield);
  cout << endl;
}

void usage (char *a)
{
  cout << PROGRAM << VERSION << " by " << AUTHOR << endl;
  cout << endl;
  cout << "Usage: " << a << " [options] <d|p> <offset> <length>" << endl;
  cout << "Options:" << endl;
  cout << "\t-x:\t where x is 1, 2, 3: the amount of ram in GB the system is ought to run" << endl;
  cout << "\t-c <name>:\t dump the read data as a c array" << endl;
  cout << endl;
  exit (0);
}


int main (int argc, char **argv)
{
  rwKernel		*rw = NULL;
  char			*inBuf = NULL,
			*arr_name = NULL;
  unsigned long		length = 0,
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
            case 'c':
              arr_name = argv[x + 1];
	      x++;
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

  offset = stoi16 (string (argv[argc - 2]));
  length = stoi16 (string (argv[argc - 1]));

  inBuf = new char[length + 1];
  rw->read (inBuf, length, offset);

  if (arr_name != NULL)
    {
      dump_c_array (arr_name, inBuf, length);
      delete inBuf;
      exit (0);
    }

  dump (inBuf, length);
  delete inBuf;
  return 0;
}
