/*
 * telnet do/dont negotiation fingerprinting
 *    by Palmers / teso || pa1mers@gmx.de
 */

#include <telnetfp.hpp>


class main_prog
{
private:
tcp_socket con;
tdfpdb db;
short	verbose,
	timeout;


void
convert_ascii_to_bin (char *line, unsigned char *bin)
{
  char *tmp = NULL;

  line += 6;
  while (line != NULL)
    {
      *bin = atoi (line);
      bin++;
      if ((tmp = strstr (line, " ")) == NULL)
	return ;
      line = tmp + 1;
    }
}


public:

void
interactBin ()
  {
    unsigned char do_d[31], dont_d[31];

    db.open ();
    while (1)
      {
	memset (do_d, 0, 31);
	memset (dont_d, 0, 31);
	read (STDIN_FILENO, do_d, 30);
	read (STDIN_FILENO, dont_d, 30);
	db.find_in_db (do_d, dont_d);
	db.reset ();
      }
  }


void
interactAscii ()
  {
    unsigned char line[LINE_LENGTH + 1], do_d[31], dont_d[31];

    db.open ();
    while (1)
      {
        memset (do_d, 0, 31);
        memset (dont_d, 0, 31);
        memset (line, 0, LINE_LENGTH + 1);
        read (STDIN_FILENO, line, LINE_LENGTH);
	if (strstr ((char *) line, "DO:   ") != NULL)
	  {
	    convert_ascii_to_bin ((char *) line, do_d);
	    memset (line, 0, LINE_LENGTH + 1);
	    read (STDIN_FILENO, line, LINE_LENGTH);
	    if (strstr ((char *) line, "DONT: ") != NULL)
	      {
		convert_ascii_to_bin ((char *) line, dont_d);
	        db.find_in_db (do_d, dont_d);
		db.reset ();
	      }
	  }
      }
  }


int
switch_verbosity ()
  {
    return (verbose ^= 1);
  }


/*
 * void send_will_wont (unsigned char *):
 * reply to do / dont request with propper will / wont. 
 */
void
send_will_wont (unsigned char *a)
{
  unsigned char will[] = {IAC, WILL, 0, 0},
       wont[] = {IAC, WONT, 0, 0};
  while (strlen ((char *) a) > 0)
    {
      if (a[0] == IAC)
	{
	  if (a[1] == DO)
	    {
	      will[2] = a[2];
	      con.swrite ((char *) will);
	    }
	  else if (a[1] == DONT)
	    {
	      wont[2] = a[2];
	      con.swrite ((char *) wont);
	    }
	}
      a += 3;
    }
}


void
usage (char *s)
{
  printf ("Usage: %s [-v -d <file>] <host>\n", s);
  printf ("\t-v:\t\t turn off verbose output\n");
  printf ("\t-t <x>:\t\t set timeout for connect attemps\n");
  printf ("\t-d <file>:\t define from which file finger prints shall be read (default: %s)\n", DEFAULT_DB);
  printf ("\t-i (b|a):\t interactive mode. read either (b)inary or (a)scii fingerprints from stdin\n");
  exit (1);
}


main_prog (int argc, char **argv)
{
  int x = 1;
  printf (PROGRAM VERSION " by "AUTHOR "\n");
  verbose = 1;
  timeout = 5;

  db.init ();

  if (argc < 2)
    usage (argv[0]);
  while ((argc - 1) > x)
    {
      if (argv[x][0] == '-')
	{
	  switch (argv[x][1])
	    {
	      case 'v':
	 	switch_verbosity ();
		break;
	      case 't':
		x++;
		timeout = atoi (argv[x]);
		break;
	      case 'd':
		x++;
		if (!((x) < argc))
		  usage (argv[0]);
		db.set (argv[x]);
		break;
	      case 'i':
		x++;
		if (argv[x][0] == 'b')
		  {
		    interactBin ();
		  }
		else if (argv[x][0] == 'a')
		  {
		    interactAscii ();
		  }
		else
		  usage (argv[0]);
		break;
	      default:
		usage (argv[0]);
	    }
	}
      else
	usage (argv[0]);
      x++;
  }
  con.init ();
  check (argv[argc - 1]);
}


void
check (char *host)
{
  unsigned char *do_d = NULL, *dont_d = NULL;
  int x = 0;

  db.open ();
  alarm (timeout);
  if (con.sopen (host, 23) != 0)
    {
      printf ("sopen: can not connect to \"%s\"\n", host);
      exit (3);
    }
/*
 * 1.: get do's
 */
  if ((do_d = (unsigned char *) con.sread (30)) == NULL)
    {
      exit (4); 
    }
  if (verbose)
    {
      printf ("DO:   ");
      for (x = 0; x < strlen ((char *) do_d); x++)
        printf ("%d ", do_d[x]);
      printf ("\n");
    }

/*
 * 2.: reply will's
 */
  send_will_wont (do_d);

/*
 * 3.: get dont's
 */
  if ((dont_d = (unsigned char *) con.sread (30)) == NULL)
    {
      exit (5);
    }
  if (verbose)
    {
      printf ("DONT: ");
      for (x = 0; x < strlen ((char *) dont_d); x++)
        printf ("%d ", dont_d[x]);
      printf ("\n");
    }

/*
 * 4.: reply wont's
 */
  send_will_wont (dont_d);

  con.sclose ();

/*
 * look up fp, do some output
 */
  db.find_in_db (do_d, dont_d);
  db.close ();  
  exit (0);
}
};


void alarmHandler (int x)
{
  alarm (0);
  fprintf (stderr, "got timeout\n");
  return;
}


int
main (int argc, char **argv)
{
  siginterrupt(SIGALRM, 1);
  signal (SIGALRM, alarmHandler);

  main_prog a(argc, argv);
}
