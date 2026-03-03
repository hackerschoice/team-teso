/*  HiHo,
   this utility changes the host of a given username (all his logins affected)
   usage is utcl <user> <host> where host is the desired host (only 20 chars)

   this piec of software is mostly ripped from ute.c which i found on my hdd
   and dont know where it came from.. many thanks to the author of this one..
   thanks goes also out to xdr who gave me the idea of writing this (he wrote 
   such thingie, but then lost it @#$! ;)

   have fun...
   -hendy (flames to hendy@winterland.net)

   greetings: (oh, this is lame, i know) to #!teso, #hax, #hack

   // hope it's not too lame

 */

#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/file.h>
#include <fcntl.h>
#include <utmp.h>
#include <pwd.h>
#include <lastlog.h>
// #define UTMP_FILE "/var/run/utmp" /* should have been defined in utmp.h */
#define MAX_ENT 100

int 
main (int argc, char **argv)
{
  int item;
  struct utmp Entry[MAX_ENT + 1];
  off_t position[MAX_ENT + 1];
  FILE *fptr;

  if (argc < 3)
    {
      printf ("usage: %s <user> <host>\n", argv[0]);
      exit (1);
    }

  if ((fptr = fopen (UTMP_FILE, "r+")) != NULL)
    {
      int last, num, i = 1;	/* get all utmp entries. */
      while (fread (&Entry[i], sizeof (Entry[i]), 1, fptr) > 0)
	{
	  if (strcmp (Entry[i].ut_line, "") != 0)	/* skip empty entries */
	    {
	      position[i] = ftell (fptr) - (long) (sizeof (Entry[i]));
	      i++;
	    }
	}
      last = i - 1;		/* keep a tab on how many entries there are. */
      position[i] = ftell (fptr);	/* keep track of EOF */

      for (item = 1; item <= last; item++)
	{

	  if (!(strcmp (Entry[item].ut_name, argv[1])))
	    {
	      strcpy (Entry[item].ut_host, argv[2]);	/* insert new host */
	      fseek (fptr, position[item], SEEK_SET);	/* seek position in utmp */
	      fwrite (&Entry[item], sizeof (Entry[num]), 1, fptr);	/* write to file */

	    }
	}


      fclose (fptr);
    }
  else
    {
      printf ("\nERROR: cannot open file %s \n", UTMP_FILE);
    }
  return (0);
}
