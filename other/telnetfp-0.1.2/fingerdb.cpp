class tdfpdb
{
  private:
  char *db_file;
  FILE *fd;
  int integrity;

  public:

  int 
  compare_do_dont_line (char *line, unsigned char *d)
    {
      char *tmp = NULL;

      if ((line == NULL) || (d == NULL))
	return 0;

      while ((line[0] != 0) && (d[0] != 0))
	{
	  if (line[0] == '*')
	    {
	      integrity += 50;
	      return 1;
	    }
	  else if (line[0] == '?')
	    {
	      integrity++;
	      if (line[1] != 0)
		line += 2;
	      return (compare_do_dont_line (line, d) || compare_do_dont_line (line, d + 1));
	    }
	  else if (atoi (line) != d[0])
	    return 0;

	  d += 1;
	  tmp = strstr (line, " ");
	  if (tmp)
	    line = tmp + 1;
	}
      if ((tmp != NULL) || (d[0] != 0))
        return 0;
      return 1;
    }


  void
  find_in_db (unsigned char *dos, unsigned char *donts)
    {
      unsigned int x = 0;
      char line[LINE_LENGTH + 1];

      fseek (fd, 0, SEEK_SET);
      while (!feof (fd))
	{
	  bzero (line, LINE_LENGTH + 1);
	  fgets (line, LINE_LENGTH, fd);
	  if (strstr (line, "DO:   ") != NULL)
	    {
	      if (compare_do_dont_line (line + 6, dos))
		{
		  bzero (line, LINE_LENGTH + 1);
		  fgets (line, LINE_LENGTH, fd);
		  if (compare_do_dont_line (line + 6, donts))
		    {
		      printf ("Found matching finger print: ");
		      if (integrity > 0)
			printf ("\nWarning: fingerprint contained wildcards! (integrity: %d)\n", integrity);
		      while (!feof (fd))
			{
			  bzero (line, LINE_LENGTH + 1);
			  fgets (line, LINE_LENGTH, fd);
			  if ((strstr (line, "DO:   ") == NULL) && (strlen (line) > 0))
			    printf ("%s", line);
			  else
			    return;
			}
		    }
		}
	    }
	}
      printf ("\nNOT FOUND!\n\nplease mail the following lines and OS/machine type to pa1mers@gmx.de:\nDO:   ");
      for (x = 0; x < strlen ((char *) dos); x++)
	printf ("%d ", dos[x]);
      printf ("\nDONT: ");
      for (x = 0; x < strlen ((char *) donts); x++)
	printf ("%d ", donts[x]);
      printf ("\n\n");
    }


  int
  open ()
    {
      if (db_file == NULL)
        {
	  db_file = (char *) malloc (strlen (DEFAULT_DB) + 1);
	  memset (db_file, 0, strlen (DEFAULT_DB) + 1);
	  memcpy (db_file, DEFAULT_DB, strlen (DEFAULT_DB));
	}
      if ((fd = fopen (db_file, "r")) == NULL)
	{
	  printf ("Error: can not open fingerprint file \"%s\"\n", db_file);
	  exit (2);
        }
      return 1;
    }


  void
  close ()
    {
      fclose (fd);
    }


  void
  set (char *file)
    {
      if (db_file != NULL)
	{
	  free (db_file);
	}
      db_file = (char *) malloc (strlen (file) + 1);
      memset (db_file, 0, strlen (file) + 1);
      memcpy (db_file, file, strlen (file));
    }


  void
  reset ()
    {
      integrity = 0;
      fseek (fd, 0, SEEK_SET);
    }


  void
  init ()
    {
      integrity = 0;
      fd = NULL;
      db_file = NULL;
    }
};
