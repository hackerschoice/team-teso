#ifdef 0
void
print_exported_symbols ()
{
  struct new_module_symbol
  {
    unsigned long value;
    unsigned long name;
  }
   *syms = NULL, *s = NULL;

  unsigned long long_tmp;
  char *char_tmp = NULL;
  size_t ret, bufsize, x = 800;

  s = syms = new struct new_module_symbol[x];
  bufsize = sizeof (struct new_module_symbol) * x;

  while (query_module (NULL, QM_SYMBOLS, syms, bufsize, &ret) == -1)
    {
      if (errno == ENOSPC)
	{
	  delete syms;
	  x += 400;
	  s = syms = new struct new_module_symbol[x];
	  bufsize = sizeof (struct new_module_symbol) * x;
	}
      else
	{
	  if (Silent)
            {
	      cout << "0" << endl;
	      exit (1);
            }
	  cerr << "query_module error!" << endl;
	  abort ();
	}
    }

  cout.setf (ios::hex, ios::basefield);
  for (x = 0; x < ret; x++, s++)
    {
      char_tmp = (char *) syms + s->name;
      long_tmp = (unsigned long) s->value;
      cout << long_tmp << " " << char_tmp << endl;
    }
  delete syms;
  cout.setf (ios::dec, ios::basefield);
}
#endif

main (){}
