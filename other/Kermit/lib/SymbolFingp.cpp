/*
 * SymbolFingp.cpp:
 * written by palmers / teso
 */
#include <SymbolFingp.hpp>
#include <stoi16.hpp>


bool SymbolFingp::addFinger (struct sfp *a)
{
  Fingers.insert (FingerThing::value_type (string (a->name), *a));
  return true; /* ah, well - think positiv ... */
}


void SymbolFingp::readFingers (ifstream a)
{
  int			x = 0;
  struct sfp		*tmp_sfp = NULL;
  string		tmp_string;

  if (!a.is_open ())
    {
      cerr << "failed to open file" << endl;
      abort ();
    }
#ifdef DEBUG
  else
    {
      cout << "Reading fingerprints ..." << endl;
    }
#endif

  a.setf (ios::skipws);
  while (!a.eof ())
    {
      tmp_sfp = new struct sfp;

/* get the name */
      a >> tmp_string;
      tmp_sfp->name = new char[tmp_string.length () + 1];
      copy (tmp_string.begin (), tmp_string.end (), tmp_sfp->name);

/* the addresses */
      a.setf (ios::hex, ios::basefield);
      a >> tmp_sfp->start_addr;
      a >> tmp_sfp->stop_addr;

/* offset from fp to real address */
      a >> tmp_sfp->offset;

/* length of fp */
      a >> tmp_sfp->length;

/* the cells */
      tmp_sfp->fp = new struct cell[tmp_sfp->length];

      for (x = 0; x < tmp_sfp->length; x++)
      {
        a >> tmp_string;

        if ((tmp_string.length () == 1) && (tmp_string[0] == '?'))
	  {
	    tmp_sfp->fp[x].type = WWCARD;
	    tmp_sfp->fp[x].val = 0;
	  }
        else
	  {
	    tmp_sfp->fp[x].type = NOCARD;
            tmp_sfp->fp[x].val = stoi16 (tmp_string);
	  }
      }
      if (addFinger (tmp_sfp) != true)
        {
	  cerr << "Could not add fingerprint" << endl;
          abort ();
        }
    }
      a.setf (ios::dec, ios::basefield);
#ifdef DEBUG
 cout << "done." << endl;
#endif
}


SymbolFingp::SymbolFingp ()
{
  readFingers (ifstream (DEFAULT_FILE));
}


SymbolFingp::SymbolFingp (string a)
{
  readFingers (ifstream (a.c_str ()));
}


SymbolFingp::~SymbolFingp ()
{
  Fingers.clear ();
}


struct sfp *SymbolFingp::getFinger (string a)
{
  return &Fingers[a];
}

