/*
 * SymbolTable.cpp:
 * written by palmers / teso
 */
#include <SymbolTable.hpp>


/*
 * helper classes
 */
class DumpTable
  {
private:
    string		file;

public:
    DumpTable (string a)
    {
      file = string (a);
    }

    ~DumpTable ()
    {
    }

    void operator() (zzSym *foo)
    {
      ofstream dump (file.c_str ());
      if (!dump.is_open ())
	{
	  cerr << "Pfff..." << endl;
	  abort ();
	}
      dump << foo->Name << "\tE\t" << foo->Address << endl;
      dump.close ();
    }
  };


class FindFind
  {
  private:
    string		search;

  public:
    FindFind (string a)
    {
      search = string (a);
    }

    bool operator() (struct zzSym *foo)
    {
      if (search.compare (foo->Name, search.length ()))
	{
	  return true;
	}
     return false;
    }
  };


/*
 * member functions
 */
  bool SymbolTable::loadFiles (string a, string b)
  {
/* check for System.map */
    mapp = SystemMap (a);

/* load a dumped cache */
    rest = SystemMap (b);
    return true;
  }


  bool SymbolTable::createObjects (rwKernel *a)
  {
    if (a == NULL)
      patt = new DevMemPatt ();
    else
      patt = new DevMemPatt (a);
    fing = new SymbolFingp ();
    return true;
  }


  SymbolTable::SymbolTable ()
  {
    loadFiles (DEFAULTSYSTEMMAP, DEFAULTDUMP);
    createObjects (NULL);

/* XXX, init set of exported symbols */
    if (false)
      {
        exported = SystemMap ();
      }
  }


  SymbolTable::SymbolTable (string res, string sys)
  {
    loadFiles (sys, res);
    createObjects (NULL);

/* XXX, init set of exported symbols */
    if (false)
      {
        exported = SystemMap ();
      }
  }


  SymbolTable::SymbolTable (rwKernel *f)
  {
    loadFiles (DEFAULTSYSTEMMAP, DEFAULTDUMP);
    createObjects (f);
  }


  SymbolTable::~SymbolTable ()
  {
    delete fing;
    delete patt;
    clearCache ();
  }


  void SymbolTable::setSaveFile (string file)
  {
    dump_file = string (file);
  }


  unsigned int SymbolTable::getSymbol (string name)
  {
    zzSymList::iterator	x;
    zzSym		*y = NULL;

    x = find_if (symList.begin (), symList.end (), FindFind (name));
    if (x == symList.end ())
      return 0;
    y = *x;
    return y->Address;
  }


  bool SymbolTable::findSymbol (string name)
  {
    unsigned int	x = 0;
/*
 * first  check if the symbol can be found in restore date
 * second check if the symbol can be found using SymbolFingp
 * third  is list of exported symbols
 * fourth System.map (if supplied)
 */
    if (rest.contains (name))
      {
	addSymbolToCache (name, rest[name]);
	return true;
      }

    if ((x = patt->find_patt (fing->getFinger (name))) != 0)
      {
	addSymbolToCache (name, x);
	return true;
      }

    if (exported.contains (name))
      {
	addSymbolToCache (name, exported[name]);
	return true;
      }

    if (mapp.contains (name))
      {
	addSymbolToCache (name, mapp[name]);
	return true;
      }

    return false;
  }


  void SymbolTable::addSymbolToCache (string name, unsigned int add)
  {
    zzSym		*x = new zzSym;

    x->Name = string (name);
    x->Address = add;
    symList.push_back (x);
  }


  void SymbolTable::clearCache ()
  {
    symList.clear ();
  }


  bool SymbolTable::saveCache ()
  {
    for_each (symList.begin (), symList.end (), DumpTable (dump_file));
    return true;
  }

