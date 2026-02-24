/*
 * Patch.cpp:
 * written by palmers / teso
 */
#include <Patch.hpp>

SystemMap DummyValMap;

/*
 * helper class
 */
class replaceAddr
{
private:
  unsigned char		*data;
  unsigned short	len;

public:
  replaceAddr (unsigned char *a, unsigned short x)
  {
    data = a;
    len = x;
  }
 
  void operator() (Addr2Addr *a)
  {
    unsigned short	x = 0;
    unsigned char	*b = NULL,
			*c = NULL;

    b = (unsigned char *) &a->first;
    c = (unsigned char *) &a->second;

    for (x = 0; x <= (len - 3); x++)
      {
        if (b[0] == data[x])
	  {
	    if ((b[1] == data[x + 1]) && \
		(b[2] == data[x + 2]) && \
		(b[3] == data[x + 3]))
	      {
		data[x] = c[0];
		data[x + 1] = c[1];
		data[x + 2] = c[2];
		data[x + 3] = c[3];
	      }
	  }
      }
  }
};


/*
 * member functions
 */
  string Patch::state2string ()
  {
    string		ret;

    switch (state)
      {
	case CLEAN:
	  ret = "Clean";
	  break;
	case LINKED:
	  ret = "Linked";
	  break;
	case APPLIED:
	  ret = "Applied";
	  break;
	case AFAILED:
	  ret = "ApplyFailed";
	  break;
	case LFAILED:
	  ret = "LinkFailed";
	  break;
	default:
	  ret = "Unknown";
	  break;
      }
    return ret;
  }


  void Patch::string2state (string a)
  {
    if (a == "Clean")
      state = CLEAN;
    else if (a == "Linked")
      state = LINKED;
    else if (a == "Applied")
      state = APPLIED;
    else if (a == "ApplyFailed")
      state = AFAILED;
    else if (a == "LinkFailed")
      state = LFAILED;
    else if (a == "Unknown")
      abort ();
  }


  string Patch::data2string (unsigned char *a)
  {
    string		ret;
    int			x;

    ret = itos16 ((unsigned int) a[0]);
    for (x = 1; x < len; x++)
      {
	ret += ' ';
	ret += itos16 ((unsigned int) a[x]);
      }

    return ret;
  }


  void Patch::string2data (string s, unsigned char *d)
  {
    string		tmp;
    unsigned short	x,
			y;

    for (x = 0; x < (len - 1); x++)
      {
        y = s.find_first_of (" ");
        tmp.resize (y);
        s.copy (tmp.begin (), y);
        s.erase (0, y + 1);
	d[x] = (unsigned char) stoi16 (tmp) & 0xff;
	tmp.erase ();
      }
    tmp.resize (s.length ());
    s.copy (tmp.begin (), s.length ());
    d[x] = (unsigned char) stoi16 (tmp) & 0xff;
  }


  bool Patch::initObjects (unsigned char *d, unsigned short l, unsigned int add, rwKernel *x)
  {
    len = l;
    address = add;
    local_rw = x;

    data = new unsigned char[len];
    back_data = new unsigned char[len];
    overwr = new unsigned char[len];

    copy (d, d + len, data);
    copy (d, d + len, back_data);
    state = CLEAN;
    return true;
  }


  void Patch::parse (string s)
  {
    unsigned char	*a = NULL;
    string		tmp;
    int			x = 0;

    x = s.find_first_of (",");
    tmp.resize (x);
    s.copy (tmp.begin (), x);
    s.erase (0, x + 1);

    address = stoi16 (tmp);
    tmp.erase ();

    x = s.find_first_of (":");
    tmp.resize (x);
    s.copy (tmp.begin (), x);
    s.erase (0, x + 1);

    string2state (tmp);
    tmp.erase ();

    x = s.find_first_of ("(");
    s.erase (0, x + 1);

    x = s.find_first_of (")");
    tmp.resize (x);
    s.copy (tmp.begin (), x);
    len = count (tmp.begin (), tmp.end (), ' ') + 1;

    data = new unsigned char[len];
    back_data = new unsigned char[len];
    overwr = new unsigned char[len];

    string2data (tmp, data);
    tmp.erase ();

    if (state == CLEAN)
      return;

    switch (state)
      {
	case LINKED:
	case LFAILED:
	  a = back_data;
	  break;
	case APPLIED:
	case AFAILED:
	  a = overwr;
	  break;
      }

    x = s.find_first_of ("(");
    s.erase (0, x + 1);

    x = s.find_first_of (")");
    tmp.resize (x);
    s.copy (tmp.begin (), x);

    string2data (tmp, a);
  }


  Patch::Patch ()
  {
  }


  Patch::Patch (unsigned char *d, unsigned short l, unsigned int add)
  {
    initObjects (d, l, add, NULL);
  }


  Patch::Patch (unsigned char *d, unsigned short l, unsigned int add, rwKernel *x)
  {
    initObjects (d, l, add, x);
  }


  Patch::Patch (string s)
  {
    parse (s);
  }


  Patch::Patch (string s, rwKernel *rw)
  {
    parse (s);
    local_rw = rw;
  }


  Patch::~Patch ()
  {
    delete data;
    delete back_data;
    delete overwr;
  }


  void Patch::initFromString (string a)
  {
    parse (a);
  }


  string Patch::getPatchAsString ()
  {
    unsigned char	*a = NULL;
    string		b;

    switch (state)
      {
	case LINKED:
	case LFAILED:
	  a = back_data;
	  break;
	case APPLIED:
	case AFAILED:
	  a = overwr;
	  break;
      }

    b = itos16 (address) + ',' + state2string () + ": (" + data2string (data) + ')';
    if (a != NULL)
      b += ", (" + data2string (a) + ')';
    b += '\n';
    return b;
  }


  bool Patch::isLinked ()
  {
    return (state & LINKED);
  }


  bool Patch::wasChanged ()
  {
    int			x;

    for (x = 0; x < len; x++)
      if (data[x] != back_data[x])
	return true;
    return false;
  }


  bool Patch::isApplied ()
  {
    return (state & APPLIED);
  }


  bool Patch::isClean ()
  {
    return (state & CLEAN);
  }


  bool Patch::isFailed ()
  {
    return (state & AFAILED) || (state & LFAILED);
  }


  int Patch::getState ()
  {
    return state;
  }


  void Patch::restore ()
  {
    copy (back_data, back_data + len, data);
    state = CLEAN;
  }


  bool Patch::remove (rwKernel *rw)
  {
    if (state != APPLIED)
      return false;

    rw->write (overwr, len, address);
    return true;
  }


  bool Patch::remove ()
  {
    if (local_rw == NULL)
      return false;
    if (state != APPLIED)
      return false;

    local_rw->write (overwr, len, address);
    return true;
  }


  unsigned char *Patch::getData ()
  {
    return data;
  }


  void Patch::apply (rwKernel *rw)
  {
/* pretty simple :) */
    rw->read (overwr, len, address);
    rw->write (data, len, address);
    state = APPLIED;
  }


  void Patch::apply ()
  {
    if (local_rw == NULL)
      {
	state = AFAILED;
	return;
      }
    local_rw->read (overwr, len, address);
    local_rw->write (data, len, address);
    state = APPLIED;
  }


  void Patch::link (Addr2AddrList *a2a)
  {
    replaceAddr			x (data, len);
    int				y = a2a->size ();
    Addr2AddrList::iterator	z = a2a->begin ();
    Addr2Addr			*t = NULL;

/* XXX: why doesnt for_each work with pointer to list???
 * its the same problem with for "(x = a2a->begin (); x != a2a->end (); ..."
 * the x != end (); just f#$§ true!
 */
    while (y--)
      {
	t = *z;
	x (t);
	z++;
      }
    state = LINKED;
  }


  void Patch::dump (string file)
  {
    unsigned char	*a = NULL;
/*
 * dump file format:
 * <Address>,<State>: (<data, hex, byte wise>){, (<other data, hex, byte wise>)}\n
 * where the data in the curled brackets in depending on the state:
 * state:	data in the curled bbrackets:
 * clean	none
 * applied	overwr
 * afailed	overwr
 * linked	back_date
 * lfailed	back_data
 */
    ofstream f;

    switch (state)
      {
	case LINKED:
	case LFAILED:
	  a = back_data;
	  break;
	case APPLIED:
	case AFAILED:
	  a = overwr;
	  break;
      }

    f.open (file.c_str (), ios::ate | ios::app);

    f.setf (ios::hex, ios::basefield);
    f << address << ',' << state2string () << ':' << ' ';
    f << '(' << data2string (data) << ')';
    if (a != NULL)
      f << ',' <<  ' ' << '(' << data2string (a) << ')';
    f << endl;
    f.setf (ios::dec, ios::basefield);
  }


  istream& operator>> (istream& is, Patch& p)
  {
    string		tmp;

    getline (is, tmp, '\n');
    p.initFromString (tmp);
    return is;
  }


  ostream& operator<< (ostream& os, Patch& p)
  {
    os << p.getPatchAsString ();
    return os;
  }


/*
 * unrelated functions ....
 */
  Addr2AddrList *genReplaceValMap (SymbolTable *st)
  {
    zzSymList::iterator	x;
    Addr2Addr		*y = NULL;
    zzSym		*z = NULL;
    Addr2AddrList	*a2a = NULL;

    a2a = new Addr2AddrList ();

    /* get all symbol addressess together with dummy values */
    for (x = st->symList.begin (); x != st->symList.end (); x++)
      {
	z = *x;
        if (DummyValMap[z->Name] != 0)
	  {
            y = new Addr2Addr ();
            y->first = DummyValMap[z->Name];
            y->second = z->Address;
            a2a->push_back (y);
	  } 
      }
    return a2a;
  }


  void genDummyValMap ()
  {
    int			x = 0;

    while (__n2a[x].name != NULL)
     {
       DummyValMap.add (string (__n2a[x].name), __n2a[x].add);
       x++;
     }
  }

