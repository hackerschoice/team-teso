/*
 * SystemMap.cpp:
 * written by palmers / teso
 */
#include <SystemMap.hpp>


  SystemMap::SystemMap (string a)
  {
    string		tmp;
    unsigned int	num = 0;
    ifstream		f;

    f.open (a.c_str ());
    if (!f.is_open ())
      {
	cerr << "Error opening file \"" << a << "\"!" << endl;
	abort ();
      }

    f.setf (ios::skipws);
    f.setf (ios::hex, ios::basefield);

    while (!f.eof ())
      {
	f >> num;
	f >> tmp;
	f >> tmp;

        add_map.insert (add_map.end (), bla_val (tmp, num));       
      }
    f.close ();
  }


  SystemMap::SystemMap ()
  {
  }


  SystemMap::~SystemMap ()
  {
    add_map.clear ();
  }


  bool SystemMap::contains (string a)
  {
    if (add_map.find (a) == add_map.end ())
      return false;
    return true;
  }


  void SystemMap::add (string a, unsigned int x)
  {
    add_map.insert (add_map.end (), bla_val (a, x));       
  }


  unsigned int SystemMap::operator[] (string a)
  {
    if (add_map.find (a) == add_map.end ())
      return 0;
    return add_map[a];
  }

