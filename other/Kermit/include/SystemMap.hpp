/*
 * SystemMap.hpp:
 * representation if a system map file (and alike).
 * written by palmers / teso
 */
#ifndef SYSTEM_MAP_C
#define SYSTEM_MAP_C

#include <map>
#include <string>
#include <fstream>

/**
 * Representation of a System.map file. It maps names to addresses.
 */
class SystemMap
{
private:
  typedef map<string, unsigned int> blamap;
  typedef blamap::value_type bla_val;

  blamap add_map;

public:
/**
 * Create a SystemMap object and read symbol names and addresses from a file.
 */
  SystemMap (string file);

/**
 * Create a SystemMap object and leave it empty.
 */
  SystemMap ();

/**
 * Foo.
 */
  ~SystemMap ();

/**
 * Check if a symbol (by name) is part of the object.
 * @return true if the questioned symbol is part of the object (else false).
 */
  bool contains (string);

/**
 * Add a name, address pair to the object.
 * @param name Symbolname. If a symbol with this name already exists
 * it will not be added.
 * @param address the address of the symbol.
 */
  void add (string name, unsigned int address);

/**
 * Random access operator for accessing elements in the form x = <name>[<symbol>].
 * @param name of a symbol.
 * @return the address of symbol name.
 */
  unsigned int operator[] (string name);
};
#endif /* SYSTEM_MAP_C */
