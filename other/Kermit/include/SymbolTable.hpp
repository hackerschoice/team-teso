/*
 * SymbolTable.hpp:
 * a container for "on-demand" symbol address fetching
 * written by palmers / teso
 */
#ifndef __SYMBOL_TABLE_C
#define __SYMBOL_TABLE_C

#include <SymbolFingp.hpp>
#include <SystemMap.hpp>
#include <DevMemPatt.hpp>
#include <rwKernel.hpp>
#include <list>
#include <string>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>

#define DEFAULTDUMP		"SymbolTableDump"
#define DEFAULTSYSTEMMAP	"System.map"

typedef struct
  {
    string Name;
    unsigned int Address;
  } zzSym;
typedef list<zzSym *> zzSymList;


/**
 * A container class for "on-demand" symbol address fetching.
 */
class SymbolTable
{
private:
  SymbolFingp *fing;
  DevMemPatt *patt;
  SystemMap exported;
  SystemMap mapp;
  SystemMap rest;
  string dump_file;

  bool createObjects (rwKernel *);
  bool loadFiles (string, string);

public:
/**
 * List of name, address pairs.
 */
  zzSymList symList;

/**
 * Construct a SymbolTable object and load configuration from default files.
 */
  SymbolTable ();

/**
 * Construct a SymbolTable object and load configuration from defined files.
 * @param res file name of restore file.
 * @param sys System.map file to load.
 */
  SymbolTable (string res, string sys);

/**
 * Construct a SymbolTable object and use the referenced rwKernel object in all
 * member attributes and methods.
 */
  SymbolTable (rwKernel *);

/**
 * Foo.
 */
  ~SymbolTable ();

/**
 * Define the file written to on saveCache ().
 * @see saveCache()
 */
  void setSaveFile (string);

/**
 * get the address of a known symbol.
 * @return If the symbol is unknow zero is returned.
 * (hey, would you call 0x00000000?). Else, the address
 * of the symbol.
 */
  unsigned int getSymbol (string);

/**
 * Find a symbol. This will try all available methods to
 * find a symbol and cache the address, name pair (zero
 * if search was not successfull).
 * @return true on success.
 */
  bool findSymbol (string);

/**
 * add a symbol, address pair to the cache.
 */
  void addSymbolToCache (string, unsigned int);

/**
 * flush the address cache.
 */
  void clearCache ();

/**
 * save the cache to a file (human readable, System.map style).
 */
  bool saveCache ();
};
#endif /* __SYMBOL_TABLE_C */
