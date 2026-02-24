/*
 * SymbolFingp.hpp:
 * some fingerprint
 * written by palmers / teso
 */
#ifndef __SymbolFingp_H
#define __SymbolFingp_H
#include <map>
#include <fstream>
#include <string>
#include <iostream>

/* default file to open */
#define DEFAULT_FILE	"SymbolFind.conf"

/* defines used for the type field in struct cell */
#define WWCARD	1
#define NOCARD	0


struct cell
{
  unsigned char type;
  unsigned char val;
};


struct sfp
{
  char *name;
  unsigned long start_addr;
  unsigned long stop_addr;
  long offset;
  unsigned short length;
  struct cell *fp;
};


/** 
 * class to hold fingerprints of a function (a [kernel-]symbol).
 */
class SymbolFingp
{
private:

  typedef map<string, struct sfp> FingerThing;
  FingerThing Fingers;

  void readFingers (ifstream);
  bool addFinger (struct sfp *);

public:

/**
 * Reads configuration from default file.
 */
  SymbolFingp ();

/**
 * Reads configuration from specified file.
 */
  SymbolFingp (string);

/**
 * Foo.
 */
  ~SymbolFingp ();

/**
 * Return the Fingerprint matching the supplied name.
 */
  struct sfp *getFinger (string);
};

#endif /* __SymbolFingp_H */
