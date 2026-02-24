/*
 * Patch.hpp:
 * representation of a kernel patch.
 * written by palmers / teso
 */
#ifndef __PATCH_C
#define __PATCH_C

#include <rwKernel.hpp>
#include <SymbolTable.hpp>
#include <SystemMap.hpp>
#include <stoi16.hpp>
#include <itos16.hpp>
#include <utility>
#include <functional>
#include <algorithm>
#include <list>
#include <fstream>
#include <string>
#include <name2add.h>


typedef pair<unsigned int, unsigned int>	Addr2Addr;
typedef list<Addr2Addr *>			Addr2AddrList;

Addr2AddrList *genReplaceValMap (SymbolTable *st);
void genDummyValMap ();
extern SystemMap DummyValMap;


#define CLEAN	1
#define LINKED	2
#define APPLIED	4
#define LFAILED	8
#define	AFAILED	16


/**
 * Representation of a kernel patch. A Patch is a amount of data, which is to be written
 * to a given address. Patching means modification of kernel memory. Therefore, the data,
 * which will be overwritten, is saved (before writting).
 * Additionally the status of the Patch is tracked. Thus, you are able to undo, reapply
 * and debug patches. The states a Patch must be in are:
 * CLEAN (the patch was never touched)
 * LINKED (it was linked without an error)
 * APPLIED (it was applied without an error)
 * LFAILED (linking failed)
 * AFAILED (applying failed)
 */
class Patch
{
private:
  int state;
  unsigned short len;
  unsigned char *back_data, *data, *overwr;
  unsigned int address;
  rwKernel *local_rw;

  bool initObjects (unsigned char *, unsigned short, unsigned int, rwKernel *);
  string state2string ();
  void string2state (string);
  string data2string (unsigned char *);
  void string2data (string, unsigned char *);
  void parse (string);

public:
/**
 * Create, but init nothing.
 */
  Patch ();

/**
 * Create a patch with supplied data.
 * @param data patch data.
 * @param len length of patch data.
 * @param addr memory address to where the data shall be written.
 */
  Patch (unsigned char *data, unsigned short len, unsigned int addr);

/**
 * Create a patch with supplied data. This constructor, compared with the above,
 * will set a local reference to a rwKernel object.
 * @param x pointer to a rwKernel object.
 */
  Patch (unsigned char *data, unsigned short len, unsigned int addr, rwKernel *x);

/**
 * Initialize the object from a string as created by dump ().
 * @see dump()
 */
  Patch (string);

/**
 * Initialize the object from a string as created by dump ().
 * @see dump()
 */
  Patch (string, rwKernel *);

/**
 * Foo.
 */
  ~Patch ();


/**
 * init object from a string.
 */
  void initFromString (string);

/**
 * Foo.
 */
  string getPatchAsString ();

/**
 * tells you if the patch data was modified. (e.g. by linking).
 * @return true if backup data and data differ.
 */
  bool wasChanged ();

/**
 * @return true if the linking returned no error messages. 
 */
  bool isLinked ();

/**
 * @return true if the applying was successful. 
 */
  bool isApplied ();

/**
 * @return true if linking or applying failed.
 */
  bool isFailed ();

/**
 * @return true if the patch was not touched.
 */
  bool isClean ();

/**
 * @return the status.
 */
  int getState ();

/**
 * Restore patch data. Might be helpful if linking failed.
 */
  void restore ();

/**
 * Remove applied Patch (Undo changes done to memory).
 */
  bool remove ();

/**
 * Remove applied Patch (Undo changes done to memory).
 */
  bool remove (rwKernel *);

/**
 * Get a pointer to patch data.
 */
  unsigned char *getData ();

/**
 * Apply the patch to the kernel. Effectivly write the patch data to the supplied address.
 * The method allows you to supply a a reference to a rwKernel object. you can supply on
 * construction of the patch. However, there might be none at that time.
 */
  void apply (rwKernel *);

/**
 * Apply the patch to the kernel. Use this apply method if you supplied a reference to a
 * rwKernel object at creation time.
 */
  void apply ();

/**
 * link the patch with the kernel. Replace all placeholders with real addresses.
 */
  void link (Addr2AddrList *);

/**
 * Dump patch information into a file. This will produce human readable output. It
 * can be used e.g. for restoring and debugging. Because the output is line based
 * and can be used to initialize a Patch object you are effecitvely able to reproduce
 * patching sessions.
 * @see Patch(string)
 * @param file filename.
 */
  void dump (string file);

/**
 * Foo.
 */
  friend istream& operator>> (istream&, Patch&);

/**
 * Foo.
 */
  friend ostream& operator<< (ostream&, Patch&);
};
#endif /* __PATCH_C */
