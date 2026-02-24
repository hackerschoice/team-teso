/*
 * DevMemPatt.hpp:
 * search the kernel...
 * written by palmers / teso
 *
 * ahh, btw. fuck. now you can grep for it :)
 */
#ifndef __DEVMEMPATT_C
#define __DEVMEMPATT_C

#define READ_BUFF_SIZE		4096

#include <string>
#include <rwKernel.hpp>
#include <SymbolFingp.hpp>


/**
 * Searching the kernel. This class helps you by seaching for
 * patterns in kernel memory. Each function has a, more or less, unique structure.
 * There is nothing to wonder about this: each function is for solving a different
 * task. If the function, or parts of it, are know it can be found without any further
 * knowledge about it.
 */
class DevMemPatt
{
private:
  rwKernel *rw;
  int compare_data_snippet (unsigned char *, struct sfp *);

public:
/**
 * This constructor will initialize the object with a reference to a rwKernel object.
 * @see rwKernel
 */
  DevMemPatt (rwKernel *);

/**
 * Another constructor. This one will generate a new rwKernel object.
 */
  DevMemPatt ();

/**
 * Destruct DevMemPatt object. Local rwKernel object will not be deleted.
 */
  ~DevMemPatt ();

/**
 * Find a data string in kernel memory.
 * @param start start address of the search.
 * @param end the search will go upto this address in kernel memory.
 * @param length the length of the data.
 * @param data the data searched for.
 * @return the address of the first byte of the searched data or
 * zero if it was not found.
 */
  unsigned int find_patt (unsigned int start, unsigned int end, \
		unsigned short len, unsigned char *data);

/**
 * Find a data pattern in kernel memory.
 * @param a search a data pattern defined by a.
 * @return the address of the first byte of the searched pattern or
 * zero if it was not found.
 * @see SymbolFingp
 */
  unsigned int find_patt (struct sfp *a);
};
#endif /* __DEVMEMPATT_C */
