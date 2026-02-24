/*
 * rwKernel.hpp:
 * access to kernel memory.
 * written by palmers / teso
 */
#ifndef __RW_KERNEL_C
#define __RW_KERNEL_C

#include <algorithm>

#define PROCKCORE	213
#define DEVMEM		23846

#define CONF_1GB	34
#define CONF_2GB	33
#define CONF_3GB	32
#define IGNORE		31

/**
 * Wrapper around kernel memory access. It lets you read from
 * and write to the kernel without taking care of offsets or file access.
 */
class rwKernel
{
private:

  char *fd;
  int which;
  unsigned int mem_conf;

  bool openFile (int);
  void closeFile ();
  void setOffset (int);


public:

/**
 * Create the object with a fairly standard configuration. This constructor will assume
 * that you want to use /dev/mem and a standard offset (as used by any 2.4.x and any
 * 2.2.x kernel not defined to use more than 1GB of ram).
 */
  rwKernel ();

/**
 * Create a rwKernel object with the defined parameters.
 * @param file sets the file to use. This must be either
 * PROCKCORE (to use /proc/kcore as the memory device) or
 * DEVMEM (to use /dev/mem as the memory device).
 * @param offset sets the offset from real memory addresses
 * to virtual (kernel-) addresses. This is only needed if
 * (file == DEVMEM), otherways supply IGNORE.
 */
  rwKernel (int file, int offset);

/**
 * Destructor. Will unmap the used device.
 */
  ~rwKernel ();

/**
 * read from kernel.
 * @param dest read data to this address.
 * @param len amount of bytes to read.
 * @param addr read data from this address.
 */
  void read (unsigned char *dest, unsigned int len, unsigned int addr);

/**
 * write to kernel.
 * @param src read data from this address.
 * @param len amount of bytes to write.
 * @param addr write data to this address.
 */
  void write (unsigned char *src, unsigned int len, unsigned int addr);

/**
 * Foo.
 */
  void read (char *a, unsigned int b, unsigned int c)
  {
    read ((unsigned char *) a, b, c);
  }

/**
 * Foo.
 */
  void write (char *a, unsigned int b, unsigned int c)
  {
    write ((unsigned char *) a, b, c);
  }
};

#endif /* __RW_KERNEL_C */
