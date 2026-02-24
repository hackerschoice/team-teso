/*
 * rwKernel.cpp:
 * written by palmers / teso
 */
#include <rwKernel.hpp>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <iostream>


  bool rwKernel::openFile (int w)
  {
    int			a = 0;
    void		*tmp = NULL;
    char		*file = NULL;

    if (w == DEVMEM)
      file = "/dev/mem";
    else if (w == PROCKCORE)
      file = "/proc/kcore";

    if ((a = open (file, O_RDWR)) <= 0)
      {
        cerr << "open error" << endl;
        abort ();
      }

    if ((tmp = mmap (NULL, 0x40000000, PROT_READ | \
	PROT_WRITE, MAP_SHARED, a, 0xc0000000 - mem_conf)) == (void *) -1)
      {
        cerr << "mmap failed" << endl;
        abort ();
      }
    fd = (char *) tmp;
    return true;
  }


  void rwKernel::setOffset (int x)
  {
    switch (x)
      {
        case CONF_1GB:
	  mem_conf = 0xC0000000;
	  break;
        case CONF_2GB:
	  mem_conf = 0x80000000;
	  break;
        case CONF_3GB:
	  mem_conf = 0x40000000;
	  break;
        case IGNORE:
	  mem_conf = 0xC0000000;
	  break;
	default:
	  mem_conf = 0xC0000000;
	  break;
      }
  }


  void rwKernel::closeFile ()
  {
    munmap (fd, 0x40000000);
  }


  rwKernel::rwKernel ()
  {
    setOffset (CONF_1GB);
    openFile (DEVMEM);
  }


  rwKernel::rwKernel (int file, int off)
  {
    if (file == PROCKCORE)
      off = IGNORE;
    setOffset (off);
    openFile (file);
  }


  rwKernel::~rwKernel ()
  {
    closeFile ();
  }


  void rwKernel::read (unsigned char *dest, unsigned int len, \
		unsigned int offset)
  {
    offset -= mem_conf;
    copy (fd + offset, fd + offset + len, dest);
  }


  void rwKernel::write (unsigned char *src, unsigned int len, \
		unsigned int offset)
  {
    offset -= mem_conf;
    copy (src, src + len, fd + offset); 
  }

