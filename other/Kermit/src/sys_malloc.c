/*
 * sys_malloc: system call for malloc'ing kernel memory
 * written by palmers / teso 
 */
#include <stdio.h>
#include <pseudo_link.h>

/* from linux/mm.h */
#define __GFP_WAIT	0x01
#define __GFP_MED	0x04
#define __GFP_IO	0x10
#define GFP_KERNEL	(__GFP_MED | __GFP_WAIT | __GFP_IO)


void cbegin (){}

void *sys_malloc (size_t x)		/* malloc x bytes */
{
  USE_KMALLOC
  void *y = NULL;

  y = kmalloc (x, GFP_KERNEL);
  return y;
}

void cend(){}

