
#ifndef	MIPS_IRIX_H
#define	MIPS_IRIX_H

#include "shellcode.h"

arch	mips_irix;

void
mips_irix_setgid_setup (unsigned char *code, unsigned short int gid);

void
mips_irix_setreuid_setup (unsigned char *code,
	unsigned short int ruid, unsigned short int euid);

#endif

