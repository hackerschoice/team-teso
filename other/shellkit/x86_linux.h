
#ifndef	X86_LINUX_H
#define	X86_LINUX_H

#include "x86.h"
#include "shellcode.h"

arch	x86_linux;


void
x86_linux_chmod_setup (unsigned char *, unsigned char *, unsigned long int);

void
x86_linux_setgid_setup (unsigned char *, unsigned short int);

void
x86_linux_setuid_setup (unsigned char *, unsigned short int);

void
x86_linux_setreuid_setup (unsigned char *,
	unsigned short int, unsigned short int);

void
x86_linux_portshell_setup (unsigned char *, unsigned short int);

void
x86_linux_connectshell_setup (unsigned char *,
	unsigned long int, unsigned short int);

#endif

