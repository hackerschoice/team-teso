#include <iostream.h>
#include <errno.h>
#include <string.h>
#include "elf_help.h"

elf_fault::elf_fault (void)
{
	s = NULL;
	err = errno;
}

elf_fault::elf_fault (int error)
{
	s = NULL;
	err = error;
}

elf_fault::elf_fault (const char *_error)
{
	err = 0;

	s = new char [strlen(_error)+1];
	strcpy (s, _error);
}

elf_fault::~elf_fault ()
{
}

void
elf_fault::print (void)
{
	if (s != NULL) {
		cerr << s << endl;
	} else {
		cerr << (char *)(strerror(err)) << endl;
	}
	return;
}
