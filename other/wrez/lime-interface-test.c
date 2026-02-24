/* small test program for the lime c interface
 */

#include "int80.h"
#include "lime-interface.h"


static unsigned long helloworld (void);


int
main (int argc, char *argv[])
{
	void			(* code_f)(void);
	unsigned int		code_len;
	unsigned char		code[4096 + 128];
	unsigned long		addr;
	int			n;


	for (n = 0 ; n < sizeof (code) ; ++n)
		code[n] = 0x00;

	write (2, "plain: ", 6);
	addr = helloworld ();

	code_len = lime_generate ((void *) addr,
		50,
		&code[0], (unsigned long int) &code[0]);

	write (2, "limed\n", 6);
	code_f = (void (*)(void)) &code[0];
	code_f ();

	return (0);
}


static unsigned long
helloworld (void)
{
	unsigned long	address;

	__asm__ __volatile__ ("
		.global	tlab0
		.global	tlab3
		call	tlab4
	tlab4:	popl	%%eax
		addl	$(tlab0 - tlab4), %%eax
		jmp	tlab3

	tlab0:	pushf
		pusha
		movl	$0x4, %%eax
		movl	$0x2, %%ebx
		movl	$12, %%edx
		call	tlab1
		.asciz	\"hello world\\n\"
	tlab1:	popl	%%ecx
		int	$0x80
	tlab2:	popa
		popf
		ret
	tlab3:	nop"
		: "=a" (address) : : "%ebx", "%ecx", "%edx");

	return (address);
}

