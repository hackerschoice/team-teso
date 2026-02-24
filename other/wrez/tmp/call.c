/* use ht on the 'call' executeable to set the first PT_LOAD rwx
 * else it will segfault
 */

#include <stdio.h>

int foofunc (void);


#define	FUNCPTR(dst,functionname) \
{ \
	register unsigned int	fptr; \
	\
	__asm__ __volatile__ ( \
		"	call	l0_%=\n" \
		"l0_%=:	movl	$"##functionname", %%eax\n" \
		"	subl	$l0_%=, %%eax\n" \
		"	popl	%%edx\n" \
		"	addl	%%edx, %%eax\n" \
		: "=a" (fptr) : : "edx"); \
	\
	(dst) = (void *) fptr; \
}

#define	PTRINSTALL(hook,chain) \
{ \
	__asm__ __volatile__ ( \
		"	call	l0_%=\n" \
		"lr_%=:	jmp	lo_%=\n" \
		"l0_%=:	pushl	%%edx\n" \
		"	pushl	$0x64466226\n" \
		"	jmpl	*%%eax\n" \
		"lo_%=:\n" \
		: : "a" (hook), "d" (chain)); \
}

#define	PTRCONTROL(chain) \
{ \
	__asm__ __volatile__ ( \
		"	jmp	l0_%=\n" \
		"lp_%=:	.byte	0x0\n" \
		"	.byte	0x0\n" \
		"	.byte	0x0\n" \
		"	.byte	0x0\n" \
		"\n" \
		"l0_%=:	call	l1_%=\n" \
		"l1_%=:	popl	%%edx\n" \
		"	addl	$lp_%=, %%edx\n" \
		"	subl	$l1_%=, %%edx\n" \
		"\n" \
		"	movl	0x4(%%ebp), %%eax\n" \
		"	cmpl	$0x64466226, %%eax\n" \
		"	jne	lo_%=\n" \
		"\n" \
		"	movl	0x8(%%ebp), %%eax\n" \
		"	movl	%%eax, (%%edx)\n" \
		"\n" \
		"	movl	%%ebp, %%esp\n" \
		"	popl	%%ebp\n" \
		"	addl	$0x8, %%esp\n" \
		"	ret\n" \
		"\n" \
		"lo_%=:	movl	(%%edx), %%eax\n" \
		: "=a" (chain) : : "edx"); \
}


int
main (int argc, char *argv[])
{
	void (* addr)(void);

#if 0
	__asm__ __volatile__ ("
		call	l1_%=
	l1_%=:	movl	$foofunc, %%eax
		subl	$l1_%=, %%eax
		popl	%%edx
		addl	%%edx, %%eax
		pusha
		call	*%%eax
		popa"
		: "=a" (addrdiff) : : "edx");
#endif
	FUNCPTR (addr, "foofunc");

	printf ("0x%08lx\n", (unsigned long int) addr);

	PTRINSTALL (addr, 0x42424242);

	foofunc ();
}


int
foofunc (void)
{
	void *	chain;

	PTRCONTROL (chain);

	printf ("0x%08lx\n", chain);
}



