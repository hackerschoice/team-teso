/* inmem.c - in-memory runtime infection engine
 *
 * this module provide the capability to attach to other running processes
 * through the 'ptrace' debug interface on linux/x86. it provides abstracted
 * functions to call functions within the attached process and to infect the
 * runtime image of the process with the entire virus in a safe way. it is
 * optimized for a minimum of context switches, so infection does not delay
 * normal execution.
 */

#ifndef	INMEM_H
#define	INMEM_H


/* inm_call
 *
 * obtain the address of function `func' in already traced process referenced
 * by `pid' and call with parameter frame `args', which is `args_count' words
 * long. when `retval' is non-NULL, store return value of function call in it.
 * will clobber pf_ptrace's static frame.
 *
 * XXX: the process `pid' has to be in stopped state with us already having
 *      waitpid'ed on it, else this function might run into serious blocking
 *      or ptrace-misbehave issues.
 *
 * return 0 on success
 * return != 0 on failure
 */

int inm_call (int pid, char *func, unsigned int *args,
	unsigned int args_count, unsigned int *retval);


#endif

