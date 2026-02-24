/*
 * assfault.so, 2001-09-25, anonymous@segfault.net
 * 
 * This is unpublished proprietary source code of someone without a name...
 * someone who dont need to be named....
 *
 * The contents of these coded instructions, statements and computer
 * programs may not be disclosed to third parties, copied or duplicated in
 * any form, in whole or in part, without the prior written permission of
 * the author. 
 *
 * Tries to catch SIGSEGV/SIGILL and continues execution flow.
 *
 * $ make
 * $ LD_PRELOAD=./assfault.so netscape &
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>

#define REPLACE(a, x, y) if ( !(o_##x = dlsym(##a , ##y)) )\
            { fprintf(stderr, ##y"() not found in libc!\n");\
                exit(-1); }


static void *(*o_signal)(int, void(*)(int));
static void *libc_handle = NULL;
static int segillcount = 0;

void
assfault_handler(int sig)
{
    fprintf(stderr, "%s occured (%d)\n"
            , (sig==SIGSEGV)?"SIGSEGV":"SIGILL", ++segillcount);
asm("
    movl 0x44(%ebp),%ebx
    incl %ebx
    movl %ebx,0x44(%ebp)
");
}

/*
 * you may want to intercept sigprocmask, sigaction, setsig, .. also
 */
void 
(*signal(int signum, void (*sighandler)(int)))(int)
{
    /*
     * ignore if programm tries to set signal handler for SIGSEGV/SIGILL
     */
    if (signum == SIGSEGV)
    {
        fprintf(stderr, "signal(SIGSEGV, ...) call ignored [%d]\n", getpid());
        return assfault_handler;
    }

    if (signum == SIGILL)
    {
        fprintf(stderr, "signal(SIGSILL, ...) call ignored [%d]\n", getpid());
        return assfault_handler;
    }
    
    /*
     * call the original libc signal() -function
     */
    return o_signal(signum, sighandler);
}


static void
assfault_init(void)
{
    if ( (libc_handle = dlopen("libc.so", RTLD_NOW)) == NULL)
        if ( (libc_handle = dlopen("libc.so.6", RTLD_NOW)) == NULL)
        {
            fprintf(stderr, "error loading libc!\n");
            exit(-1);
        }

    REPLACE(libc_handle, signal, "signal");

    o_signal(SIGSEGV, assfault_handler);
    o_signal(SIGILL, assfault_handler);

    dlclose(libc_handle);
}


/*
 * this function is called by the loaded.
 */
void
_init(void)
{
    if (libc_handle != NULL)
        return; /* should never happen */

    fprintf(stderr, "assfault.so activated\n");
    assfault_init();
}

