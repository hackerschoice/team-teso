#include <signal.h>
#include <bscan/signal.h>

/*
 * add the signals that you want to be set to default-action
 */
int
do_sig_setall (sighandler_t action)
{
#ifdef SIGHUP
    signal (SIGHUP, action);
#endif
#ifdef SIGINT
    signal (SIGINT, action);
#endif
#ifdef SIGQUIT
    signal (SIGQUIT, action);
#endif
#ifdef SIGABRT
    signal (SIGABRT, action);
#endif
#ifdef SIGPIPE
    signal (SIGPIPE, action);
#endif
#ifdef SIGALRM
    signal (SIGALRM, action);
#endif
#ifdef SIGTERM
    signal (SIGTERM, action);
#endif
#ifdef SIGUSR1
    signal (SIGUSR1, action);
#endif
#ifdef SIGUSR1
    signal (SIGUSR1, action);
#endif
#ifdef SIGCHLD
    signal (SIGCHLD, action);
#endif
#ifdef SIGCOMT
    signal (SIGCOMT, action);
#endif
#ifdef SIGSTOP
    signal (SIGSTOP, action);
#endif
#ifdef SIGTSTP
    signal (SIGTSTP, action);
#endif
#ifdef SIGTTIM
    signal (SIGTTIM, action);
#endif
#ifdef SIGTTOU
    signal (SIGTTOU, action);
#endif

    return (0);
}

/*
 * sig-ctl function.
 * atm only SIG_DFL implemented....
 */
int
sigctl (int flags, sighandler_t action)
{
    int ret = 0;

    if (flags & SIG_SETALL)
	ret = do_sig_setall (action);

    return (ret);
}
