/* writeonly redo if dirtyh.c.. hmm, still ugly, but cbreak mode - typo/teso */

#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <getopt.h>

#define EXTERN	extern
#define PRIVATE	static
#define PUBLIC

PRIVATE struct	termios save_termios;
PRIVATE int	ttysavefd = -1;
PRIVATE enum	{ RESET, DIRTY } ttystate = RESET;

int tty_dirtyterm (int fd) {
    struct termios	buf;

    if (tcgetattr(fd, &save_termios) < 0)
	return(-1);
    
    buf = save_termios;

    buf.c_lflag &= ~(ECHO | ICANON);

    buf.c_cc[VMIN] = 1;
    buf.c_cc[VTIME] = 0;

    if (tcsetattr(fd, TCSAFLUSH, &buf) <0)
	return(-1);
    
    ttystate = DIRTY;
    ttysavefd = fd;
    
    return(0);
}

int tty_reset (int fd) {
    if (ttystate == RESET)
	return(0);

    if (tcsetattr(fd, TCSAFLUSH, &save_termios) < 0)
	return(-1);

    ttystate = RESET;
    return(0);
}

void tty_cleanup (void) {
    if (ttysavefd >= 0) {
	fflush(stdout);
	tty_reset(ttysavefd);
    }
    exit(EXIT_SUCCESS);
}

void err (const int syserr, const char *msg, ...) {
    va_list	ap;

    printf("err: ");

    va_start (ap, msg);
    vprintf (msg, ap);
    va_end (ap);

    if (syserr)
        printf(": %s\n", sys_errlist[errno]);
    else
        printf("\n");

    tty_cleanup();
    exit(EXIT_FAILURE);
}

void sig_catch (int signo) {
    printf("%s\n", sys_siglist[signo]);
    tty_cleanup();
}

int main (int argc, char **argv) {
    int		i, fd;
    char	c;
    char        moo[2]; /* char + \0 */

    if (argc < 2)
	err(0, "usage: %s </dev/ttyXY>", argv[0]);

    if (signal(SIGINT, sig_catch) == SIG_ERR)
	err(1, "signal(SIGINT) error");
    if (signal(SIGQUIT, sig_catch) == SIG_ERR)
	err(1, "signal(SIGQUIT) error");
    if (signal(SIGTERM, sig_catch) == SIG_ERR)
	err(1, "signal(SIGTERM) error");

    if ( (fd = open(argv[1], O_WRONLY)) < 0)
	err(1, "open() error");

    tty_dirtyterm(STDIN_FILENO);

    while ( (i = read(STDIN_FILENO, &c, 1)) == 1) {
	c &= 255;
	sprintf(moo, "%c", c);
	printf("%c", c);
	if (c == 127)
	    printf("\b \b");
	fflush(stdout);
	ioctl(fd, TIOCSTI, moo);
    }

    tty_reset(STDIN_FILENO);
    if (i <= 0)
	err(1, "read error");

    return(42); /* not reached */
}
