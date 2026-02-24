/*
 * most of this stuff is ripped from solar's excelent john-1.6 source
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <unistd.h>
#include <stdlib.h>
#include <termios.h>

static int tty_fd = 0;
static int tty_buf = -1;
static struct termios saved_ti;


/*
 *  Reads a character, returns -1 if no data available or on error.
 */
int
tty_getchar ()
{
    int c;

    /* 
     * process buffer first
     */
    if (tty_buf != -1)
    {
	c = tty_buf;
	tty_buf = -1;
	return (c);
    }

    if (tty_fd)
    {
	c = 0;
	if (read (tty_fd, &c, 1) > 0)
	    return c;
    }

    return (-1);
}

/*
 * check if someone pressed a key
 * Actually we do a read on the fd and store the result in a buffer
 * todo: check with ioctl if data is pending
 * return 1 is data is pending, 0 if not
 */
int
tty_ischar ()
{
    if (tty_buf != -1)
	return (1);

    if ((tty_buf = tty_getchar ()) != -1)
	return (1);

    return (0);
}


/*
 * Restores the terminal parameters and closes the file descriptor.
 */
void
tty_done ()
{
    int fd;

    if (!tty_fd)
	return;

    fd = tty_fd;
    tty_fd = 0;
    tcsetattr (fd, TCSANOW, &saved_ti);

    close (fd);
}


/* 
 * Initializes the terminal for unbuffered non-blocking input. Also registers
 * tty_done() via atexit().
 */
void
tty_init ()
{
    int fd;
    struct termios ti;

    if (tty_fd)
	return;

    if ((fd = open ("/dev/tty", O_RDONLY | O_NONBLOCK)) < 0)
	return;

    if (tcgetpgrp (fd) != getpid ())
    {
	close (fd);
	return;
    }

    tcgetattr (fd, &ti);
    saved_ti = ti;
    ti.c_lflag &= ~(ICANON | ECHO);
    ti.c_cc[VINTR] = 3;		/* CTRL-C is INTR */
    ti.c_cc[VMIN] = 1;
    ti.c_cc[VTIME] = 0;
    tcsetattr (fd, TCSANOW, &ti);

    tty_fd = fd;

    atexit (tty_done);
}
