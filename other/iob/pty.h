/* brutate
 *
 * scut / team teso
 *
 * pseudo tty handler include file
 */

#ifndef	BR_PTY_H
#define	BR_PTY_H

#include <sys/types.h>
#include <sys/ioctl.h>
#include <termios.h>


/* pty_m_open
 *
 * open master pty and return actual file used in `pts_name', which has
 * to point to allocated memory and must be at least 20 bytes long.
 *
 * return master pty filedescriptor in case of success
 * return negative error number in case of failure
 */

int	pty_m_open (char *pts_name);


/* pty_s_open
 *
 * open slave pty with filename pointed to by `pts_name' and bind it to
 * master pty with descriptor `fdm'.
 *
 * return slave pty filedescriptor in case of success
 * return negative error number in case of failure
 */

int	pty_s_open (int fdm, char *pts_name);


/* pty_fork
 *
 * fork a child process and create a pty binding between this parent process
 * (master pty) and the child process (slave pty). return the master pty
 * filedescriptor through `fd_master_ptr'. `slave_name' may be NULL or contain
 * a pointer to allocated memory where the slave pty name will be stored.
 * `slave_termios' may be NULL or contain a valid termios structure which will
 * initialize the slave terminal line discipline. in case `slave_winsize' is
 * not NULL it will initialize the slave pty window size.
 *
 * return values are the same as the ones of fork(2) (see "man 2 fork").
 */

pid_t	pty_fork (int *fd_master_ptr, char *slave_name,
	const struct termios *slave_termios,
	const struct winsize *slave_winsize);


/* set_noecho
 *
 * disable echo capability on terminal associated with filedescriptor `fd'
 *
 * return in any case
 */

void	set_noecho (int fd);


/* tty_raw
 *
 * put terminal associated with filedescriptor `fd' into raw mode, saving the
 * current mode into the termios structure pointed to by `sios' in case it is
 * non-NULL
 *
 * return 0 on success
 * return -1 on failure
 */

int	tty_raw (int fd, struct termios *sios);


/* pty_setup
 *
 * helper routine, which allocates a pseudo terminal and tries to preserve
 * as much settings as possible from the current terminal. then it forks
 * away a child process in which nothing happens except that the handler
 * function `handler' is called with `data' as parameter.
 *
 * returns the filedescriptor of the pty on success
 * exits in case of failure
 */

int	pty_setup (void (* handler)(void *), void *data);

#endif

