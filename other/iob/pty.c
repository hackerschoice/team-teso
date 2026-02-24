/* iob - i/o bridge
 *
 * by scut, based mostly of r. stevens masterpiece apue with some twirks
 *
 * pseudo tty handler
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <termios.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef	TIOCGWINSZ
#include <sys/ioctl.h>
#endif
#ifdef	SYS_V_RELEASE_4
#include <stropts.h>
#endif
#include <unistd.h>


#ifdef	SYS_V_RELEASE_4

extern char	*ptsname (int);		/* prototype not in any system header */

int
pty_m_open (char *pts_name)
{
	char	*ptr;
	int	fdm;

	strcpy (pts_name, "/dev/ptmx");
	fdm = open (pts_name, O_RDWR);
	if (fdm < 0)
		return (-1);

	if (grantpt (fdm) < 0) {
		close (fdm);
		return (-2);
	}

	if (unlockpt (fdm) < 0) {
		close (fdm);
		return (-3);
	}

	ptr = ptsname (fdm);
	if (ptr == NULL) {
		close (fdm);
		return (-4);
	}

	strcpy (pts_name, ptr);

	return (fdm);
}


int
pty_s_open (int fdm, char *pts_name)
{
	int	fds;

	fds = open (pts_name, O_RDWR);
	if (fds < 0) {
		close (fdm);
		return (-5);
	}

	if (ioctl (fds, I_PUSH, "ptem") < 0) {
		close (fdm);
		close (fds);
		return (-6);
	}

	if (ioctl (fds, I_PUSH, "ldterm") < 0) {
		close (fdm);
		close (fds);
		return (-7);
	}

	if (ioctl (fds, I_PUSH, "ttcompat") < 0) {
		close (fdm);
		close (fds);
		return (-8);
	}

	return (fds);
}

#else


int
pty_m_open (char *pts_name)
{
	int	fdm;
	char	*ptr1,
		*ptr2;

	strcpy (pts_name, "/dev/ptyXY");
	for (ptr1 = "pqrstuvwxyzPQRST" ; *ptr1 != 0 ; ++ptr1) {
		pts_name[8] = *ptr1;

		for (ptr2 = "0123456789abcdef" ; *ptr2 != 0 ; ++ptr2) {
			pts_name[9] = *ptr2;
			fdm = open (pts_name, O_RDWR);
			if (fdm < 0) {
				if (errno == ENOENT)
					return (-1);
				else
					continue;
			}

			pts_name[5] = 't';

			return (fdm);
		}
	}

	return (-1);
}


int
pty_s_open (int fdm, char *pts_name)
{
	struct group	*grp_ptr;
	int		gid,
			fds;

	grp_ptr = getgrnam ("tty");
	if (grp_ptr != NULL)
		gid = grp_ptr->gr_gid;
	else
		gid = -1;

	chown (pts_name, getuid (), gid);
	chmod (pts_name, S_IRUSR | S_IWUSR | S_IWGRP);

	fds = open (pts_name, O_RDWR);
	if (fds < 0) {
		close (fdm);

		return (-1);
	}

	return (fds);
}

#endif


/* pty_fork
 *
 */

pid_t
pty_fork (int *fd_master_ptr, char *slave_name,
	const struct termios *slave_termios,
	const struct winsize *slave_winsize)
{
	int	fdm,
		fds;
	pid_t	pid;
	char	pts_name[20];

	fdm = pty_m_open (pts_name);
	if (fdm < 0) {
		exit (EXIT_FAILURE);
	}

	if (slave_name != NULL)
		strcpy (slave_name, pts_name);

	pid = fork ();
	if (pid < 0)
		return (-1);

	if (pid == 0) {
		if (setsid () < 0)
			exit (EXIT_FAILURE);
		fds = pty_s_open (fdm, pts_name);
		if (fds < 0)
			exit (EXIT_FAILURE);
		close (fdm);

#if defined(TIOCSCTTY) && !defined(CIBAUD)
		if (ioctl (fds, TIOCSCTTY, (char *) 0) < 0)
			exit (EXIT_FAILURE);
#endif
		if (slave_termios != NULL) {
			if (tcsetattr (fds, TCSANOW, slave_termios) < 0)
				exit (EXIT_FAILURE);
		}
		if (slave_winsize != NULL) {
			if (ioctl (fds, TIOCSWINSZ, slave_winsize) < 0)
				exit (EXIT_FAILURE);
		}

		if (dup2 (fds, STDIN_FILENO) != STDIN_FILENO ||
			dup2 (fds, STDOUT_FILENO) != STDOUT_FILENO ||
			dup2 (fds, STDERR_FILENO) != STDERR_FILENO)
		{
			exit (EXIT_FAILURE);
		}
		if (fds > STDERR_FILENO)
			close (fds);

		return (0);	/* just like fork (), child */
	} else {
		*fd_master_ptr = fdm;

		return (pid);
	}
}


void
set_noecho (int fd)
{
	struct termios	stermios;

	if (tcgetattr (fd, &stermios) < 0)
		exit (EXIT_FAILURE);

	stermios.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
	stermios.c_oflag &= ~(ONLCR);

	if (tcsetattr (fd, TCSANOW, &stermios) < 0)
		exit (EXIT_FAILURE);

	return;
}


int
tty_raw (int fd, struct termios *sios)
{
	struct termios	tios;


	if (sios != NULL && tcgetattr (fd, sios) < 0)
		return (-1);

	/* saved old termios structure, now copy it to work with it
	 */
	memcpy (&tios, sios, sizeof (struct termios));

	tios.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
	tios.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
	tios.c_cflag &= ~(CSIZE | PARENB);
	tios.c_cflag |= CS8;
	tios.c_oflag &= ~(OPOST);
	tios.c_cc[VMIN] = 1;
	tios.c_cc[VTIME] = 0;

	if (tcsetattr (fd, TCSAFLUSH, &tios) < 0)
		return (-1);

	return (0);
}


int
pty_setup (void (* handler)(void *), void *data)
{
	int			interactive,
				fdm;
	pid_t			mpid;

	char			slave_name[20];
	struct termios		ts_orig;
	struct termios *	ts_init = NULL;
	struct winsize		ws_orig;
	struct winsize *	ws_init = NULL;


	interactive = isatty (STDIN_FILENO);
	if (interactive != 0) {
		if (tcgetattr (STDIN_FILENO, &ts_orig) < 0)
			exit (EXIT_FAILURE);

		ts_init = &ts_orig;

		if (ioctl (STDIN_FILENO, TIOCGWINSZ, (char *) &ws_orig) < 0)
			exit (EXIT_FAILURE);

		ws_init = &ws_orig;
	}

	mpid = pty_fork (&fdm, slave_name, ts_init, ws_init);
	if (mpid < 0)
		exit (EXIT_FAILURE);

	/* child calls handler
	 */
	if (mpid == 0) {
		handler (data);

		/* handler shouldn't return
		 */
		printf ("pty handler returned, failure\n");
		exit (EXIT_FAILURE);
	}

	/* parent just returns master filedescriptor
	 */
	return (fdm);
}

