/* memory dump utility
 * -scut
 */

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <libgen.h>	/* basename */


void dr_dump (FILE *out, struct user *child);
void hexdump (unsigned char *data, unsigned int amount);


int
main (int argc, char *argv[], char *envp[])
{
	pid_t			fpid;		/* child pid, gets ptraced */
	char *			argv0;
	struct user		regs;		/* PTRACE pulled registers */
	unsigned long int	addr,		/* segment start address */
				addr_end,	/* segment end address */
				len;		/* length of segment */
	unsigned long int	addr_walker,	/* walker to dump memory */
				eip;		/* current childs eip */

	/* array to temporarily store data into */
	unsigned char		data_saved[sizeof (unsigned long int)];

	/* file to read mapping information */
	FILE *			map_f;		/* /proc/<pid>/maps stream */
	unsigned char		map_line[256];	/* one line each from map */

	/* data for the dump files */
	FILE *			dump_f;		/* stream */
	char			dump_name[64];	/* filename buffer */


	if (argc < 2) {
		printf ("usage: %s <argv0 [argv1 [...]]>\n\n", argv[0]);
		printf ("will run 'argv0' as program with given arguments.\n\n");

		exit (EXIT_FAILURE);
	}

	fpid = fork ();
	if (fpid < 0) {
		perror ("fork");
		exit (EXIT_FAILURE);
	}
	if (fpid == 0) {	/* child */
		if (ptrace (PTRACE_TRACEME, 0, NULL, NULL) != 0) {
			perror ("ptrace PTRACE_TRACEME");
			exit (EXIT_FAILURE);
		}
		fprintf (stderr, "  child: TRACEME set\n");

		fprintf (stderr, "  child: executing: %s\n", argv[2]);
		close (1);
		dup2 (2, 1);
		execve (argv[1], &argv[1], envp);

		/* failed ? */
		perror ("execve");
		exit (EXIT_FAILURE);
	}

	wait (NULL);

	memset (&regs, 0, sizeof (regs));

	if (ptrace (PTRACE_GETREGS, fpid, NULL, &regs) < 0) {
		perror ("ptrace PTRACE_GETREGS");
		exit (EXIT_FAILURE);
	}
	fprintf (stderr, "[0x%08lx] first stop\n", regs.regs.eip);
	dr_dump (stderr, &regs);

	regs.u_debugreg[0] = 0x41414141;
	if (ptrace (PTRACE_SETREGS, fpid, NULL, &regs) < 0) {
		perror ("ptrace PTRACE_GETREGS");
		exit (EXIT_FAILURE);
	}
	sleep (10);
	if (ptrace (PTRACE_GETREGS, fpid, NULL, &regs) < 0) {
		perror ("ptrace PTRACE_GETREGS");
		exit (EXIT_FAILURE);
	}
	fprintf (stderr, "[0x%08lx] first stop\n", regs.regs.eip);
	dr_dump (stderr, &regs);

	/* now single step until given eip is reached */
	do {
		sleep (1);

		if (ptrace (PTRACE_SYSCALL, fpid, NULL, NULL) < 0) {
			perror ("ptrace PTRACE_SINGLESTEP");
			exit (EXIT_FAILURE);
		}
		wait (NULL);

		memset (&regs, 0, sizeof (regs));
		if (ptrace (PTRACE_GETREGS, fpid, NULL, &regs) < 0) {
			perror ("ptrace PTRACE_GETREGS");
			exit (EXIT_FAILURE);
		}
		fprintf (stderr, "0x%08lx\n", regs.regs.eip);
		dr_dump (stderr, &regs);
	} while (1);

	if (ptrace (PTRACE_DETACH, fpid, NULL, NULL) < 0) {
		perror ("ptrace PTRACE_DETACH");
		exit (EXIT_FAILURE);
	}

	fprintf (stderr, "MEMDUMP: success. terminating.\n");
	exit (EXIT_SUCCESS);
}



void
hexdump (unsigned char *data, unsigned int amount)
{
	unsigned int	dp, p;	/* data pointer */
	const char	trans[] =
		"................................ !\"#$%&'()*+,-./0123456789"
		":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
		"nopqrstuvwxyz{|}~...................................."
		"....................................................."
		"........................................";

	for (dp = 1; dp <= amount; dp++) {
		printf ("%02x ", data[dp-1]);
		if ((dp % 8) == 0)
			printf (" ");
		if ((dp % 16) == 0) {
			printf ("| ");
			p = dp;
			for (dp -= 16; dp < p; dp++)
				printf ("%c", trans[data[dp]]);
			printf ("\n");
		}
	}
	if ((amount % 16) != 0) {
		p = dp = 16 - (amount % 16);
		for (dp = p; dp > 0; dp--) {
			printf ("   ");
			if (((dp % 8) == 0) && (p != 8))
				printf (" ");
		}
		printf (" | ");
		for (dp = (amount - (16 - p)); dp < amount; dp++)
			printf ("%c", trans[data[dp]]);
	}
	printf ("\n");

	return;
}


void
dr_dump (FILE *out, struct user *child)
{
	char *	desc[] = { "dr0 (debug address register)",
		"dr1 (debug address register)",
		"dr2 (debug address register)",
		"dr3 (debug address register)",
		"dr4 (reserved)",
		"dr5 (reserved)",
		"dr6 (debug status register)",
		"dr7 (debug control register)" };
	int	n;

	for (n = 0 ; n < 8 ; ++n) {
		fprintf (out, "\t0x%08lx  %s\n", child->u_debugreg[n],
			desc[n]);
	}
}


