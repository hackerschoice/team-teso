/* redirect opcodes find utility
 * -scut / teso
 */

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


void opcode_check (unsigned char *data, unsigned int dlen,
	unsigned long fromaddr);
void hexdump (unsigned char *data, unsigned int amount);


char *	progname;


void
usage (char *prog)
{
	fprintf (stderr, "usage: %s [options] <pid>\n\n", prog);
	fprintf (stderr, "options\n"
		"-g str\tgrep map entry for simple substring (strstr)\n"
		"-x\tcheck only executeable pages (normal any page, since on x86\n"
		"\tall pages that are writeable are executable, too. use this w/ PaX\n\n");

	exit (EXIT_FAILURE);
}


int
main (int argc, char *argv[])
{
	char			c;
	int			only_exec = 0;
	pid_t			fpid;		/* child pid, gets ptraced */
	char *			searchstr = NULL;
	struct user		regs;		/* PTRACE pulled registers */
	unsigned long int	addr,		/* segment start address */
				addr_end,	/* segment end address */
				addr_walker,	/* walker to dump memory */
				len;		/* length of segment */

	/* array to temporarily store data into */
	unsigned char		data_saved[sizeof (unsigned long int)];

	/* file to read mapping information */
	FILE *			map_f;		/* /proc/<pid>/maps stream */
	unsigned char		map_line[256];	/* one line each from map */


	progname = argv[0];

	if (argc < 2)
		usage (progname);

	while ((c = getopt (argc, argv, "g:x")) != EOF) {
		switch (c) {
		case 'g':
			searchstr = optarg;
			break;
		case 'x':
			only_exec = 1;
			break;
		default:
			usage (progname);
			break;
		}
	}

	if (sscanf (argv[argc - 1], "%u", &fpid) != 1) {
		printf ("usage: %s <trace-pid>\n\n", argv[0]);

		exit (EXIT_FAILURE);
	}

	/* try to attach to process
	 */
	if (ptrace (PTRACE_ATTACH, fpid, NULL, NULL) < 0) {
		perror ("ptrace");

		exit (EXIT_FAILURE);
	}


	memset (&regs, 0, sizeof (regs));

	if (ptrace (PTRACE_GETREGS, fpid, NULL, &regs) < 0) {
		perror ("ptrace PTRACE_GETREGS");
		exit (EXIT_FAILURE);
	}
	fprintf (stderr, "[md] pid %u, freezed at 0x%08lx\n", fpid, regs.regs.eip);


	snprintf (map_line, sizeof (map_line), "/proc/%d/maps", fpid);
	map_line[sizeof (map_line) - 1] = '\0';
	map_f = fopen (map_line, "r");
	if (map_f == NULL) {
		perror ("fopen map-file");

		exit (EXIT_FAILURE);
	}

	while (fgets (map_line, sizeof (map_line), map_f) != NULL) {
		char		map_perm[8];

		if (sscanf (map_line, "%08lx-%08lx %7[rwxp-] ",
			&addr, &addr_end, map_perm) != 3)
		{
			perror ("invalid map-line");

			exit (EXIT_FAILURE);
		}

		/* should we search for a substring ?
		 */
		if (searchstr != NULL && strstr (map_line, searchstr) == NULL)
			continue;

		/* in case the user wants only the real explicit executeable
		 * pages (a PaX user ;-), then fullfil his wish
		 */
		if (only_exec && map_perm[2] != 'x')
			continue;

		fprintf (stderr, "%s", map_line);

		if (addr_end < addr) {
			fprintf (stderr, "sanity required, not so: "
				"addr = 0x%08lx, addr_end = 0x%08lx",
				addr, addr_end);

			exit (EXIT_FAILURE);
		}
		len = addr_end - addr;
		map_perm[sizeof (map_perm) - 1] = '\0';	/* ;-) */


		/* save data, assuming addr is page aligned */
		for (addr_walker = 0 ;
			addr_walker <= (len - sizeof (unsigned long int)) ;
			addr_walker += 1)
		{
			errno = 0;

			/* yeah! i fucking like a fucking million context
			 * switches - linux sucks! :->
			 */
			*((unsigned long int *) &data_saved[0]) =
				ptrace (PTRACE_PEEKDATA, fpid,
					addr + addr_walker, NULL);
			if (errno != 0) {
				fprintf (stderr,
					"[0x%08lx] invalid PTRACE_PEEKDATA\n",
					addr + addr_walker);

				exit (EXIT_FAILURE);
			}

			opcode_check (&data_saved[0], 2, addr + addr_walker);
		}
	}
	fclose (map_f);

	if (ptrace (PTRACE_DETACH, fpid, NULL, NULL) < 0) {
		perror ("ptrace PTRACE_DETACH");

		exit (EXIT_FAILURE);
	}

	fprintf (stderr, "[md] released pid %u\n", fpid);

	exit (EXIT_SUCCESS);
}


void
opcode_check (unsigned char *data, unsigned int dlen,
	unsigned long fromaddr)
{
	char *	out = NULL;


	if (dlen < 2)
		return;

	/* hardcoded, doh!
	 */
	if (data[0] != 0xff)
		return;

	switch (data[1]) {
	case (0xe0):
		out = "jmp *%eax";
		break;
	case (0xe1):
		out = "jmp *%ecx";
		break;
	case (0xe2):
		out = "jmp *%edx";
		break;
	case (0xe3):
		out = "jmp *%ebx";
		break;
	case (0xee):
		out = "jmp *%esi";
		break;
	case (0xef):
		out = "jmp *%edi";
		break;

	case (0xd0):
		out = "call *%eax";
		break;
	case (0xd1):
		out = "call *%ecx";
		break;
	case (0xd2):
		out = "call *%edx";
		break;
	case (0xd3):
		out = "call *%ebx";
		break;
	case (0xd6):
		out = "call *%esi";
		break;
	case (0xd7):
		out = "call *%edi";
		break;
	}

	if (out != NULL)
		fprintf (stderr, "    [0x%08lx] %s\n", fromaddr, out);

	return;
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
