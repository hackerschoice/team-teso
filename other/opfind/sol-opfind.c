/* sparc/solaris redirect opcodes find utility
 * -scut / teso
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


typedef struct mape {
	struct mape *		next;
	unsigned long int	data_start;
	unsigned long int	data_length;
	char *			perm;
	char *			origin;
} mape;

mape *	map_root = NULL;


void opcode_check (unsigned char *data, unsigned long int fromaddr);
void hexdump (unsigned char *data, unsigned int amount);


char *	progname;


void
usage (char *prog)
{
	fprintf (stderr, "usage: %s [options] <pid>\n\n", prog);
	fprintf (stderr, "options\n"
		"-g str\tgrep map entry for simple substring (strstr)\n"
		"-x\tcheck only executeable pages\n\n");

	exit (EXIT_FAILURE);
}


int
main (int argc, char *argv[])
{
	char			c;
	int			only_exec = 0;
	pid_t			fpid;		/* child pid, gets ptraced */
	char *			searchstr = NULL;

	FILE *			as_f;

	/* file to read mapping information */
	FILE *			map_f;		/* /proc/<pid>/maps stream */
	unsigned char		map_line[256];	/* one line each from map */

	mape *			mw;		/* map walker */


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

	if (sscanf (argv[argc - 1], "%lu", &fpid) != 1) {
		printf ("usage: %s <trace-pid>\n\n", argv[0]);

		exit (EXIT_FAILURE);
	}

	/* get maps
	 */
	snprintf (map_line, sizeof (map_line), "pmap %u | "
		"egrep \"[0-9A-F]+[ \t]+[0-9]+K\"", fpid);
	map_line[sizeof (map_line) - 1] = '\0';
	map_f = popen (map_line, "r");
	if (map_f == NULL) {
		perror ("fopen map-file");

		exit (EXIT_FAILURE);
	}

	while (fgets (map_line, sizeof (map_line), map_f) != NULL) {
		char		map_perm[32],
				map_origin[256];
		mape *		nmape;

		nmape = calloc (1, sizeof (mape));
		if (sscanf (map_line, "%08lX%*[ \t]%luK %[^ ]%*[ \t]%[^\n]",
			(long int *) &nmape->data_start,
			&nmape->data_length,
			map_perm, map_origin) != 4)
		{
			perror ("invalid map-line");
			fprintf (stderr, "line: %s\n", map_line);

			exit (EXIT_FAILURE);
		}

		nmape->data_length *= 1024;

		/* should we search for a substring ?
		 */
		if (searchstr != NULL && strstr (map_line, searchstr) == NULL) {
			free (nmape);

			continue;
		}

		/* in case the user wants only the real explicit executeable
		 * pages (a PaX user ;-), then fullfil his wish
		 */
		if (only_exec && strstr (map_perm, "exec") == NULL) {
			free (nmape);

			continue;
		}

		nmape->perm = strdup (map_perm);
		nmape->origin = strdup (map_origin);
		nmape->next = map_root;
		map_root = nmape;

	}
	fclose (map_f);

	snprintf (map_line, sizeof (map_line), "/proc/%lu/as", fpid);
	as_f = fopen (map_line, "rb");
	if (as_f == NULL) {
		perror ("open as file");

		exit (EXIT_FAILURE);
	}

	for (mw = map_root ; mw != NULL ; mw = mw->next) {
		unsigned char *	data;
		unsigned long	dw;	/* data walker */

		fprintf (stderr, "mapped: 0x%08lx, len: 0x%lx, "
			"prot: %s, origin: %s\n",
			mw->data_start, mw->data_length,
			mw->perm, mw->origin);

		/* seek to memory segment start
		 */
		fseek (as_f, mw->data_start, SEEK_SET);
		data = malloc (mw->data_length);
		if (fread (data, 1, mw->data_length, as_f) != mw->data_length) {
			fprintf (stderr, "fread read too less (should %lu)\n",
				mw->data_length);

			exit (EXIT_FAILURE);
		}

		for (dw = 0 ; dw < mw->data_length ; dw += 4)
			opcode_check (&data[dw], mw->data_start + dw);

		free (data);
	}

	fclose (as_f);

	exit (EXIT_SUCCESS);
}


void
opcode_check (unsigned char *data, unsigned long int fromaddr)
{
	unsigned long int	inst;
	char *			inst_s = NULL;
	char *			inst_rd = NULL;
	char *			inst_rs1 = NULL;
	char *			inst_rs2 = NULL;
	unsigned long int	inst_off = 0;
	int			inst_off_neg = 0;
	char *	regs[] = {
		"g0", "g1", "g2", "g3", "g4", "g5", "g6", "g7",
		"o0", "o1", "o2", "o3", "o4", "o5", "o6", "o7",
		"l0", "l1", "l2", "l3", "l4", "l5", "l6", "l7",
		"i0", "i1", "i2", "i3", "i4", "i5", "i6", "i7", NULL };


	inst = *((unsigned long int *) data);
#ifdef DEBUG
	fprintf (stderr, "0x%08lx: instruction = 0x%08lx\n", fromaddr, inst);
#endif

	switch (inst & 0xc1f82000) {
	/* jmpl r[rs1] + r[rs2], r[rd]
	 */
	case (0x81c00000):
		inst_s = "jmpl";

		inst_rd = regs[(inst & 0x3e000000) >> 25];
		inst_rs1 = regs[(inst & 0x0007c000) >> 14];
		inst_rs2 = regs[inst & 0x000001f];

		fprintf (stderr, "0x%08lx: [0x%08lx]\t%s\t%%%s + %%%s, %%%s\n",
			fromaddr, inst, inst_s, inst_rs1, inst_rs2, inst_rd);
		break;

	/* jmpl r[rs1] + sim13, r[rd]
	 */
	case (0x81c02000):
		inst_s = "jmpl";

		inst_rd = regs[(inst & 0x3e000000) >> 25];
		inst_rs1 = regs[(inst & 0x0007c000) >> 14];

		inst_off = inst & 0x00001fff;

		/* negative immediate offset ? */
		if (inst_off & 0x1000) {
			inst_off = (~inst_off & 0x0fff) + 1;
			inst_off_neg = 1;
		}

		fprintf (stderr, "0x%08lx: [0x%08lx]\t%s\t%%%s %s %lu, %%%s\n",
			fromaddr, inst, inst_s, inst_rs1,
			inst_off_neg ? "-" : "+", inst_off, inst_rd);
		break;
	default:
		break;
	}

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
