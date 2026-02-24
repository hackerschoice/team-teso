/* wrezsweep - wrez detection and removal tool
 * not to be distributed, ever.
 */

#define	VERSION	"0.2"


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>


int isinfected (char *pathname, int disinfect);
int ctors_seek (FILE *fp, unsigned int ofs_low, unsigned int ofs_high,
	unsigned int ctors_act, unsigned int opc_mask,
	unsigned int opc_value);
unsigned int ctors_getold (unsigned char *virus);


int	verbose = 0;
int	ctors_fromheader = 0;
char *	virus_outname = NULL;


void
usage (char *progname)
{
	fprintf (stderr, "usage: %s [-h] [-x] [-D] [-v] [-d virus] \\\n"
		"\t\t<file1 [file2 [...]]>\n"
		"\n", progname);
	fprintf (stderr, "options\n"
		"\t-h\t\tthis help\n"
		"\t-x\t\ttry to fix/disinfect file\n"
		"\t-D\t\tuse alternate original-ctors detection code\n"
		"\t-v\t\tverbose mode\n"
		"\t-d virus\tdump virus code to file 'virus'\n"
		"\n");

	exit (EXIT_FAILURE);
}


int
main (int argc, char *argv[])
{
	char	c;
	char *	progname = argv[0];
	char **	oargv = argv;
	int	disinfect = 0;


	printf ("wrezsweep - version "VERSION"\n\n");

	if (argc < 2)
		usage (progname);

	while ((c = getopt (argc, argv, "hxDvd:")) != EOF) {
		switch (c) {
		case 'h':
			usage (progname);
			break;
		case 'x':
			disinfect = 1;
			break;
		case 'D':
			ctors_fromheader = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'd':
			virus_outname = optarg;
			break;
		default:
			usage (progname);
			break;
		}
	}

	if (optind == argc)
		usage (progname);

	if (verbose) {
		printf ("scanning %d files\n", argc - optind);
		if (disinfect)
			printf ("disinfection enabled\n");
	}

	printf ("===================================================="
		"==========================\n");

	for ( ; optind < argc ; ++optind) {
		printf ("FILE %s\n", oargv[optind]);

		isinfected (oargv[optind], disinfect);
	}

	exit (EXIT_SUCCESS);
}


/* 0 clean
 * 1 infected
 * -1 error
 */

int
isinfected (char *pathname, int disinfect)
{
	int		retval = -1;
	FILE *		fp = NULL;
	long int	fp_ofs;	/* temporary file offset */
	long int	fp_len;	/* victim file size */

	off_t		fp_new_end;
	unsigned char *	slide_data = NULL;
	unsigned int	slide_len;
	FILE *		fpv;
	unsigned char *	virus = NULL;
	int		n;
	Elf32_Ehdr	veh;
	Elf32_Shdr	seh;
	Elf32_Shdr	sh[32],	/* temporary */
			bss,	/* .bss section header table entry */
			ctors;	/* .ctors section */
	int		ctors_seen = 0;
	Elf32_Phdr	ptl1,	/* 1rst PT_LOAD segment header */
			ptl2;	/* 2nd PT_LOAD segment header */
	long int	ptl2_ofs;	/* file offset of header */
	int		vlen_sanity;	/* odd stuff */
	unsigned int	vlen;	/* virus length */
	unsigned int	vlen_filesz,
			vlen_addmem,
			vlen_virtual,
			vlen_offset;
	unsigned int	old_ctors,
			vir_ctors;
	unsigned int	new_displ,
			ph_lastphys;


	fp = fopen (pathname, "rb");
	if (fp == NULL) {
		perror ("fopen");
		return (-1);
	}

	if (fread (&veh, sizeof (veh), 1, fp) != 1) {
		perror ("fread Elf32_Ehdr");
		goto bail;
	}

	if (veh.e_ident[EI_MAG0] != ELFMAG0 ||
		veh.e_ident[EI_MAG1] != ELFMAG1 ||
		veh.e_ident[EI_MAG2] != ELFMAG2 ||
		veh.e_ident[EI_MAG3] != ELFMAG3)
	{
		if (verbose)
			printf ("   no ELF file\n");
		goto bail;
	}

	if (veh.e_type != ET_EXEC || veh.e_machine != EM_386)
		goto bail;

	if (veh.e_shoff == 0) {
		if (verbose)
			printf ("   section header table offset is zero\n");

		goto bail;
	}

	if (fseek (fp, veh.e_shoff, SEEK_SET) != 0) {
		perror ("fseek e_shoff");
		goto bail;
	}

	/* walk sections, until .bss is reached. because .bss is always at the
	 * end of the second PT_LOAD segment, we can expect our virus to be
	 * after .bss
	 */
	memset (&bss, '\0', sizeof (bss));
	for (n = 0 ; n < veh.e_shnum && n < 32 ; ++n) {
		if (fread (&sh[n], sizeof (sh[0]), 1, fp) != 1) {
			perror ("fread Elf32_Shdr");

			goto bail;
		}

		/* when .bss is found, copy it
		 */
		if (sh[n].sh_type == SHT_NOBITS)
			memcpy (&bss, &sh[n], sizeof (bss));

		/* check for .ctors section
		 */
		if (ctors_seen == 0 &&
			sh[n].sh_type == SHT_PROGBITS &&
			sh[n].sh_size == 8 &&
			sh[n].sh_flags == (SHF_WRITE | SHF_ALLOC))
		{
			ctors_seen = 1;
			memcpy (&ctors, &sh[n], sizeof (ctors));
		}
	}

	if (bss.sh_type != SHT_NOBITS) {
		if (verbose)
			printf ("   .bss section not found\n");
		goto bail;
	}

	if (veh.e_phoff == 0) {
		if (verbose)
			printf ("   segment header table offset is zero\n");
		goto bail;
	}
	if (fseek (fp, veh.e_phoff, SEEK_SET) != 0) {
		perror ("fseek e_phoff");
		goto bail;
	}

	for (n = 0 ; n < veh.e_phnum ; ++n) {
		if (fread (&ptl2, sizeof (ptl2), 1, fp) != 1) {
			perror ("fread Elf32_Phdr");
			goto bail;
		}

		if (ptl2.p_type == PT_LOAD && ptl2.p_flags == (PF_W | PF_R)) {
			ptl2_ofs = ftell (fp) - sizeof (ptl2);
			break;
		} else if (ptl2.p_type == PT_LOAD) {
			memcpy (&ptl1, &ptl2, sizeof (ptl1));
		}
	}
	if (n == veh.e_phnum) {
		if (verbose)
			printf ("   2nd PT_LOAD segment not found\n");
		goto bail;
	}

	vlen = ptl2.p_offset + ptl2.p_memsz;
	vlen -= bss.sh_offset + bss.sh_size;

	/* XXX: there are some weird files, where the end of .bss is past the
	 *      memsz of the data PT_LOAD segment. strange.
	 */
	vlen_sanity = vlen;
	if (vlen_sanity < 0)
		goto bail;


	if (vlen == 0) {
		if (verbose)
			printf ("CLEAN: %s\n", pathname);

		retval = 0;
		goto bail;
	}

	vlen_filesz = ptl2.p_offset + ptl2.p_filesz;
	vlen_filesz -= bss.sh_offset + bss.sh_size;
	vlen_addmem = vlen - vlen_filesz;
	vlen_virtual = bss.sh_addr + bss.sh_size;
	vlen_offset = bss.sh_offset + bss.sh_size;

	printf ("WARNING: file \"%s\", possible infection detected !\n"
		"         memory: %u bytes at 0x%08x\n"
		"           file: %u (+%u mem) bytes at 0x%08x\n",
		pathname,
		vlen, vlen_virtual, vlen_filesz, vlen_addmem,
		vlen_offset);

	/* read virus into memory, and optionally dump it to file for further
	 * analysis
	 */
	if (fseek (fp, vlen_offset, SEEK_SET) != 0) {
		perror ("fseek virus offset");
		goto bail;
	}

	virus = calloc (1, vlen_filesz);
	fread (virus, vlen_filesz, 1, fp);

	if (virus_outname != NULL) {
		if (verbose)
			printf ("DUMPING virus region (0x%x to 0x%x, "
				"%d bytes) to \"%s\"\n", vlen_offset,
			       vlen_offset + vlen_filesz, vlen_filesz,
			       virus_outname);

		fpv = fopen (virus_outname, "wb");

		if (fpv == NULL) {
			perror ("fopen virus");

			goto bail;
		}

		/* skip .ctors entry, only write real virus code
		 */
		fwrite (virus + sizeof (unsigned int),
			vlen_filesz - sizeof (unsigned int), 1, fpv);
		fclose (fpv);
	}

	fclose (fp);
	fp = NULL;

	if (disinfect == 0) {
		retval = (vlen == 0) ? 0 : 1;
		goto bail;
	}

	/* for disinfection, open the file read/write
	 */
	fp = fopen (pathname, "r+b");
	if (fp == NULL) {
		perror ("fopen disinfection");
		
		goto bail;
	}

	/* first patch the original .ctors. this will deactivate the virus
	 * code, even if we fail to later remove it cleanly from the file
	 */
	vir_ctors = vlen_virtual;
	old_ctors = ctors_getold (virus);

	if (old_ctors != 0xffffffff)
		old_ctors -= 4;	/* returns +4 since crt0.o walks downwards */

	if (ctors_seen) {
		if (ctors.sh_addr != old_ctors) {
			printf ("DISINFECTION WARNING: original .ctors "
				"addresses differ\n");
			printf ("   .ctors section header: 0x%08x\n"
				"     ctors from wrconfig: 0x%08x\n",
				ctors.sh_addr, old_ctors);
		}

		if (ctors_fromheader) {
			if (verbose)
				printf ("   overriding .ctors address\n");

			old_ctors = ctors.sh_addr;
		}
	}

	if (old_ctors == 0xffffffff) {
		printf ("DISINFECTION WARNING: either not wrez or its "
			"polymorph\n");
		printf ("   manually disinfect it (virus start: 0x%08x)\n",
			vir_ctors);
		printf ("   or override ctors disinfection using the '-D' "
			"option\n");

		goto bail;
	}

	printf ("DISINFECTING\n"
		"   old   ctors address: 0x%08x\n"
		"   virus ctors address: 0x%08x\n", old_ctors, vir_ctors);

	if (ctors_seek (fp, ptl1.p_offset, ptl1.p_offset + ptl1.p_filesz,
		vir_ctors, 0xf8, 0xb8))
	{
		printf ("FAILURE: cannot find viral ctors address in "
			"crt0.o\n");

		goto bail;
	}
	
	fp_ofs = ftell (fp);

	if (verbose) {
		printf ("   found virus ctors activation code within crt0.o "
			"at: 0x%08lx\n", fp_ofs);
	}

	/* overwrite first address (%ebx load), then search for the second
	 * one, immediatly after it (offset + 64 bytes)
	 */
	if (fwrite (&old_ctors, sizeof (old_ctors), 1, fp) != 1)
		goto bail;

	if (ctors_seek (fp, fp_ofs, fp_ofs + 64, vir_ctors, 0, 0)) {
		printf ("FAILURE: cannot find second viral ctors address "
			"in crt0.o\n");

		goto bail;
	}

	if (verbose)
		printf ("   found second virus ctors activation code "
			"at: 0x%08lx\n", ftell (fp));

	if (fwrite (&old_ctors, sizeof (old_ctors), 1, fp) != 1)
		goto bail;

	if (verbose)
		printf ("   restored old ctors address\n");

	printf ("   disabled virus activation, viral code is still in file, "
		"though\n");

	/* try to remove viral code from file
	 */
	if (fseek (fp, 0, SEEK_END) != 0)
		goto bail;

	fp_len = ftell (fp);
	slide_len = fp_len - (ptl2.p_offset + ptl2.p_filesz);
	new_displ = vlen_filesz + bss.sh_size;

	if (verbose)
		printf ("   sliding 0x%x bytes at the end of file (0x%x "
			"bytes forward)\n", slide_len, new_displ);

	slide_data = calloc (1, slide_len);
	if (fseek (fp, fp_len - slide_len, SEEK_SET) != 0)
		goto bail;

	if (fread (slide_data, slide_len, 1, fp) != 1) {
		perror ("fread slide-data");
		goto bail;
	}

	/* seek to end of old PT_LOAD segment and slide file end there
	 */
	if (fseek (fp, bss.sh_offset, SEEK_SET) != 0)
		goto bail;

	if (fwrite (slide_data, slide_len, 1, fp) != 1) {
		perror ("fwrite slide-data");
		goto bail;
	}

	fp_new_end = bss.sh_offset + slide_len;
	fflush (fp);
	ftruncate (fileno (fp), fp_new_end);

	ph_lastphys = ptl2.p_offset + ptl2.p_filesz;
	if (veh.e_shoff > ph_lastphys) {
		veh.e_shoff -= new_displ;
		if (fseek (fp, 0, SEEK_SET) != 0)
			goto bail;
		if (fwrite (&veh, sizeof (veh), 1, fp) != 1)
			goto bail;
	}

	/* repair second PT_LOAD header
	 */
	ptl2.p_filesz -= new_displ;
	ptl2.p_memsz -= vlen;
	if (fseek (fp, ptl2_ofs, SEEK_SET) != 0)
		goto bail;
	if (fwrite (&ptl2, sizeof (ptl2), 1, fp) != 1)
		goto bail;

	/* and fixup all slided sections
	 */
	if (fseek (fp, veh.e_shoff, SEEK_SET) != 0)
		goto bail;

	for (n = 0 ; n < veh.e_shnum ; ++n) {
		if (fread (&seh, sizeof (seh), 1, fp) != 1) {
			perror ("fread fixup Elf32_Shdr");
			goto bail;
		}

		if (seh.sh_offset > ph_lastphys) {
			seh.sh_offset -= new_displ;
			if (fseek (fp, - sizeof (seh), SEEK_CUR) != 0)
				goto bail;
			if (fwrite (&seh, sizeof (seh), 1, fp) != 1)
				goto bail;

			if (verbose)
				printf ("   section %d fixed\n", n);
		}
	}

	printf ("   successfully removed viral code from file\n");

bail:	if (fp != NULL)
		fclose (fp);

	if (virus != NULL)
		free (virus);
	if (slide_data != NULL)
		free (slide_data);

	return (retval);
}


/* ctors_seek
 *
 * seek within file `fp', between byte offset `ofs_low' and `ofs_high' for
 * the unaligned 32 bit unsigned number `ctors_act'
 *
 * return 1 on failure
 * return 0 on success, seek fp to the &ctors_act position
 */

int
ctors_seek (FILE *fp, unsigned int ofs_low, unsigned int ofs_high,
	unsigned int ctors_act, unsigned int opc_mask,
	unsigned int opc_value)
{
	long		ofs;
	unsigned char	dopcode;
	unsigned char	rbuf[4];
	unsigned int *	rbp;


	if (verbose)
		printf ("   scanning for 0x%08x in: [0x%x - 0x%x]\n",
			ctors_act, ofs_low, ofs_high);

	/* we do not have to optimize this with streaming buffers, since
	 * the FILE buffers do that, better than we ever can ;)
	 */
	if (fseek (fp, ofs_low, SEEK_SET) != 0)
		goto bail;
	memset (rbuf, '\x00', sizeof (rbuf));

	for (ofs = ofs_low ; ofs <= (ofs_high - sizeof (unsigned int)) ;
		ofs = ftell (fp))
	{
		dopcode = rbuf[0];
		dopcode &= opc_mask;

		if (fread (rbuf, sizeof (rbuf), 1, fp) != 1)
			goto bail;

		/* compare with given address
		 */
		rbp = (unsigned int *) &rbuf[0];
		if (*rbp == ctors_act && dopcode == opc_value) {
			if (fseek (fp, ofs, SEEK_SET) != 0)
				goto bail;

			return (0);
		}

		if (fseek (fp, ofs + 1, SEEK_SET) != 0)
			goto bail;
	}

bail:
	return (1);
}


unsigned int
ctors_getold (unsigned char *virus)
{
	virus += sizeof (unsigned int);	/* new ctors */

	/* kludge, skip until call opcode
	 */
	while (virus[2] != 0xe8)
		return (0xffffffff);

	virus += 2;

	virus += 1 + sizeof (unsigned int);	/* skip opcode + imm32 */

	/* virus points to wrconfig structure now
	 */
	return (((unsigned int *) virus)[2]);
}



