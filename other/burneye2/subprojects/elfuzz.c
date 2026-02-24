

#include <stdio.h>
#include <stdlib.h>
#include <elf.h>

#include <utility.h>


int
main (int argc, char *argv[])
{
	FILE *		fp;
	unsigned char *	elf_input;
	unsigned int	elf_input_size;

	unsigned int	mutations = 23;


	if (argc != 3) {
		fprintf (stderr, "usage: %s <in> <out>\n\n", argv[0]);

		exit (EXIT_FAILURE);
	}

	fp = fopen (argv[1], "rb");
	if (fp == NULL) {
		perror ("fopen input");

		exit (EXIT_FAILURE);
	}

	fseek (fp, 0, SEEK_END);
	elf_input_size = ftell (fp);
	elf_input = calloc (1, elf_input_size);
	fseek (fp, 0, SEEK_SET);
	fread (elf_input, 1, elf_input_size, fp);
	fclose (fp);

	be_randinit ();


	while (mutations-- > 0) {
		unsigned int *	rptr;

		rptr = (unsigned int *)
			&elf_input[be_random (elf_input_size - 4)];
	//	printf ("0x%04x\n", ((unsigned char *) rptr) - elf_input);

		switch (be_random (2)) {
		case (0):
			*rptr -= be_random (0x100);
			break;
		case (1):
			*rptr = be_random (0xffffffff);
			break;
		default:
			exit (EXIT_FAILURE);
		}
	}
	elf_input_size += be_random (3);


	fp = fopen (argv[2], "wb");
	if (fp == NULL) {
		perror ("fopen output");

		exit (EXIT_FAILURE);
	}

	fwrite (elf_input, 1, elf_input_size, fp);
	fclose (fp);

	exit (EXIT_SUCCESS);
}


