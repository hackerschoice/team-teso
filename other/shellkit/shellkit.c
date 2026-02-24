/* shellkit.c - experimentation program for included shellcodes
 *
 * team teso
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "shellkit.h"


void	usage (void);
void	sc_list (void);

int	dump = 0;
int	execute = 0;


void
usage (void)
{
	printf ("usage: shellkit [-hdlx] [-e env1 [-e env2] ...] [code-identifier1 [ci2 [...]]]\n\n");
	printf ("options:\n");
	printf ("\t-h\thelp, you're just viewing it\n"
		"\t-d\tdump shellcode in hex\n"
		"\t-l\tonly list available shellcodes\n"
		"\t-x\texecute choosen shellcode\n"
		"\t-e env\tbuild an environment for the shellcode, use -e list\n"
		"\t\tto get a list\n\n");
	printf ("the shellkit utility will build a chained block of codes described by the\n"
		"given code identifiers, copy it to a writeable place of memory and will\n"
		"do anything necessary to execute this block of code on your architecture.\n"
		"before executing the code the environments specified are installed.\n"
		"you can - of course - only execute code for your architecture.\n\n");

	exit (EXIT_FAILURE);
}


void
env_list (void)
{
	printf ("list of available environments:\n\n");

	exit (EXIT_SUCCESS);
}


void
sc_list (void)
{
	int		sc_walker;
	int		arch_walker;
	arch *		a;


	for (arch_walker = 0 ; shellcodes[arch_walker] != NULL ;
		++arch_walker)
	{
		a = shellcodes[arch_walker];

		printf ("%s:\n", a->arch_string);
		for (sc_walker = 0 ; a->arch_codes[sc_walker] != NULL ;
			++sc_walker)
		{
			printf ("\t%-30s  %3d\n",
				a->arch_codes[sc_walker]->code_string,
				a->arch_codes[sc_walker]->code_len);
		}
		printf ("\n");
	}

	exit (EXIT_SUCCESS);
}


int
main (int argc, char *argv[])
{
	int		c;
	int		xenvc = 0;
	char *		xenv[16];


	random_init ();
	memset (xenv, '\x00', sizeof (xenv));

	if (argc < 2)
		sc_list ();

	while ((c = getopt (argc, argv, "hdlxe:")) != -1) {
		switch (c) {
		case 'h':
			usage ();
			break;
		case 'd':
			dump = 1;
			break;
		case 'l':
			sc_list ();
			break;
		case 'x':
			execute = 1;
			break;
		case 'e':
			if (strcmp (optarg, "list") == 0)
				env_list ();
			if (xenvc >= 15) {
				fprintf (stderr, "insane, huh? dont mess\n");
				exit (EXIT_FAILURE);
			}
			xenv[xenvc++] = optarg;
			break;
		default:
			usage ();
			break;
		}
	}

	exit (EXIT_SUCCESS);
}


