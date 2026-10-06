/* rpctest
 *
 * smiler / teso
 */
#include "rpc.h"
#include "pmap.h"

static void help_command (void);

int
main (int argc, char **argv)
{
	char    line[200],
	       *args[15];
	int     argcount;

	puts ("RPC-test v"VERSION" by smiler\n");

	srand (time (NULL));

	bzero (line, sizeof (line));

	printf ("[] > ");
	fflush (stdout);

	for (; fgets (line, sizeof (line) - 1, stdin);
	     printf ("\n[] > "), fflush (stdout)) {
		strip_crlf (line);

		argcount = parse_args (line, args);
		if (!argcount)
			continue;


		if (!strcasecmp (args[0], "help")) {
			help_command ();
		} else if (!strcasecmp (args[0], "quit")) {
			exit (0);
		} else if (!strcasecmp (args[0], "dump")) {
			if (argcount < 2) {
				printf ("usage: dump <hostname>\n");
			} else
				pmap_dump (args[1]);
		} else if (!strcasecmp (args[0], "cache")) {
			pmap_dump_cache ();
		} else if (!strcasecmp (args[0], "build")) {
			build_rpc ();
		} else {
			printf ("unknown command: %s\n", args[0]);
		}
	}
	return (0);
}

static void
help_command (void)
{
	printf ("help\t\t\t- get help\n" 
		"dump <hostname>\t\t- gets the portmapper listing\n"
		"build\t\t\t- build your own rpc packet (tm)\n"  
		"\t\t\t  note you need to dump a host before building\n" \
		"cache\t\t\t- prints the last portmapper listing\n");
	return;
}
