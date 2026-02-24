
#include <stdio.h>
#include <string.h>


int cow (char *in);

int
main (int argc, char *argv[])
{
	if (argc >= 2)
		cow (argv[1]);
}

int
cow (char *in)
{
	char	buf[512];

	strcpy (buf, in);
	buf[516] = '\x20';
	buf[517] = '\xab';
	buf[518] = '\x00';
	buf[519] = '\x40';
}


