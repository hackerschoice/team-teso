/* zodiac spoof proxy
 *
 * by team teso
 *
 * test program
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "../io-udp.h"
#include "../network.h"


int
main (int argc, char **argv)
{
	unsigned char	*data =
		"\xe7\x30\xbb\x0b\xda\x73\xdf\x98\xf6\x38\xac\x9f\xa3\xcc\xc0\x8f"
		"dabadiduthisisatestforthezodiacspoofproxywhichisalmightyyoushouldknow:-)";

	udp_send (NULL, 0, "127.0.0.1", 17852, "foobar", data, strlen (data));

	exit (EXIT_SUCCESS);
}


