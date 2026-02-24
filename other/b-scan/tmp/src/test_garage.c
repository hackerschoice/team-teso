/* test_garage.c - test program for the garage module
 *
 * by scut / teso
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <garage.h>


void
cleaner_t (ip_list *il);

int
main (int argc, char *argv[])
{
	int			data_len;
	unsigned char *		data;
	unsigned long int	ip,
				gip = 0;
	unsigned long int	ips;
	garage_hdlr *		hdl;
	unsigned long int	maxkeep;

	printf ("mg_cidr_getmask (20) = 0x%08lx\n", mg_cidr_getmask (20));
	printf ("mg_cidr_getmask (0xffffffc0) = 0x%08lx\n", mg_cidr_getmask (0xffffffc0));

	if (argc < 2 || sscanf (argv[1], "%lu", &ips) != 1) {
		printf ("usage: %s <number-of-ips> [maxkeep]\n\n", argv[0]);

		exit (EXIT_FAILURE);
	}
	if (argc == 3 && sscanf (argv[2], "%lu", &maxkeep) != 1)
		exit (EXIT_FAILURE);

	srand (time (NULL));
	hdl = mg_init ("footest", maxkeep, cleaner_t);

	printf ("mg_cidr_getmask (0) = 0x%08lx\n", mg_cidr_getmask (0));

	mg_write (hdl, 2048, "foobar", 7, 0);
	mg_write (hdl, 2050, "foobar", 7, 0);
	mg_write (hdl, 101911, "foobar", 7, 0);
	mg_write (hdl, 28914191, "foobar", 7, 0);
	printf ("mg_cidr_count (hdl, 2048, 32) = %lu\n", mg_cidr_count (hdl, 2048, 32));
	printf ("mg_cidr_count (hdl, 2048, 31) = %lu\n", mg_cidr_count (hdl, 2048, 31));
	printf ("mg_cidr_count (hdl, 2048, 30) = %lu\n", mg_cidr_count (hdl, 2048, 30));
	printf ("mg_cidr_count (hdl, 2048, 13) = %lu\n", mg_cidr_count (hdl, 2048, 13));
	printf ("mg_cidr_count (hdl, 2048,  0) = %lu\n", mg_cidr_count (hdl, 2048, 0));


	ip = 123;
	mg_write (hdl, ip, "foo", 4, 0);
	mg_read (hdl, ip);
	mg_clean (hdl, ip, NULL);

	do {
		ip = rand ();

		data_len = rand () % 64;
		data_len += 1;	/* avoid allocating zero bytes */
		data = malloc (data_len);
		memset (data, '\x73', data_len);
		data[data_len - 1] = '\0';

		mg_write (hdl, ip, (void *) data, data_len, 1);
		if (ips % 137 == 0)
			gip = ip;

		if (ips % 139 == 0)
			(void) mg_read (hdl, gip);

		ips -= 1;
		if (ips % 5000 == 0)
			mg_show (hdl);

	} while (ips > 0);

	mg_show (hdl);
	mg_destroy (hdl, 0);

	exit (EXIT_SUCCESS);
}


void
cleaner_t (ip_list *il)
{
	if ((rand () % 20000) == 0)
		printf ("cleaner_t: il = 0x%08lx  IP = 0x%08lx\n",
			(unsigned long int) il,
			il->ip);

	return;
}


