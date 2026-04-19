/* format string test program
 * by team teso
 *
 */


#define	VERSION	"0.0.1"


#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <string.h>


void	test_has_n (void);
void	test_has_star (void);
void	test_has_nstar (void);
void	test_has_star_ow (void);
void	test_has_dollar (void);
void	test_has_float (void);
void	test_has_dot_float (void);
void	test_size_snprintf (void);
void	test_size_snprintf_NUL (void);
void	test_size_non_write_count (void);

typedef struct {
	char *	test_name;
	char *	description;
	void	(* func)(void);
} testent;

testent	tests[] = {
	{ "has_n", "determines whether %n is possible", test_has_n },
	{ "has_star", "determines whether stars within integer prints "
		"are possible", test_has_star },
	{ "has_nstar", "determines whether multiple stars can be used at "
		"once", test_has_nstar },
	{ "has_star_ow", "determines whether this implementation allows "
		"to overwrite\n                       the size specified "
		"with a star directive later on", test_has_star_ow },
	{ "has_dollar", "determines whether this implementation allows "
		"the $-sign\n                       to specify the length "
		"parameter", test_has_dollar },
	{ "has_float", "determines whether %f is possible", test_has_float },
	{ "has_dot_float", "determines whether %.f is possible",
		test_has_dot_float },
	{ "size_snprintf", "the size in bytes that %n writes",
		test_size_snprintf },
	{ "size_non_write_counts", "a large write, which exceeds the buffer "
		"size counts to the\n                       written counter "
		"anyway", test_size_non_write_count },
	{ NULL, NULL, NULL },
};


char	buffer[1024];	/* for tests to use and populate freely */


void
test_has_n (void)
{
	int	i = 0;

	sprintf (buffer, "aaa%n", &i);
	printf ("has_n %s\n", i == 3 ? "yes" : "no");
}


void
test_has_star (void)
{
	sprintf (buffer, "%*d", 30, 7350);
	printf ("has_star %s\n", strlen (buffer) == 30 ? "yes" : "no");
}


void
test_has_nstar (void)
{
	sprintf (buffer, "%**d", 50, 30, 7350);
	printf ("has_nstar %s\n", strlen (buffer) == 30 ? "yes" : "no");
}


void
test_has_star_ow (void)
{
	sprintf (buffer, "%*10d", 30, 1);
	printf ("has_star_ow %s\n", strlen (buffer) == 10 ? "yes" : "no");
}


void
test_has_dollar (void)
{
	sprintf (buffer, "%2$d", 1, 30);
	printf ("has_dollar %s\n", strcmp (buffer, "30") == 0 ? "yes" : "no");
}


void
test_has_float (void)
{
	float	f = 3.14;

	sprintf (buffer, "%f", f);
	printf ("has_float %s\n", memcmp (buffer, "3.14", 4) == 0 ? "yes" : "no");
}


void
test_has_dot_float (void)
{
	float	f = 3.14;

	sprintf (buffer, "%.f", f);
	printf ("has_dot_float %s\n", strcmp (buffer, "3") == 0 ? "yes" : "no");
}


void
test_size_snprintf (void)
{
	char	buf[5];

	memset (buf, '\x00', sizeof (buf));
	buf[4] = 'a';
	snprintf (buf, sizeof (buf) - 1, "abcd");

	if (buf[3] == 'd' && buf[4] == 'a') {
		printf ("size_snprintf weak_adjascent\n");
	} else if (buf[3] == 'd' && buf[4] == '\x00') {
		printf ("size_snprintf weak_NUL_store\n");
	} else if (buf[2] == 'c' && buf[3] == '\x00') {
		printf ("size_snprintf ok\n");
	}
}


void
test_size_non_write_count (void)
{
	int	i = 0;
	char	buf[256];	/* work around a bug in libc here */

	snprintf (buf, sizeof (buf), "%500d%n", 10, &i);
	printf ("size_non_write_count %s\n", i > 256 ? "exceeds" : "remains");
}




int
main (int argc, char *argv[])
{
	int	i;

	if (argc != 2) {
		printf ("format string test program version "VERSION"\n"
			"by team teso\n\n");

		printf ("usage: %s <test_name>\n\n", argv[0]);

		for (i = 0 ; tests[i].test_name != NULL ; ++i) {
			printf ("%-22s %s\n", tests[i].test_name,
				tests[i].description);
		}

		exit (EXIT_SUCCESS);
	}

	memset (buffer, '\x00', sizeof (buffer));

	for (i = 0 ; tests[i].test_name != NULL ; ++i) {
		if (strcmp (tests[i].test_name, argv[1]) == 0)
			tests[i].func ();
	}

	exit (EXIT_SUCCESS);

}


