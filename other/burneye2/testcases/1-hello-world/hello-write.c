
#include <unistd.h>
#include <string.h>

void output_num (char *str, int num);


int
main (int argc, char *argv[])
{
	int	n;


	for (n = 0 ; n < 5 ; ++n)
		output_num ("hello: ", n);
}


void
output_num (char *str, int num)
{
	char	numstr[12];
	int	nstrp;


	write (1, str, strlen (str));

	numstr[11] = '\0';
	nstrp = 10;
	if (num == 0)
		numstr[nstrp--] = '0';

	for ( ; num != 0 && nstrp >= 0 ; --nstrp) {
		numstr[nstrp] = num % 10 + '0';
		num = num / 10;
	}
	write (1, &numstr[nstrp] + 1, 10 - nstrp);

	write (1, "\n", 1);
}


