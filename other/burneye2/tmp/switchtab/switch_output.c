
#include <unistd.h>

int
main (int argc, char *argv[])
{
	int	change;

	switch (argc) {
	case (0):
		change = 0;
		break;
	case (1):
		change = 7;
		break;
	case (3):
		change = 12;
		break;
	case (4):
		change = 49;
		break;
	case (5):
		change = 18;
		break;
	case (6):
		change = 4;
		break;
	case (7):
		change = 13;
		break;
	default:
		change = 0;
		break;
	}

	printf ("change: %d\n", change);

	return (change);
}


