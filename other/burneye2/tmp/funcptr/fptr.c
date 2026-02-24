
int m2 (int a);

typedef	int (* fptr)(int);


int
main (int argc, char *argv[])
{
	fptr	subfunc;


	subfunc = m2;
	return (subfunc (argc));
}


int
m2 (int a)
{
	return (a << 1);
}


