
int
_start (void)
{
	int	a;

	a = 6;
	a = fac (a);
	a = fac2 (6);

	return (a);
}


int
fac (int n)
{
	if (n <= 1)
		return (1);
	else
		return (n * fac (n - 1));
}


int
fac2 (int n)
{
	unsigned int	a = n;

	while (n > 1)
		a *= --n;
}



