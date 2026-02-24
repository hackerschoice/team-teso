/*

	A tool for the young exploit coder,  Copyright (c) acpizer, 2001.

*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>


char small_global[] = "acpizer";

int uninitialized_global;


int endianess() {
	union {
		long l;
		char c[sizeof (long)];
	} u;

	u.l = 1;

	return (u.c[sizeof (long) - 1] == 1);
}


static int iterate = 10;

int stack_growsdown(int *x) {
	auto int y;


	y = (x > &y);

	if (--iterate > 0)
		y = stack_growsdown(&y);

	if (y != (x > &y))
		exit(1);

	return y;
}

typedef struct {
	char *	sys_name;
	char *	sys_release;
	char *	sys_version;
	char *	sys_machine;

	unsigned long int	malloc_zero;
	unsigned long int	malloc_neg;
	unsigned long int	malloc_big;

	unsigned long int	malloc_small;
	unsigned long int	malloc_tiny;

	unsigned long int	bss;
	unsigned long int	data;

	int			sizeof_int;
	int			sizeof_voidptr;

	unsigned long int	env_start;

	unsigned long int	frame_addr;

	int			stack_down;
	int			endian_big;
} sys_def;

sys_def	this;


int
main (int argc, char *argv[], char *env[])
{
	struct utsname	uts;

	char		localstack[5];
	auto int	x;


	printf("splocoder, v1.0 by acpizer & sc -- team teso.\n\n");

	uname (&uts);

	this.sys_name = uts.sysname;
	this.sys_release = uts.release;
	this.sys_version = uts.version;
	this.sys_machine = uts.machine;

#ifdef VERBOSE
	printf("System: %s %s %s %s\n\n", uts.sysname, uts.release, uts.version,
		uts.machine);
#endif

	this.malloc_zero = (unsigned long int) malloc (0);
	this.malloc_neg = (unsigned long int) malloc (-4);
	this.malloc_big = (unsigned long int) malloc (1024 * 1024);

#ifdef VERBOSE
	printf("malloc(0) returns: 0x%08lx\n", this.malloc_zero);
	printf("malloc(-4) returns: 0x%08lx\n", this.malloc_neg);
	printf("Big heap: 0x%08lx\n", this.malloc_big);
#endif

	/* There might be a differece, depending on malloc implementation. */
	this.malloc_small = (unsigned long int) malloc (100);
	this.malloc_tiny = (unsigned long int) malloc (5);

#ifdef VERBOSE
	printf("Small heap: 0x%08lx\n", this.malloc_small);
	printf("Tiny heap: 0x%08lx\n\n", this.malloc_tiny);
#endif


	this.bss = (unsigned long int) &uninitialized_global;
	this.data = (unsigned long int) &small_global;

#ifdef VERBOSE
	printf("bss is at: 0x%08lx\n", this.bss);
	printf("Initialized global data is at: 0x%08lx\n\n", this.data);
#endif


	this.sizeof_int = sizeof (int);
	this.sizeof_voidptr = sizeof (void *);

#ifdef VERBOSE
	printf("sizeof(int): %d\n", this.sizeof_int);
	printf("sizeof(void *): %d\n\n", this.sizeof_voidptr);
#endif


	this.env_start = (unsigned long int) &env[0];
#ifdef VERBOSE
	printf("environ[0]: 0x%08lx\n\n", this.env_start);
#endif

	this.frame_addr = (unsigned long int) &localstack;
#ifdef VERBOSE
	printf("Local stack variable is at 0x%08lx\n", this.frame_addr);
#endif

	this.stack_down = stack_growsdown (&x) ? 1 : 0;
#ifdef VERBOSE
	printf("Stack growth direction: %s\n", this.stack_down ? "down" : "up");
#endif

	this.endian_big = endianess () ? 1 : 0;
#ifdef VERBOSE
	printf("Endianess: %s\n\n", this.endian_big ? "big" : "little");
#endif


	{
		char	sys[30];

		snprintf (sys, sizeof (sys), "%s-%s-%s", this.sys_name,
			this.sys_release, this.sys_machine);
		fprintf (stderr, "%-32s ", sys);
	}
	fprintf (stderr, "%s %-10s ", this.endian_big ? "be" : "le",
		this.stack_down ? "stackdown" : "stackup");
	fprintf (stderr, "%3d %3d\n",
		this.sizeof_int, this.sizeof_voidptr);

	fprintf (stderr, "%-33s%08lx %08lx %08lx %08lx",
		"      data bss stack env",
		this.data, this.bss,
		this.frame_addr, this.env_start);
	fprintf (stderr, "\n");

	fprintf (stderr, "%-33s%08lx %08lx %08lx %08lx %08lx ",
		"   M: zero neg big small tiny",
		this.malloc_zero, this.malloc_neg, this.malloc_big,
		this.malloc_small, this.malloc_tiny);
	fprintf (stderr, "\n");

	exit (EXIT_SUCCESS);
}

