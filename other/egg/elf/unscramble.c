/* procedures to unscramble the text segment of the running process
 * only works in a linux environment at the moment
 *
 * smiler / teso
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>

/* these should go into the data segment */
char	error[] = "scramble error";
char	mask[] = "/proc/self/maps";
char	fmt[] = "%x-%x";
/* this should go in the text segment */
char	*buf = "AAAAAAAA";

void
xor_bytes (u_long addr, u_long size)
{
	u_long *ptr;

	ptr = (u_long *)addr + size/sizeof(u_long);
	while (ptr >= (u_long *)addr) {
		*ptr-- ^= 0xD637A588;
	}
}

int
unscramble (void)
{
	u_long	start,
		end,
		off,
		size;
	char	line[40];
	int	fd,
		n;

	fd = open (mask, O_RDONLY);
	n = read (fd, line, sizeof (line) - 1);
	close (fd);
	line[n] = '\0';

	sscanf (line, fmt, &start, &end);

	mprotect ((void *)start, end - start, PROT_READ|PROT_WRITE|PROT_EXEC);

	off = *(u_long *)buf;
	size = *(u_long *)(buf + 4);
	if (off != 0x41414141)
		xor_bytes (off, size);

	mprotect ((void *)start, end - start, PROT_READ|PROT_EXEC);
	return (0);
}
