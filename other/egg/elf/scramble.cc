/* program to scramble the contents of the text segment
 * and provide entry points.
 *
 * smiler / teso 
 */

#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <string>
#include <errno.h>
#include <string.h>
#include <elf.h>
#include "elf_help.h"

static int
find_rodata (string filename, Elf32_Shdr *shdr)
{
	ELF	*elf;

	try {
		elf = new ELF (filename, 1);
	} catch (elf_fault fa) {
		fa.print_exit (-1);
	}

	for (int i = 0; i < elf->ehdr_get()->e_shnum; i++) {
		elf->read_shdr (i, shdr);
		if (!strcmp (".rodata", elf->strtab (shdr))) {
			delete elf;
			return (i);
		}
	}
	cerr << "couldn't find .rodata section" << endl;
	delete elf;
	return (-1);
}

void *
memfind (void *buf, size_t len)
{
	int	match = 0;
	char	*ptr = (char *)buf;

	while (ptr < ((char *)buf + len)) {
		if (*ptr == '\x41') {
			match++;
		} else {
			match = 0;
		}
		ptr++;
		if (match == 8)
			return (ptr - 8);
	}
	return (NULL);
}

void
xor_buf (u_char *buf, int len, u_long key, u_long addr, u_long size)
{
	void	*entry;	
	u_long	*ptr;

	entry = memfind (buf, len);

	if (len % 4) len += 4 - (len % 4);
	for (ptr = (u_long *)buf; ptr < (u_long *)(buf + len); *ptr++ ^= key)
			;
	if (entry) {
		ptr = (u_long *)entry;
		*ptr++ = addr;
		*ptr++ = size; 
	}
}

void
xor_bytes (int fd, int offset, int len, u_long addr)
{
	u_long  key = 0xD637A588;
	u_char	buf[4096];
	int	n,
		togo = len;

	lseek (fd, offset, SEEK_SET);

	while (togo > 0) {
		int	toread;

		if ((unsigned)togo < sizeof (buf))
			toread = togo;
		else
			toread = sizeof (buf);

		n = read (fd, buf, toread);
		if (n <= 0)
			break;
		lseek (fd, -n, SEEK_CUR);
		xor_buf (buf, n, key, addr, (u_long)len);
		write (fd, buf, n);
		togo -= n;
	}
}

int
main (int argc, char **argv)
{
	if (argc < 2) {
		cerr << "usage: " << argv[0] << " <file>" << endl;
		exit (-1);
   	}

	string filename (argv[1]);
	Elf32_Shdr shdr;

	if (find_rodata (filename, &shdr) < 0) 
		return (-1);

	cerr << "found .rodata section...." << endl;
	cerr << "opening file" << endl;

	int fd = open (filename.data(), O_RDWR);
	if (fd < 0) {
		cerr << strerror (errno) << endl;
		exit (-1);
	}

	xor_bytes (fd, shdr.sh_offset, shdr.sh_size, (u_long)shdr.sh_addr);

	close (fd);
}
