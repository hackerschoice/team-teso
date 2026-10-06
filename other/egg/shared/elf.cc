#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "elf_help.h"

ELF::ELF (char *str, int map)
{
	map_base = NULL;

	filename = new string (str);

	fd = open (filename->data(), O_RDONLY);
	if (fd < 0)
		throw elf_fault ();

	if (read (fd, &ehdr, sizeof (ehdr)) < (signed)sizeof (ehdr)) {
		close_fd (); 
		throw elf_fault ();
	}
	if (map)
		map_shared ();
}

ELF::ELF (string str, int map)
{
	map_base = NULL;

	filename = new string (str);

	fd = open (filename->data(), O_RDONLY);
	if (fd < 0)
		throw elf_fault();

	if (read (fd, &ehdr, sizeof (ehdr)) < (signed)sizeof (ehdr)) {
		close_fd ();
		throw elf_fault();
	}
	if (map)
		map_shared ();
}

ELF::ELF (int filed, int map)
{
	map_base = NULL;

	filename = NULL;

	fd = filed;	

	if (read (fd, &ehdr, sizeof (ehdr)) < (signed)sizeof (ehdr)) {
		close_fd ();
		throw elf_fault();
	}

	if (map)
		map_shared();
}

ELF::~ELF (void)
{
	if (filename)
		delete filename;

	if (fd != -1)
		close (fd);

	if (this->map_base)
		munmap (this->map_base, this->map_len);
}

int
ELF::read_phdr (int ref, Elf32_Phdr *phdr)
{
	if (this->fd == -1)
		return (-1);

	if ((ehdr.e_phnum == 0) || (ref < 0) || (ref > ehdr.e_phnum))
		throw elf_fault ("out of range");

	if (lseek (this->fd, ehdr.e_phoff + ref*ehdr.e_phentsize, SEEK_SET)<0)
		throw elf_fault ();

	if (read (this->fd, phdr, sizeof (Elf32_Phdr)) < 0)
		throw elf_fault ();

	return (0);
}

int 
ELF::read_shdr (int ref, Elf32_Shdr *shdr)
{
	if (this->fd == -1)
		return (-1);

	if ((ehdr.e_shnum == 0) || (ref < 0) || (ref > ehdr.e_shnum))
		throw elf_fault ("out of range");

	if (lseek (this->fd, ehdr.e_shoff + ref*ehdr.e_shentsize, SEEK_SET) < 0)
		throw elf_fault ();

	if (read (this->fd, shdr, sizeof (Elf32_Shdr)) < 0)
		throw elf_fault ();

	return (0);
}

char *
ELF::strtab (Elf32_Word offset)
{
	if (this->map_base == NULL)
		throw elf_fault ("non-mmap strings not implemented");

	return (this->str_tab + offset);
}

void
ELF::close_fd (void)
{
	if (fd != -1) {
		close (fd);
		fd = -1;
	}
}

/* this will mmap () the string table in the elf file to memory
 * so its somewhat easier to use...
 */

void
ELF::map_shared (void)
{
	off_t	off;
	size_t	pgsize = getpagesize ();
	Elf32_Shdr shdr;
	Elf32_Off blah;

	if (ehdr.e_shstrndx == SHN_UNDEF)
		throw elf_fault ("no string table");

	off = ehdr.e_shoff + ehdr.e_shstrndx * ehdr.e_shentsize;
	if (lseek (fd, off, SEEK_SET) < 0)
		throw elf_fault ();

	if (read (fd, &shdr, sizeof (shdr)) < 0)
		throw elf_fault ();

	blah = shdr.sh_offset - (shdr.sh_offset % pgsize);
	shdr.sh_size += shdr.sh_offset - blah;

	this->map_len = shdr.sh_size + shdr.sh_offset - blah;
	this->map_base = mmap (NULL, this->map_len, PROT_READ, MAP_PRIVATE,
		this->fd, blah);
	if (this->map_base == MAP_FAILED)
		throw elf_fault ("mmap failed");

	this->str_tab = (char *)this->map_base + shdr.sh_offset - blah;

	return ;
}
