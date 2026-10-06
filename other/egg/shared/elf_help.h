#ifndef ELF_HELP_H
#define ELF_HELP_H
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <elf.h>
#include <string>
#include "elf_str.h"

/* isnt there some generic fault class? */
class elf_fault {
private:
	int	err; 
	char	*s;
public:
	elf_fault ();
	elf_fault (int error);
	elf_fault (const char *error);
	~elf_fault ();

	int error () {
		return (err);
	}

	void print (void);
	void print_exit (int exit_code) {
		elf_fault::print ();
		_exit (exit_code);
	}
};

class ELF : public elf_str {
private:
	int	fd;
	string *filename;		
	Elf32_Ehdr	ehdr;	/* elf header */

	/* stuff pertaining to mmap()ed strtable */
	void	*map_base;
	char	*str_tab;
	int	map_len;

public:
	ELF (int, int);
	ELF (string, int);
	ELF (char*, int);
	~ELF ();

	int	filed () {
		return (fd);
	}

	int	read_shdr (int, Elf32_Shdr *);
	int	read_phdr (int, Elf32_Phdr *);

	char *	strtab (Elf32_Word);
	char *	strtab (Elf32_Shdr *shdr) {
		return (strtab (shdr->sh_name));
	}

	Elf32_Ehdr *	ehdr_get () {
		return (&this->ehdr);
	}

	virtual char *	machine () {
		return (elf_str::machine (ehdr.e_machine));
	}
	virtual char *	type () {
		return (elf_str::type (ehdr.e_type));
	}
	virtual char *	version () {
		return (elf_str::version (ehdr.e_version));
	}
	virtual char *	eclass () {
		return (elf_str::eclass (ehdr.e_ident[EI_CLASS]));
	}
	virtual char *	data () {
		return (elf_str::data (ehdr.e_ident[EI_DATA]));
	}	
private:
	void	map_shared (void);
	void	close_fd (void);
};

#endif /* ELF_HELP_H */
