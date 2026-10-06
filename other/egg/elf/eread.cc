#include <iostream.h>
#include "elf_help.h"

int
main (int argc, char **argv)
{
	Elf32_Ehdr	*ehdr = NULL;
	Elf32_Shdr	shdr;
	Elf32_Phdr	phdr;
	ELF	*elf = NULL;

	cout << "eread 0.1 by smiler / teso" << endl;

	if (argc < 2) {
		fprintf (stderr, "usage: %s <file>\n", argv[0]);
		exit (-1);
	}

	try {
		elf = new ELF (argv[1], 1);
	} catch (elf_fault ef) {
		delete elf;
		ef.print_exit (-1);
	}

	ehdr = elf->ehdr_get ();

	cout	<< "e_class " << elf->eclass () << endl
		<< "e_data " << elf->data () << endl
		<< "e_type " << elf->type () << endl
		<< "e_machine " << elf->machine () << endl
		<< "e_version " << elf->version () << endl
		<< "e_shoff " << hex << ehdr->e_shoff << endl;
	if (ehdr->e_phoff)
		cout << "e_phoff: " << hex << ehdr->e_phoff << endl;
	if (ehdr->e_entry)
		cout << "e_entry: " << hex << ehdr->e_entry << endl;

	cout << endl;

	for (int i = 0; i < ehdr->e_shnum; i++) {
		try {
			elf->read_shdr (i, &shdr);
		} catch (elf_fault ef) {
			ef.print_exit (-1);
			break;
		}

		// print out all useful information in the section hdr 
		cout	<< "Section " << i << endl
			<< "sh_name: " << elf->strtab (&shdr) << endl
			<< "sh_type: " << elf->s_type (&shdr) << endl
			<< "sh_offset: " << hex << shdr.sh_offset << endl;
		if (shdr.sh_addr)
			cout << "sh_addr: " << hex << shdr.sh_addr << endl;
		cout	<< "sh_size: " << hex << shdr.sh_size << endl;
		if (shdr.sh_link != SHN_UNDEF)
			cout << "sh_link: " << shdr.sh_link << endl;
		cout	<< "sh_flags: " << shdr.sh_flags << endl << endl;

	}

	cout << endl;
	
	for (int i = 0; i < ehdr->e_phnum; i++) {
		try {
			elf->read_phdr (i, &phdr); 
		} catch (elf_fault ef) {
			delete elf;
			ef.print_exit (-1);
		}
		cout	<< "Process Header " << i << endl
			<< "p_type: " << elf->p_type (&phdr) << endl
			<< "p_offset: " << hex << phdr.p_offset << endl
			<< "p_filesz: " << hex << phdr.p_filesz << endl
			<< "p_memsz: " << hex << phdr.p_memsz << endl;
		if (phdr.p_vaddr)
			cout	<< "p_vaddr: " << hex << phdr.p_vaddr << endl;
		cout << endl;
	}
	delete elf;
}
