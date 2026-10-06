#ifndef ELF_STR_H
#define ELF_STR_H
#include <elf.h>

class elf_str {
public:
	elf_str ();
	virtual ~elf_str ();

	char	*type (Elf32_Half);
	char	*machine (Elf32_Half);
	char	*version (Elf32_Half);
	char	*eclass (char);
	char	*data (char);

	char	*type (Elf32_Ehdr *ehdr) {
		return (type ((Elf32_Half)ehdr->e_type));
	}
	char	*machine (Elf32_Ehdr *ehdr) {
		return (machine ((Elf32_Half)ehdr->e_machine));
	}
	char	*version (Elf32_Ehdr *ehdr) {
		return (version ((Elf32_Half)ehdr->e_version));
	}
	char	*eclass (Elf32_Ehdr *ehdr) {
		return (eclass (ehdr->e_ident[EI_CLASS]));
	}
	char	*data (Elf32_Ehdr *ehdr) {
		return (data (ehdr->e_ident[EI_DATA]));
	}

	char	*s_type (Elf32_Word);
	char	*s_type (Elf32_Shdr *shdr) {
		return (s_type ((Elf32_Word)shdr->sh_type));
	}

	char	*p_type (Elf32_Word);
	char	*p_type (Elf32_Phdr *phdr) {
		return (p_type ((Elf32_Word)phdr->p_type));
	}
};

#endif /* ELF_STR_H */
