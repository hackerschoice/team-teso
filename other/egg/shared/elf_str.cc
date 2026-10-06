#include <stdio.h>
#include "elf_str.h"

elf_str::elf_str()
{
}

elf_str::~elf_str()
{
}

static char	*etype_array[]=
	{
	"ET_NONE",
	"ET_RELOCATABLE",
	"ET_EXECUTABLE",
	"ET_DYNAMIC",
	"ET_CORE"
	};

char *
elf_str::type (Elf32_Half type)
{
	if (type >= ET_NUM)
		return (NULL);
	return (etype_array[type]);
}

static char	*emachine_array[]=
	{
	"EM_NONE",
	"EM_M32",
	"EM_SPARC",
	"EM_386",
	"EM_68K",
	"EM_88K",
	"EM_486",
	"EM_860",
	"EM_MIPS",
	"EM_S370",
	"EM_MIPS_RS4_BE",
	"EM_RS6000"
	};

#undef EM_NUM
#define EM_NUM 12

char *
elf_str::machine (Elf32_Half machine)
{
	if (machine >= EM_NUM)
		return (NULL);
	return (emachine_array[machine]);
} 

static char	*eversion_array[]=
	{
	"EV_NONE",
	"EV_CURRENT"
	};

char *
elf_str::version (Elf32_Half version)
{
	if (version >= EV_NUM)
		return (NULL);

	return (eversion_array[version]);
}

static char	*eiclass_array[]=
	{
	"NONE",
	"32",
	"64"
	};

char *
elf_str::eclass (char _class)
{
	if ((unsigned char)_class >= ELFCLASSNUM)
		return (NULL);

	return (eiclass_array[(unsigned int)_class]);
}

static char	*eidata_array[]=
	{
	"NONE",
	"Little Endian",
	"Big Endian",
	};

char *
elf_str::data (char data)
{
	if ((unsigned char)data >= ELFDATANUM)
		return (NULL);

	return (eidata_array[(unsigned int)data]);
}

static char	*stype_array[]=
	{
	"SHT_NULL",
	"SHT_PROGBITS",
	"SHT_SYMTAB",
	"SHT_STRTAB",
	"SHT_RELA",
	"SHT_HASH",
	"SHT_DYNAMIC",
	"SHT_NOTE",
	"SHT_NOBITS",
	"SHT_REL",
	"SHT_SHLIB",
	"SHT_DYNSYM"
	};

char *
elf_str::s_type (Elf32_Word type)
{
	if (type == SHT_GNU_versym)
		return ("SHT_GNU_versym");
	if (type == SHT_GNU_verneed)
		return ("SHT_GNU_verneed");

	if (type >= 12)
		return (NULL);

	return (stype_array[type]);
}

static char *	ptype_array[]=
	{
	"PT_NULL",
	"PT_LOAD",
	"PT_DYNAMIC",
	"PT_INTERP",
	"PT_NOTE",
	"PT_SHLIB",
	"PT_PHDR"
	};

char *
elf_str::p_type (Elf32_Word type)
{
	if (type >= PT_NUM)
		return (NULL);

	return (ptype_array[type]);
}
