/* written by some clever unnamed person
 * lots of fixes and changes by someone else
 */


#include <elf.h>
#include "lookup.h"

#ifdef TESTING
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "lookup-example/shared-library.h"
#else
#include "common.c"
#endif


struct link_map {
	Elf32_Addr		l_addr;
	char *			l_name;
	Elf32_Dyn *		l_ld;		/* .dynamic ptr */
	struct link_map	*	l_next;
	struct link_map	*	l_prev;
};


struct sym_helper {
	Elf32_Dyn *	dynsymtab;	/* DT_SYMTAB symbol table */
	Elf32_Dyn *	dynstrtab;	/* DT_STRTAB string table */
	Elf32_Word *	dynhash;	/* DT_HASH hashtable */
};


static int strstr (unsigned char *s1_hay, unsigned char *s2_needle);
static int strmatch (char *s1, char *s2);
static struct link_map * locate_link_map (void *mybase);
static inline unsigned long elf_hash (const char *name);

static Elf32_Dyn * dynamic_address (void *mybase);
static Elf32_Dyn * dynamic_findtype (Elf32_Dyn *dyntab,
	Elf32_Sword dttype);
static int symbol_helpstruct (void *mybase, Elf32_Dyn *dyno,
	struct sym_helper *shlp);

static Elf32_Sym * symtab_findfunc (Elf32_Sym *symstart, char *name,
	char *strtab, Elf32_Word *hash);


/* naive, but small
 */
static int
strstr (unsigned char *s1_hay, unsigned char *s2_needle)
{
	unsigned char *	s1wh;
	unsigned char *	s2wn;

	while (*s1_hay != 0) {
		s1wh = s1_hay++;
		s2wn = s2_needle;

		while (*s1wh++ == *s2wn++) {
			if (*s2wn == 0)
				return (0);	/* found */
		}
	}

	return (1);	/* not found */
}


static int
strmatch (char *s1, char *s2)
{
	while (*s1++ == *s2++)
		if (*s1 == 0 && *s2 == 0)
			return (0);

	return (1);
}


static struct link_map *
locate_link_map (void *mybase)
{
	Elf32_Word *		got = NULL;
	Elf32_Dyn *		dyn;
	struct link_map *	lm;


	dyn = dynamic_address (mybase);
	dyn = dynamic_findtype (dyn, DT_PLTGOT);
	if (dyn == NULL)
		return (NULL);

	got = (Elf32_Word *) dyn->d_un.d_ptr;

	/* platform dependant */
#define GOT_LM_PTR	1
	lm = (struct link_map *) got[GOT_LM_PTR];
	while (lm != NULL && lm->l_prev != NULL)
		lm = lm->l_prev;

	return (lm);
}


static Elf32_Dyn *
dynamic_address (void *mybase)
{
	Elf32_Ehdr *	e = (Elf32_Ehdr *) mybase;
	int		phw;
	Elf32_Phdr *	ph;


	ph = (Elf32_Phdr *) ((char *) e + e->e_phoff);

	for (phw = 0 ; phw < e->e_phnum ; ++phw) {
		if (ph[phw].p_type == PT_DYNAMIC)
			return ((Elf32_Dyn *) ph[phw].p_vaddr);
	}

	return (NULL);
}


static Elf32_Dyn *
dynamic_findtype (Elf32_Dyn *dyntab, Elf32_Sword dttype)
{
	for ( ; dyntab->d_tag != DT_NULL ; ++dyntab) {
		if (dyntab->d_tag == dttype) {
			return (dyntab);

			break;
		}
	}

	return (NULL);
}


static Elf32_Sym *
symtab_findfunc (Elf32_Sym *sym, char *name, char *strtab,
	Elf32_Word *hash)
{
	unsigned long	tidx;	/* table index */
	Elf32_Word *	chain = &hash[2 + hash[0]];


	for (tidx = hash[2 + (elf_hash (name) % hash[0])] ;
		tidx != STN_UNDEF ; tidx = chain[tidx])
	{
		if (ELF32_ST_TYPE (sym[tidx].st_info) != STT_FUNC)
			continue;

		if (strmatch (&strtab[sym[tidx].st_name], name) == 0)
			return (&sym[tidx]);
	}

	return (NULL);
}



static inline unsigned long
elf_hash (const char *name)
{
	unsigned long	h = 0,
			g;


	while (*name) {
		h = (h << 4) + *name++;

		if ((g = h & 0xf0000000))
			h ^= g >> 24;
		h &= ~g;
	}

	return (h);
}


static int
symbol_helpstruct (void *mybase, Elf32_Dyn *dyno, struct sym_helper *shlp)
{
	Elf32_Dyn *		dyn;


	shlp->dynsymtab = shlp->dynstrtab =
		(void *) shlp->dynhash = (void *) NULL;

	if (dyno != NULL)
		dyn = dyno;
	else
		dyn = dynamic_address (mybase);

	if (dyn == NULL)
		return (1);

	shlp->dynsymtab = dynamic_findtype (dyn, DT_SYMTAB);
	shlp->dynstrtab = dynamic_findtype (dyn, DT_STRTAB);
	dyn = dynamic_findtype (dyn, DT_HASH);
	if (dyn != NULL)
		shlp->dynhash = (Elf32_Word *) dyn->d_un.d_ptr;

	if (shlp->dynsymtab == NULL || shlp->dynstrtab == NULL ||
		shlp->dynhash == NULL)
	{
		return (1);
	}

	return (0);
}


/* public functions
 */

int
lib_ismapped (void *mybase, char *str)
{
	struct link_map *	lm;


	for (lm = locate_link_map (mybase) ; lm != NULL ; lm = lm->l_next) {
		if (strstr (lm->l_name, str) == 0)
			return (1);
	}
	
	return (0);
}


void *
symbol_resolve (void *mybase, char *sym_name)
{
	struct sym_helper	shlp;
	struct link_map	*	lm;
	Elf32_Sym *		psym;
	Elf32_Dyn *		dwalk;


	lm = locate_link_map (mybase);
	if (lm == NULL)
		return (NULL);

	/* scan link maps for the symbol
	 */
	for ( ; lm->l_next != NULL ; lm = lm->l_next) {

		/* compile necessary info for this link map
		 */
		for (dwalk = lm->l_ld ; dwalk->d_tag != DT_NULL ; ++dwalk) {
			switch (dwalk->d_tag) {
			case (DT_HASH):
				shlp.dynhash = (Elf32_Word *)
					(((char *) dwalk->d_un.d_ptr) +
					lm->l_addr);
				break;
			case (DT_STRTAB):
				shlp.dynstrtab = dwalk;
				break;
			case (DT_SYMTAB):
				shlp.dynsymtab = dwalk;
				break;
			default:
				break;
			}
		}

		psym = symtab_findfunc ((Elf32_Sym *) shlp.dynsymtab->d_un.d_ptr,
			sym_name, (char *) shlp.dynstrtab->d_un.d_ptr,
			shlp.dynhash);

		if (psym != NULL)
			return (((char *) lm->l_addr) + psym->st_value);
	}

	return (NULL);
}


int
got_funcloc_array (void *mybase, char *name, Elf32_Word *darr[], int darr_len,
	char *substr)
{
	int			darr_cur = 0;
	struct link_map *	lm;


	lm = locate_link_map (mybase);

	while (darr_cur < darr_len) {
		/* no more link maps to process
		 */
		if (lm == NULL)
			return (darr_cur);

#ifdef TESTING_DEBUG
		printf ("%s @ 0x%08x\n", lm->l_name, (unsigned int) lm->l_ld);
#endif
		if (substr == NULL || strstr (lm->l_name, substr) == 0) {
			darr[darr_cur] = got_funcloc_dyn (lm->l_ld, lm->l_addr,
				name);

			if (darr[darr_cur] != NULL)
				darr_cur += 1;	/* good god, got a GOT entry */
		}

		/* next linkmap
		 */
		lm = lm->l_next;
	}

	return (darr_cur);
}


Elf32_Word *
got_funcloc (void *mybase, char *name)
{
	Elf32_Dyn *	dyn = dynamic_address (mybase);

	return (got_funcloc_dyn (dyn, 0, name));
}


Elf32_Word *
got_funcloc_dyn (Elf32_Dyn *dyno, Elf32_Addr loadbase, char *name)
{
	struct sym_helper	shlp;
	Elf32_Dyn *		pltrel;
	Elf32_Dyn *		pltrelsz;

	unsigned int		rwk;	/* relocation walker */
	Elf32_Rel *		relw;
	Elf32_Sym *		rsym;


	if (symbol_helpstruct (NULL, dyno, &shlp))
		return (NULL);
	shlp.dynhash = (Elf32_Word *) (((char *) shlp.dynhash) +
		loadbase);

	pltrel = dynamic_findtype (dyno, DT_JMPREL);
	pltrelsz = dynamic_findtype (dyno, DT_PLTRELSZ);
	if (pltrel == NULL || pltrelsz == NULL)
		return (NULL);

	/* walk all relocation entries for the .plt
	 */
	relw = (Elf32_Rel *) pltrel->d_un.d_ptr;
	for (rwk = pltrelsz->d_un.d_val / sizeof (Elf32_Rel) ;
		rwk > 0 ; --rwk, relw += 1)
	{
		if (ELF32_R_TYPE (relw->r_info) != R_386_JMP_SLOT)
			continue;

		if (ELF32_R_SYM (relw->r_info) == STN_UNDEF)
			continue;

		rsym = (Elf32_Sym *) shlp.dynsymtab->d_un.d_ptr;
		rsym = &rsym[ELF32_R_SYM (relw->r_info)];

		if (strmatch (name,
			&(((char *) shlp.dynstrtab->d_un.d_ptr)[rsym->st_name])) == 0)
		{
			/* rsym->st_value:
			 *   == 0:
			 *        got = loadbase + relw->r_offset
			 *   != 0:
			 *        func_entry = loadbase + rsym->st_value
			 *        got = loadbase + relw->r_offset
			 */
#ifdef TESTING_DEBUG
			printf ("rsym: %s\n", &(((char *)
				shlp.dynstrtab->d_un.d_ptr)[rsym->st_name]));
#endif
			return ((Elf32_Word *) (loadbase + relw->r_offset));
		}

#ifdef TESTING_DEBUG_VERBOSE
		printf ("rsym: %s\n", &(((char *) shlp.dynstrtab->d_un.d_ptr)[rsym->st_name]));
#endif
	}

	return (NULL);
}


#ifdef TESTING
int
my_execve(const char *filename, char *const argv [], char *const envp[])
{
	printf ("execve IS hooked within execve() call\n");

	return (0);
}


void *
my_malloc (unsigned int size)
{
	fprintf (stderr, "my_malloc (%u)\n", size);

	return (NULL);
}



int
main (void)
{
	int	n,
		wk;

	void	* my_addr = (void *) 0x08048000;
	char	* sym_name = "system";
	int	(*systemf)(char *);

	Elf32_Word *	got_printf;
	Elf32_Word *	got_system;
	Elf32_Word *	got_malloc;

	char *		eargv[3] = { "/usr/bin/id", "id", NULL };
	Elf32_Word *	got_execve;
	Elf32_Word *	got_arr[16];


	printf ("ismapped(\"libpcap\") = %d\n", lib_ismapped (my_addr,
		"libpcap"));
	printf ("ismapped(\"libc.so\") = %d\n", lib_ismapped (my_addr,
		"libc.so"));
	printf ("ismapped(\"libpam\") = %d\n", lib_ismapped (my_addr,
		"libpam"));

	systemf = symbol_resolve (my_addr, sym_name);
	if (systemf == NULL)
		_exit (1);

	(*systemf)("uname -a;id;\n");
	system("echo real system;\n");

	printf ("hello\n");

	got_printf = got_funcloc (my_addr, "printf");
	got_system = got_funcloc (my_addr, "system");
	got_execve = got_funcloc (my_addr, "execve");

	/* get execve GOT table locations
	 */
	n = got_funcloc_array (my_addr, "myshareddeepfunc", got_arr, 16, "shared-library");
	printf ("got_funcloc_array (myshareddeepfunc) = %d\n", n);
	for (wk = 0 ; wk < n ; ++wk)
		printf ("  got_arr[%d] = 0x%08x [0x%08x]\n", wk,
			(unsigned int) got_arr[wk],
			*got_arr[wk]);

	got_malloc = got_arr[0];
	*got_malloc = (Elf32_Word) my_malloc;

	mysharedfunc (1911);
#if 0
	/* replace execve, then try to call execve and then system
	 */
	*got_execve = (Elf32_Word) my_execve;
	execve (eargv[0], eargv, NULL);
	system ("echo \"execve NOT hooked within system() call\"");

	/* swap printf and system GOT entries, that is fun!
	 */
	*got_printf ^= *got_system;
	*got_system ^= *got_printf;
	*got_printf ^= *got_system;

	printf ("echo printf called, system executed;id;uname -a;\n");
	system ("system called, printf executed\n");
#endif

	return (0);
}
#endif

