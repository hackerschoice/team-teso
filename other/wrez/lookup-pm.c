/* written by some clever unnamed person
 * lots of fixes and changes by someone else
 */


#include <elf.h>
#include "lookup-pm.h"

#ifdef TESTING
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "lookup-example/shared-library.h"
#else
#include "common.c"
#endif


#define	pfc(a) (pf (a) & 0xff)


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


static int strstr (peekmemfunc pf, unsigned char *s1_hay,
	unsigned char *s2_needle);
static inline int strmatch (peekmemfunc pf, unsigned char *s1,
	unsigned char *s2, int s2_direct);
static inline struct link_map *locate_link_map (peekmemfunc pf, void *mybase);
static inline Elf32_Dyn * dynamic_address (peekmemfunc pf, void *mybase);
static inline Elf32_Dyn * dynamic_findtype (peekmemfunc pf,
	Elf32_Dyn *dyntab, Elf32_Sword dttype);
static inline Elf32_Sym * symtab_findfunc (peekmemfunc pf,
	Elf32_Sym *sym, char *name, char *strtab, Elf32_Word *hash);
static inline unsigned long elf_hash (const char *name);
void * symbol_resolve (peekmemfunc pf, void *mybase, char *sym_name);


static int
strstr (peekmemfunc pf, unsigned char *s1_hay, unsigned char *s2_needle)
{
	unsigned char *	s1wh;
	unsigned char *	s2wn;

	while (pfc (s1_hay) != 0) {
		s1wh = s1_hay++;
		s2wn = s2_needle;

		while (pfc (s1wh++) == *s2wn++) {
			if (*s2wn == 0)
				return (0);	/* found */
		}
	}

	return (1);	/* not found */
}


/* strmatch
 *
 * simple asciiz conform compare of strings at `s1' and `s2'. `pf' is the
 * memory peek function that pulls the bytes from the addresses. `s1' is
 * always chained over `pf', but for `s2' the `s2_direct' parameter controls
 * the desired behavious: when s2_direct is != 0, then s2 is treated as direct
 * pointer into current address space. when s2_direct is zero, it will be
 * looked up just as s1 is.
 *
 * return 0 if strings are equal, including terminating NUL character
 * return != 0 if strings differ
 */

static inline int
strmatch (peekmemfunc pf, unsigned char *s1,
	unsigned char *s2, int s2_direct)
{
	if (s2_direct == 0) {
		while (pfc (s1++) == pfc (s2++))
			if (pfc (s1) == 0 && pfc (s2) == 0)
				return (0);
	} else {
		while (pfc (s1++) == *s2++)
			if (pfc (s1) == 0 && *s2 == 0)
				return (0);
	}

	return (1);
}


static inline struct link_map *
locate_link_map (peekmemfunc pf, void *mybase)
{
	Elf32_Word *		got = NULL;
	Elf32_Dyn *		dyn;
	struct link_map *	lm;


	dyn = dynamic_address (pf, mybase);
	if (dyn == NULL)
		return (NULL);

	dyn = dynamic_findtype (pf, dyn, DT_PLTGOT);
	if (dyn == NULL)
		return (NULL);

	got = (Elf32_Word *) pf (&dyn->d_un.d_ptr);

	/* platform dependant */
#define GOT_LM_PTR	1
	lm = (struct link_map *) pf (&got[GOT_LM_PTR]);
	while (lm != NULL && pf (&lm->l_prev) != 0)
		lm = (struct link_map *) pf (&lm->l_prev);

	return (lm);
}


static inline Elf32_Dyn *
dynamic_address (peekmemfunc pf, void *mybase)
{
	Elf32_Ehdr *	e = (Elf32_Ehdr *) mybase;
	int		phw;
	Elf32_Phdr *	ph;


	ph = (Elf32_Phdr *) ((char *) e + pf (&e->e_phoff));

	for (phw = 0 ; phw < (pf (&e->e_phnum) & 0xffff) ; ++phw) {
		if (pf (&ph[phw].p_type) == PT_DYNAMIC)
			return ((Elf32_Dyn *) pf (&ph[phw].p_vaddr));
	}

	return (NULL);
}


static inline Elf32_Dyn *
dynamic_findtype (peekmemfunc pf, Elf32_Dyn *dyntab, Elf32_Sword dttype)
{
	for ( ; pf (&dyntab->d_tag) != DT_NULL ; ++dyntab) {
		if (pf (&dyntab->d_tag) == dttype) {
			return (dyntab);

			break;
		}
	}

	return (NULL);
}


static inline Elf32_Sym *
symtab_findfunc (peekmemfunc pf, Elf32_Sym *sym, char *name, char *strtab,
	Elf32_Word *hash)
{
	unsigned long	tidx;	/* table index */
	Elf32_Word *	chain = &hash[2 + pf (&hash[0])];


	for (tidx = pf (&hash[2 + (elf_hash (name) % pf (&hash[0]))]) ;
		tidx != STN_UNDEF ; tidx = pf (&chain[tidx]))
	{
		if (ELF32_ST_TYPE (pfc (&sym[tidx].st_info)) != STT_FUNC)
			continue;

		if (strmatch (pf, &strtab[pf (&sym[tidx].st_name)], name, 1) == 0)
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
symbol_helpstruct (peekmemfunc pf, void *mybase, Elf32_Dyn *dyno,
	struct sym_helper *shlp)
{
	Elf32_Dyn *		dyn;


	shlp->dynsymtab = shlp->dynstrtab =
		(void *) shlp->dynhash = (void *) NULL;

	if (dyno != NULL)
		dyn = dyno;
	else
		dyn = dynamic_address (pf, mybase);

	if (dyn == NULL)
		return (1);

	shlp->dynsymtab = dynamic_findtype (pf, dyn, DT_SYMTAB);
	shlp->dynstrtab = dynamic_findtype (pf, dyn, DT_STRTAB);
	dyn = dynamic_findtype (pf, dyn, DT_HASH);
	if (dyn != NULL)
		shlp->dynhash = (Elf32_Word *) (pf (&dyn->d_un.d_ptr));

	if (shlp->dynsymtab == NULL || shlp->dynstrtab == NULL ||
		shlp->dynhash == NULL)
	{
		return (1);
	}

	return (0);
}


int
lib_ismapped (peekmemfunc pf, void *mybase, char *str)
{
	struct link_map *	lm;


	for (lm = locate_link_map (pf, mybase) ; lm != NULL ;
		lm = (struct link_map *) pf (&lm->l_next)) {
		if (strstr (pf, (unsigned char *) pf (&lm->l_name), str) == 0)
			return (1);
	}
	
	return (0);
}


void *
symbol_resolve (peekmemfunc pf, void *mybase, char *sym_name)
{
	struct sym_helper	shlp;
	struct link_map	*	lm;
	Elf32_Sym *		psym;
	Elf32_Dyn *		dwalk;


	lm = locate_link_map (pf, mybase);
	if (lm == NULL)
		return (NULL);

	/* scan link maps for the symbol
	 */
	for ( ; pf (&lm->l_next) != 0 ;
		lm = (struct link_map *) pf (&lm->l_next))
	{
		/* compile necessary info for this link map
		 */
		for (dwalk = (Elf32_Dyn *) pf (&lm->l_ld) ;
			pf (&dwalk->d_tag) != DT_NULL ; ++dwalk)
		{
			switch (pf (&dwalk->d_tag)) {
			case (DT_HASH):
				shlp.dynhash = (Elf32_Word *)
					(((char *) pf (&dwalk->d_un.d_ptr)) +
					pf (&lm->l_addr));
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

		psym = symtab_findfunc (pf,
			(Elf32_Sym *) pf (&shlp.dynsymtab->d_un.d_ptr),
			sym_name, (char *) pf (&shlp.dynstrtab->d_un.d_ptr),
			shlp.dynhash);

		if (psym != NULL)
			return (((char *) pf (&lm->l_addr)) +
				pf (&psym->st_value));
	}

	return (NULL);
}


int
got_funcloc_array (peekmemfunc pf, void *mybase, char *name,
	Elf32_Word *darr[], int darr_len, char *substr)
{
	int			darr_cur = 0;
	struct link_map *	lm;


	lm = locate_link_map (pf, mybase);

	while (darr_cur < darr_len) {
		/* no more link maps to process
		 */
		if (lm == NULL)
			return (darr_cur);

#ifdef TESTING_DEBUG
		printf ("%s @ 0x%08x\n", lm->l_name, (unsigned int) lm->l_ld);
#endif
		if (substr == NULL || strstr (pf,
			(unsigned char *) pf (&lm->l_name), substr) == 0)
		{
			darr[darr_cur] = got_funcloc_dyn (pf,
				(Elf32_Dyn *) pf (&lm->l_ld),
				(Elf32_Addr) pf (&lm->l_addr), name);

			if (darr[darr_cur] != NULL)
				darr_cur += 1;	/* good god, got a GOT entry */
		}

		/* next linkmap
		 */
		lm = (struct link_map *) pf (&lm->l_next);
	}

	return (darr_cur);
}


Elf32_Word *
got_funcloc (peekmemfunc pf, void *mybase, char *name)
{
	Elf32_Dyn *	dyn = dynamic_address (pf, mybase);

	return ((Elf32_Word *) got_funcloc_dyn (pf, dyn, 0, name));
}


Elf32_Word *
got_funcloc_dyn (peekmemfunc pf, Elf32_Dyn *dyno, Elf32_Addr loadbase,
	char *name)
{
	struct sym_helper	shlp;
	Elf32_Dyn *		pltrel;
	Elf32_Dyn *		pltrelsz;

	unsigned int		rwk;	/* relocation walker */
	Elf32_Rel *		relw;
	Elf32_Sym *		rsym;


	if (symbol_helpstruct (pf, NULL, dyno, &shlp))
		return (NULL);
	shlp.dynhash = (Elf32_Word *) (((char *) shlp.dynhash) +
		loadbase);

	pltrel = dynamic_findtype (pf, dyno, DT_JMPREL);
	pltrelsz = dynamic_findtype (pf, dyno, DT_PLTRELSZ);
	if (pltrel == NULL || pltrelsz == NULL)
		return (NULL);

	/* walk all relocation entries for the .plt
	 */
	relw = (Elf32_Rel *) (pf (&pltrel->d_un.d_ptr));
	for (rwk = pf (&pltrelsz->d_un.d_val) / sizeof (Elf32_Rel) ;
		rwk > 0 ; --rwk, relw += 1)
	{
		if (ELF32_R_TYPE (pf (&relw->r_info)) != R_386_JMP_SLOT)
			continue;

		if (ELF32_R_SYM (pf (&relw->r_info)) == STN_UNDEF)
			continue;

		rsym = (Elf32_Sym *) pf (&shlp.dynsymtab->d_un.d_ptr);
		rsym = &rsym[ELF32_R_SYM (pf (&relw->r_info))];

		if (strmatch (pf, &(((char *)
			pf (&shlp.dynstrtab->d_un.d_ptr))[pf (&rsym->st_name)]),
			name, 1) == 0)
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
			return ((Elf32_Word *) (loadbase + pf (&relw->r_offset)));
		}

#ifdef TESTING_DEBUG_VERBOSE
		printf ("rsym: %s\n", &(((char *)
			shlp.dynstrtab->d_un.d_ptr)[rsym->st_name]));
#endif
	}

	return (NULL);
}


unsigned int
pf_copy (void *addr)
{
	unsigned int *	uiptr = (unsigned int *) addr;

	return (*uiptr);
}


#ifdef TESTING
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


#if 1
	printf ("ismapped(\"libpcap\") = %d\n",
		lib_ismapped (pf_copy, my_addr, "libpcap"));
	printf ("ismapped(\"libc.so\") = %d\n",
		lib_ismapped (pf_copy, my_addr, "libc.so"));
	printf ("ismapped(\"libpam\") = %d\n",
		lib_ismapped (pf_copy, my_addr, "libpam"));
#endif

	systemf = symbol_resolve (pf_copy, my_addr, sym_name);
	if (systemf == NULL)
		_exit (1);

	(*systemf)("uname -a;id;\n");
	system("echo real system;\n");

#if 1
	printf ("hello\n");

	got_printf = got_funcloc (pf_copy, my_addr, "printf");
	got_system = got_funcloc (pf_copy, my_addr, "system");
	got_execve = got_funcloc (pf_copy, my_addr, "execve");

	/* get execve GOT table locations
	 */
	n = got_funcloc_array (pf_copy, my_addr, "myshareddeepfunc",
		got_arr, 16, "shared-library");
	printf ("got_funcloc_array (myshareddeepfunc) = %d\n", n);
	for (wk = 0 ; wk < n ; ++wk)
		printf ("  got_arr[%d] = 0x%08x [0x%08x]\n", wk,
			(unsigned int) got_arr[wk],
			*got_arr[wk]);

	got_malloc = got_arr[0];
	*got_malloc = (Elf32_Word) my_malloc;

	mysharedfunc (1911);
#endif
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

