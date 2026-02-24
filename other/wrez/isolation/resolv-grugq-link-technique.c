#include <elf.h>

#define NULL	((void *)0)


struct link_map {
	Elf32_Addr	  l_addr;
	char		* l_name;
	Elf32_Dyn	* l_ld;		/* .dynamic ptr */
	struct link_map	* l_next,
			* l_prev;
};

struct resolv {
	Elf32_Word	* hash;
	Elf32_Word	* chain;
	Elf32_Sym	* symtab;
	char		* strtab;
	int		  num;
};


static int
strmatch(char *s1, char *s2)
{
	while (*s1++ == *s2++)
		if (*s1 == 0)
			return (1);
	return (0);
}

/*
inline int
strlen(char *str)
{
	al = 0
	ecx = ffffffff
	repne scasb
	not ecx
}
*/

static inline struct resolv *
build_resolv(struct link_map *l, struct resolv *r)
{
	Elf32_Dyn	* d;


	for (d = l->l_ld; d->d_tag != DT_NULL; d++) {
		switch (d->d_tag) {
		case DT_HASH:
			{
				Elf32_Word	* h;


				h = (Elf32_Word *)
					((char *)d->d_un.d_ptr+l->l_addr);

				r->num = *h++; // num buckets
					  h++; // num chains
				r->hash = h;
				r->chain = h + r->num;
			}
			break;
		case DT_STRTAB:
			r->strtab = (char *)d->d_un.d_ptr;
			break;
		case DT_SYMTAB:
			r->symtab = (Elf32_Sym *)d->d_un.d_ptr;
			break;
		default:
			break;
		}
	}
	return (r);
}

static void *
resolve(char *sym_name, long hn, struct link_map *l)
{
	Elf32_Sym	* sym;
	struct	resolv	* r;
	long		  ndx;


	r = build_resolv(l, alloca(sizeof(*r)));

	for (ndx = r->hash[ hn % r->num ]; ndx; ndx = r->chain[ ndx ]) {
		sym = &r->symtab[ ndx ];

		if (ELF32_ST_TYPE(sym->st_info) != STT_FUNC)
			continue;

		if (strmatch(sym_name, r->strtab + sym->st_name))
			return (((char *)l->l_addr) + sym->st_value);
	}

	return NULL;
}

static struct link_map *
locate_link_map(void *my_base)
{
	Elf32_Ehdr	* e = (Elf32_Ehdr *)my_base;
	Elf32_Phdr	* p;
	Elf32_Dyn	* d;
	Elf32_Word	* got;


	p = (Elf32_Phdr *)((char *)e + e->e_phoff);

	while (p++<(Elf32_Phdr *)((char*)p + (e->e_phnum * sizeof(Elf32_Phdr))))
		if (p->p_type == PT_DYNAMIC)
			break;

	// error check
	/*
	if (p->p_type != PT_DYNAMIC)
		return (NULL);
	*/

	for (d = (Elf32_Dyn *)p->p_vaddr; d->d_tag != DT_NULL; d++)
		if (d->d_tag == DT_PLTGOT) {
			got = (Elf32_Word *)d->d_un.d_ptr;
			break;
		}
	// error check
	// if (got == NULL)
	// 	return (NULL);

	// different on other platforms
#define GOT_LM_PTR	1
	return ((struct link_map *)got[GOT_LM_PTR]);
}

void *
get_addr(void *my_base, char *sym_name, long hn)
{
	struct link_map	* l;
	void		* a;


	l = locate_link_map(my_base);
	// scan link maps... 

	//  don't know where it terminates... NULL, I hope. :-)
	while (l->l_prev)
		l = l->l_prev;
	
	// scan link maps for the symbol. slow, but...
	for (; l->l_next; l = l->l_next)
		if ((a = resolve(sym_name, hn, l)))
			return (a);

	return (NULL);
}

unsigned long
elf_hash(const char *name)
{
	unsigned long	h = 0, g;

	while (*name) {
		h = (h << 4) + *name++;

		if ((g = h & 0xf0000000))
			h ^= g >> 24;
		h &= ~g;
	}
	return (h);
}

/*
void *
locate_my_base()
{
	find an address within the .text section, or at least within the 
	.data. Then search backwards page at a time:

	for (addr = ALIGN(cur_addr, 4096); ; addr -= 4096)
		if (memcmp(addr, ELFMAG, SELFMAG))
			return (addr);
	
	return (NULL);

	That failing, you can hard code it (but doing it dynamicly
	means you more cool. :)  

}
*/

#if 1
int
main (void)
{
	unsigned long	  hn;
	void	* my_addr = (void *) 0x08048000;
	char	* sym_name = "printf";
	int	(*printf)(const char *, ...);


	hn = elf_hash(sym_name);
	printf = get_addr(my_addr, sym_name, hn);

	(*printf)("Hello World\n");

	return (0);
}
#endif
