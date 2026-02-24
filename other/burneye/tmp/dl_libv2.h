/*
 * dl_libv2.h :
 *      defines and function defs for dl_libv2.c
 *
 *      libdl.o needs to be linked in with the other object code to be loaded,
 *      in order to provide its fucktionality.  
 *
 *      dl_libv2.o will allow the dynamic linking against libraries that the
 *	runtime dynamic linker can find an mmap in... this means that you can 
 *	use system libraries, or the full path to another library.
 *
 *      The interface is described below.
 *      !! BE AWARE that this version of libdl uses the heap !!
 *      if you require a stack based libdl, then uses libdl_stack, which
 *      is availble in this distro.. (actually, dl_lib_stack.c was rm'd by 
 *	accident... it requires too much work with alloca in main() anyway....
 *	just use the damn heap!)
 *
 *
 *      Copyright the grugq, 2001.
 */

#ifndef _LIB_DYN_LINKER__H
#define _LIB_DYN_LINKER__H

#include <elf.h>

#define __syscall1(type,name,type1,arg1) \
type _##name(type1 arg1) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name),"b" ((long)(arg1))); \
        return (type) __res; \
}

#define __syscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
type _##name(type1 arg1,type2 arg2,type3 arg3) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
        : "=a" (__res) \
        : "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
                "d" ((long)(arg3))); \
        return (type) __res; \
}

#define  NULL   ((void *)0)     /* to avoid stdio.h */
#define  BUFSIZ 4096            /* should be plenty */

struct lib_desc
{
        Elf32_Word      * l_buckets;    /* addr of the hash table */
        Elf32_Word        l_nbuckets;   /* number of buckets in hash tab */
        Elf32_Word        l_nchain;     /* number of elements in chain */
        Elf32_Word      * l_chain;      /* addr of the chain */
        Elf32_Sym       * l_symtab;     /* ptr to symbol table */
        char            * l_strtab;     /* ptr to string table */
        char            * l_load_addr;  /* load address of the library */
        void            * l_handle;     /* handle from dlopen(), for dlcose() */
        struct lib_desc * l_prev;       /* pointer to previous LibDesc */
        struct lib_desc * l_next;       /* pointer to next LibDesc */
        /* These values are only intialized for the head of the list */
        void            *(*malloc)(unsigned long); /* fct ptr to malloc(3) */
        void             (*free)(void *); /* fct ptr to free(3) */
        void            *(*dlopen)(char *, int, void *)
                __attribute__ ((regparm(3))); /* fct ptr to _dl_open() */
        void             (*dlclose)(void *)
                __attribute__ ((regparm(1))); /* fct ptr to _dl_close() */
};

typedef struct lib_desc LibDesc;

/* PROTOTYPES */
void * dl_lib_init(void);
void   dl_lib_fini(void *h);
void * dl_lib_open(char *lib_name, void *head);
void * dl_lib_sym(char *sym_name, void *handler);
void   dl_lib_close(void *lib, void *head);

#endif  /* _LIB_DYN_LINKER__H */
