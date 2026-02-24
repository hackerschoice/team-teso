/* loader.c - simple elf object loader
 *
 * by scut
 */

#include <sys/mman.h>
#define	__USE_GNU
#include <sys/ucontext.h>
#undef	__USE_GNU
/*#include <asm/processor.h>*/
#include <asm/unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <assert.h>
#include <elf.h>

#include <elf_base.h>
#include <elf_reloc.h>
#include <elf_section.h>
#include <ia32-function.h>
#include <ia32-decode.h>
#include <ia32-trace.h>
#include <ia32-dataflow.h>

#include <datahandler.h>
#include <morph.h>
#include <utility.h>
#include <common.h>
#include <objwriter.h>
#include <func_handling.h>

#include <version.h>


#define	rwait	read(0,rdummy,2);
#define	rloop	__asm__ __volatile__ (".byte 0xeb\n.byte 0xfe\n");

unsigned char	rdummy[2];

/*** static prototypes
 */

static void
bblock_fix (void);

static void
br_reloc_fix (ia32_function *func, ia32_bblock *br,
	ia32_xref *xr, elf_reloc *rel);

static int
check_object (void);

static int
is_systemcall_forbidden (ucontext_t *uctx);

static void
exec_stackdump (unsigned int *sptr);

static void
exec_sigtrap (int signum, siginfo_t *si, ucontext_t *uctx);

static int inline
process_call (ia32_function *target);

static void
usage (char *program);

static void
regdump (ucontext_t *uctx);

static void
test_morph (ia32_function **flist, unsigned int flist_count, char *fname);

void
execute (ia32_function **flist, unsigned int flist_count,
	int argc, char *argv[]);

static ia32_function **
func_list_filter_dynamic (ia32_function **flist, unsigned int flist_count,
	unsigned int *out_count);

static void
bblock_describe (void *fptr, unsigned char *breakpos);

void
check_unsorted_xrefs (ia32_function *func);

#ifdef	DUPE_DEBUG
extern int dupe_check_enabled;
void dupe_alloc (unsigned int max_addr);
void dupe_free (void);
#endif


/* global variables used by signal handlers and other mischief functions ;)
 */

char *		startfunc = "_start";
extern int	quiet;
int		quiet_limited = 0;
int		debug = 1,
		bblock_skip = 0;

extern int	ia32_verbosity;
extern int	ia32_confirm_all;


struct {
	unsigned int		bb_count;
	unsigned long long int	bb_byte_size,
				bb_inst_size;
} sim_stats = {
	.bb_count = 0,
	.bb_byte_size = 0,
	.bb_inst_size = 0,
};


ia32_function *	curfunc;
ia32_bblock *	cur;

ia32_function **	g_flist;
unsigned int		g_flist_count;

unsigned char	overwritten;
unsigned char *	breakpos;
unsigned int *	execute_retloc;

void		(* fptr)(void);


int	reg_cpu_to_uc[] = { REG_EAX, REG_ECX, REG_EDX, REG_EBX, REG_ESP,
	REG_EBP, REG_ESI, REG_EDI };


/*** implementation
 */

static void
usage (char *program)
{
	fprintf (stderr, "usage: %s [options] <function>\n\n", program);

	fprintf (stderr, "options\n"
		"\t-3 lvl\tset ia32 verbosity level\n"
		"\t\tlevels 0 to 3: fatal (0), warnings (1), info (2), debug (3)\n"
		"\t-D\tno debug mode, step without break\n"
		"\t-s num\tskip break on first <num> basic blocks\n"
		"\t-q\tquiet mode\n"
		"\t-Q\tlimited quiet mode, be quiet until approaching -s block\n"
		"\t-e func\tentry point function\n"
		"\t-l func\tdump a register usage analysis (dataflow analysis: live reg)\n"
		"\t-v\tvisual mode, show function graph\n"
		"\n");

	exit (EXIT_FAILURE);
}


/* global, uhh (for sigaction handler to use)
 */
elf_base *		base;

int
main (int argc, char *argv[])
{
	unsigned int		xref_count;
	ia32_function **	flist = NULL;
	unsigned int		flist_count = 0;
	elf_rel_list *		rel_list;

	unsigned int		lidx;
	unsigned int		reloc_code_list_count = 0;
	elf_reloc_list **	reloc_code_list = NULL;

	elf_reloc_list *	reloc_rodata = NULL;
	elf_reloc_list *	reloc_data = NULL;
#if 0
	unsigned int		xref_count;
	data_item *		dh;
	elf_section *		rodata;
#endif

	char			c;
	char *			fname = "main";
	char *			elfname;
	char *			progname = argv[0];

	int			visual = 0,
				n;
	char *			livereg_func = NULL;

	int			exec_argc;
	char **			exec_argv;

	code_pair *		exec_sections;
	code_pair *		exec_sec;	/* walker */

	ia32_function **	func_dyn;
	unsigned int		func_dyn_count;


	printf ("burneye2 simulation loader, version "VERSION".\n");
	printf ("PRELIMINARY ALPHA SOFTWARE, DO NOT USE FOR REAL STUFF\n\n");

	if (argc < 3)
		usage (progname);

	srandom (time (NULL));

	while ((c = getopt (argc, argv, "3:Ds:Qqcl:ve:")) != EOF) {
		switch (c) {
		case ('3'):
			if (sscanf (optarg, "%u", &ia32_verbosity) != 1)
				usage (progname);
			break;
		case ('D'):
			debug = 0;
			break;
		case ('s'):
			if (sscanf (optarg, "%u", &bblock_skip) != 1)
				usage (progname);

			assert (bblock_skip >= 0);
			break;
		case ('Q'):
			quiet = quiet_limited = 1;
			break;
		case ('q'):
			quiet = 1;
			break;
		case ('c'):
			ia32_confirm_all = 1;
			break;
		case ('l'):
			livereg_func = optarg;
			break;
		case ('v'):
			visual = 1;
			break;
		case ('e'):
			startfunc = optarg;
			break;
		default:
			usage (progname);
			break;
		}
	}

	if (quiet_limited && bblock_skip == 0) {
		fprintf (stderr, "limited quiet mode (-Q) is only possible "
			"when using skip option (-s)\n\n");

		exit (EXIT_FAILURE);
	}

	/* process further non-option arguments
	 */
	if ((optind + 1) > argc)
		usage (progname);

	elfname = argv[optind];
	optind += 1;

	if (optind < argc) {
		fname = argv[optind];
		optind += 1;
	}

	/* emulated program arguments
	 */
	if (optind < argc) {
		exec_argc = argc - optind + 1;
		exec_argv = xcalloc (exec_argc + 1, sizeof (char *));

		exec_argv[0] = elfname;
		exec_argv[exec_argc] = NULL;
		for (n = 0 ; n < exec_argc ; ++n)
			exec_argv[n + 1] = argv[optind + n];
	} else {
		exec_argc = 1;
		exec_argv = xcalloc (2, sizeof (char *));
		exec_argv[0] = elfname;
		exec_argv[1] = NULL;
	}

	fnote ("%d argument%s:\n", exec_argc, (exec_argc >= 2) ? "s" : "");
	for (n = 0 ; n < exec_argc ; ++n)
		fnote ("   exec_argv[%d] = \"%s\"\n", n, exec_argv[n]);
	fnote ("\n");

	if (fname[0] == '-' || elfname[0] == '-')
		usage (progname);

	/* now that we processed all arguments, try to load and analyze the
	 * elf object
	 */
	base = elf_base_load (elfname);
	if (base == NULL) {
		fprintf (stderr, "elf_base_load failed\n");

		exit (EXIT_FAILURE);
	}
	elf_section_secalloc (base->seclist);

	fix_ustart (base);

#ifdef	DUPE_DEBUG
	{
		elf_section *	text_sec;

		/* FIXME:SEC */
		text_sec = elf_section_list_find_name (base->seclist, ".text");
		assert (text_sec != NULL);
		assert (text_sec->Shdr.sh_addr < 0x1000);
		dupe_alloc (text_sec->Shdr.sh_addr + text_sec->Shdr.sh_size);
	}
#endif

	/* for every executeable section, find a possible relocation table,
	 * and process the pair.
	 */
	rel_list = elf_rel_list_create (base);
	exec_sections = code_pair_extract (base, base->seclist, rel_list);
	for (exec_sec = exec_sections ; exec_sec != NULL ;
		exec_sec = exec_sec->next)
	{
		ia32_function **	flist_sec;
		unsigned int		flist_sec_count;

		printf ("codepair: %s / %s with %s\n",
			exec_sec->code_section->name,
			exec_sec->reloc->reloc_section->name,
			exec_sec->reloc->reloc_symbol->name);

		flist_sec = elf_function_list_create (base->elf, base->seclist,
			exec_sec->code_section, &flist_sec_count);

		if (flist_sec == NULL) {
			fprintf (stderr, "elf_function_list_create failed on "
				"%s\n", exec_sec->code_section->name);

			exit (EXIT_FAILURE);
		}

		/* append new functions to global list.
		 */
		flist = xrealloc (flist, (flist_count + flist_sec_count) *
			sizeof (ia32_function *));
		memcpy (&flist[flist_count], flist_sec, flist_sec_count *
			sizeof (ia32_function *));

		printf ("adding %d items to %d items long list\n", flist_sec_count,
			flist_count);
		flist_count += flist_sec_count;
		free (flist_sec);
	}
	elf_function_list_sort (flist, flist_count);

	/* build relocation lists
	 */
	/* before starting the actual program, we need to relocate any entries
	 * within .data, if there are some.
	 *
	 * FIXME: handle function pointers properly (spilling a stub)
	 * FIXME: we should do the same for .rodata, not just switch table
	 *        stuff. but when doing so, check that we do not clash with
	 *        XXX: have done .rodata relocation already (see above)
	 * switch table offset calculation !
	 */

	for (exec_sec = exec_sections ; exec_sec != NULL ;
		exec_sec = exec_sec->next)
	{
		lidx = reloc_code_list_count;
		reloc_code_list_count += 1;
		reloc_code_list = xrealloc (reloc_code_list,
			reloc_code_list_count * sizeof (elf_reloc_list *));

		reloc_code_list[lidx] = elf_reloc_list_create (base,
			exec_sec->reloc, flist, flist_count);
		elf_reloc_list_hashgen (reloc_code_list[lidx], 0);
	}

	backup_section_data (base);
	relocate_sections (base, rel_list);
	ia32_func_list_dump (flist, flist_count);

	/* do the real intra-function analysis
	 */
	lidx = 0;
	for (exec_sec = exec_sections ; exec_sec != NULL ;
		exec_sec = exec_sec->next, ++lidx)
	{
		/* enable and setup dupe checking
		 */
#ifdef	DUPE_DEBUG
		dupe_check_enabled = 1;

		dupe_alloc (exec_sec->code_section->Shdr.sh_addr +
			exec_sec->code_section->Shdr.sh_size);
#endif
		/* note that the code is already relocated to allow better
		 * parsing of switch tables.
		 */
		ia32_func_treeplain (&flist, &flist_count,
			reloc_code_list[lidx], reloc_rodata,
			exec_sec->code_section->sh_idx);
#ifdef	DUPE_DEBUG
		dupe_free ();
#endif
	}


	/* TODO: implement real checking
	 */
	if (check_object ()) {
		fprintf (stderr, "object invalid\n");
	}

	if (visual)
		func_output ("output.vcg", flist, flist_count, fname, 0);

	/* TODO: maybe filter all is_copy functions here */

	ia32_func_list_walk (flist, flist_count, ia32_func_oxref_fromfunc);

	// FROM HERE MOVED AWAY: .rel.data relocation

	if (livereg_func != NULL)
		func_livereg ("output.vcg", flist, flist_count, livereg_func, 0);

	/* also insert proper .rodata content
	 */
//	if (reloc_data != NULL)
//		relocate_data (base, reloc_rodata);

#if 0
	test_morph (flist, flist_count, fname);

	if (visual)
		output (flist, flist_count, fname);

	elf_base_destroy (base);

	exit (EXIT_SUCCESS);
#endif
	printf ("### FUNCTION LIST BEGIN ###\n");
	ia32_func_list_dump (flist, flist_count);
	printf ("### FUNCTION LIST END ###\n");

	find_position_curious_functions (flist, flist_count);
	find_abnormal_end_functions (flist, flist_count);

	func_bblock_deref_interfunc (flist, flist_count);
	func_dyn = func_list_filter_dynamic (flist, flist_count,
		&func_dyn_count);

	restore_section_data (base);

	printf ("### UNSORTED \"OTHER\" CROSS REFERENCES BEGIN ###\n");
	ia32_func_list_walk (flist, flist_count, check_unsorted_xrefs);
	printf ("### UNSORTED \"OTHER\" CROSS REFERENCES END ###\n");
//	exit (EXIT_FAILURE);

	printf ("### EXECUTION BEGIN ###\n");
	execute (flist, flist_count, exec_argc, exec_argv);
	/* RETURN TO HERE */
	printf ("### EXECUTION END ###\n");

	exit (EXIT_SUCCESS);
}


void
check_unsorted_xrefs (ia32_function *func)
{
	if (func->other_xref_count) {
		fnote ("%-30s | other xref count = %d\n",
			func->name, func->other_xref_count);
	}
}


static int
check_object (void)
{
#if 0
	/* FIXME: dietlibc has missing function objects for "exit" and such that
	 *        will puke up here
	 */
	/* for loading the object we have to ensure there are no external
	 * function references. if there are, bail out early.
	 */
	xref_count = ia32_func_xref_count (flist, flist_count,
		IA32_XREF_FUNCEXTERN);
	if (xref_count != 0) {
		unsigned int	fln,
				xrn;

		fprintf (stderr, "%u extern function references, aborting\n",
			xref_count);


		for (fln = 0 ; fln < flist_count ; ++fln) {
			for (xrn = 0 ; xrn < flist[fln]->func_xref_count ; ++xrn) {
				char *		ext_name;
				unsigned int	from_addr;
				elf_reloc *	rel;

				if (flist[fln]->func_xref[xrn]->to_type !=
					IA32_XREF_FUNCEXTERN)
					continue;

				from_addr = flist[fln]->func_xref[xrn]->from +
					flist[fln]->func_xref[xrn]->addend +
					flist[fln]->start;
				fprintf (stderr, "\t@ 0x%08x: ", from_addr);

				rel = elf_reloc_list_lookup (reloc_text,
					from_addr);

				if (rel == NULL) {
					fprintf (stderr, "??? by (%s)\n",
						flist[fln]->name);
					continue;
				}

				ext_name = "?";
				if (rel->sym->name != NULL)
					ext_name = rel->sym->name;

				fprintf (stderr, "\t\"%s\" referenced from "
					"0x%08x (%s)\n", ext_name,
					from_addr, flist[fln]->name);
			}
		}

		exit (EXIT_FAILURE);
	}
	/* FIXME: add check for "common" symbols and abort if found
	 */
#endif
	return (0);
}


/* func_list_filter_dynamic
 *
 * filter the function list `flist', which is `flist_count' items long for
 * functions that are invoked dynamically. this includes any function which is
 * pointer-referenced. create an output list of functions which we cannot
 * inline or drop, because they may be called dynamically (we create a stub
 * for them). the length of the output list will be stored in `out_count'.
 *
 * return NULL on failure (no dynamic functions)
 * return list of success
 */

static ia32_function **
func_list_filter_dynamic (ia32_function **flist, unsigned int flist_count,
	unsigned int *out_count)
{
	unsigned int		fn;
	ia32_function **	fl_out = NULL;


	*out_count = 0;
	for (fn = 0 ; fn < flist_count ; ++fn) {
		ia32_bblock **		all = NULL;
		unsigned int		all_count,
					all_walk;
		ia32_bblock *		cur;

		all = ia32_br_get_all (flist[fn]->br_root, &all_count);
		for (all_walk = 0 ; all_walk < all_count ; ++all_walk) {
			ia32_xref **	xrarr;
			ia32_xref *	xr;
			unsigned int	xn;
			elf_reloc *	rel;

			cur = all[all_walk];
			xrarr = (ia32_xref **) cur->other_xref;
			for (xn = 0 ; xn < cur->other_xref_count ; ++xn) {
				xr = xrarr[xn];
				assert (xr != NULL);

				if (xr->to_type != IA32_XREF_FUNCTION)
					continue;

				rel = (elf_reloc *) xr->to_data;
				assert (rel != NULL);

				if (rel->type != ELF_RELOC_FUNCTION)
					continue;

				/*assert (rel->func != NULL);*/
				if (rel->func == NULL) {
					fnote ("WARNING: ELF_RELOC_FUNCTION "
						"relocation in \"%s\" (0x%x-"
						"0x%x) with func = NULL\n",
						flist[fn]->name, cur->start,
						cur->end);
					continue;
				}

				printf ("dyn: %s (referenced by %s)\n",
					rel->func->name, flist[fn]->name);

				/* FIXME:TODO: add to return list */
				assert (0);
			}
		}

		if (all != NULL)
			free (all);
	}

	return (fl_out);
}


/* bblock_fix
 *
 * fix any "other" relocations happening in current bblock, before it is
 * executed. to do this, use global variables `cur', `curfunc' and `base'.
 *
 * return in any case
 */

static void
bblock_fix (void)
{
	unsigned int	n;
	ia32_xref **	xrarr;
	ia32_xref *	xr;
	elf_reloc *	rel;
	unsigned int	br_relstart,
			br_relend;


	br_relstart = cur->start - curfunc->start;
	br_relend = cur->end - curfunc->start;

	xrarr = (ia32_xref **) cur->other_xref;
	fnote ("[%2u] cross references within basic block. fixing.\n",
		cur->other_xref_count);

	for (n = 0 ; n < cur->other_xref_count ; ++n) {
		xr = xrarr[n];
		assert (xr != NULL);

#if 0
		fnote ("(0x%04x-0x%04x,rel:0x%04x)",
			br_relstart, br_relend, xr->from);
#endif

		if (xr->from < br_relstart || xr->from >= br_relend)
			continue;

		rel = (elf_reloc *) xr->to_data;
		assert (rel != NULL && rel->sym != NULL &&
			rel->sym->name != NULL);
#if 0
		fnote (" (0x%04x: %s)", xr->from, rel->sym->name);
#endif
		br_reloc_fix (curfunc, cur, xr, rel);
	}
	fnote ("\n");

	return;
}


static void
br_reloc_fix (ia32_function *func, ia32_bblock *br,
	ia32_xref *xr, elf_reloc *rel)
{
	unsigned int	value;
	unsigned int *	place;
	unsigned int	addend,
			symval;


/*	fnote ("  reltype %d", ELF32_R_TYPE (rel->orig.r_info)); */

	place = (unsigned int *) &func->mem[xr->from];
#if 0
	/* the correct addend should always be in xr->rel_addend for other
	 * xrefs than bblock end function crossreferences.
	 */
	addend = *place;
	printf ("\nAT: %s:0x%04x: addend (there): 0x%08x\naddend (xref): 0x%08x\n",
		func->name, xr->from, addend, xr->rel_addend);
#endif
	addend = xr->rel_addend;

	/* FIXME: maybe make this necessary only for relocations which have
	 * type S
	 */
	assert (rel->sym != NULL);
	assert (rel->sym->sec != NULL);
/*	if (rel->sym->sec == NULL)
		exit (EXIT_FAILURE);
*/
	value = (unsigned int) rel->sym->sec->data;

	symval = rel->sym->sent.st_value;

#if 0
	fnote (" [A: 0x%08x, S: 0x%08x, SEC: %08x \"%s:%s\"]\n",
		addend, symval, value, rel->sym->sec->name,
		(rel->sym->name == NULL) ? "__unknown" : rel->sym->name);
#endif

	switch (ELF32_R_TYPE (rel->orig.r_info)) {
	/* R_386_32 = S + A */
	case (R_386_32):
		value += symval + addend;
		break;
	/* R_386_PC32 = S + A - P */
	case (R_386_PC32):
		value = symval + addend - rel->orig.r_offset;
		/* assert (0); */
		break;
	default:
		assert (0);
		break;
	}

	fnote ("     => 0x%08x into 0x%08x\n", value,
		(unsigned int) place);
	/* XXX: probably insane, as value can be anything ;) */
	/*
	fnote ("        content: [0x%08x] = 0x%08x\n",
		value, *((unsigned int *) value));
	*/

	*place = value;

	return;
}


static void
bblock_describe (void *fptr, unsigned char *breakpos)
{
	ia32_instruction *	inst,
				inst_s;
	unsigned int		vaddr,
				xn,
				n;
	unsigned char *		curmem;
	char			inst_str[256];
	ia32_xref **		xrarr;
	ia32_xref *		xr;
	elf_reloc *		rel;


	if (quiet)
		return;

	xrarr = (ia32_xref **) cur->other_xref;

	fnote ("\n");
	fnote ("### about to execute at 0x%08x (%s:0x%08x = 0x%x) ###\n",
		(unsigned int) fptr, curfunc->name == NULL ? "__unknown" :
			curfunc->name, cur->start - curfunc->start,
			cur->start);
	fnote ("############################################################"
		"######################################\n");

#define	INSTRUCTION_MAX_LEN	7
	for (vaddr = cur->start ; vaddr < cur->end ; vaddr += inst->length) {
		curmem = &curfunc->mem[vaddr - curfunc->start];
		if (curmem > breakpos)
			break;

		inst = ia32_decode_instruction (curmem, &inst_s);
		assert (inst != NULL);

		fnote ("# 0x%04x # %02x . ", vaddr - curfunc->start,
			vaddr - cur->start);

		for (n = 0 ; n < INSTRUCTION_MAX_LEN ; ++n) {
			if (n < inst->length) {
				fnote ("%02X%c", curmem[n],
					(curmem == breakpos && n == 0) ?
					'<' : ' ');
			} else {
				fnote ("   ");
			}
		}

		fnote (" # ");

		ia32_sprint (inst, inst_str, sizeof (inst_str));
		for (n = 0 ; n < sizeof (inst_str) ; ++n)
			if (inst_str[n] == '\t')
				inst_str[n] = ' ';

		fnote ("%-40s #\n", inst_str);

		for (xn = 0 ; xn < cur->other_xref_count ; ++xn) {
			xr = xrarr[xn];
			assert (xr != NULL);

			if (xr->from < (vaddr - curfunc->start) ||
				xr->from >= (vaddr + inst->length - curfunc->start))
				continue;

			rel = (elf_reloc *) xr->to_data;

			fnote ("#        #    . ");
			for (n = 0 ; n < (xr->from - (vaddr - curfunc->start)) ; ++n)
				fnote ("   ");
			fnote ("~~~~~~~~~~~");
			for (n = 3 * n + 11 ;
				(INSTRUCTION_MAX_LEN * 3 + 1) > n ; ++n)
				fnote (" ");

			assert (rel != NULL && rel->sym != NULL &&
				rel->sym->name != NULL);
			fnote ("#   %-38s #\n", rel->sym->name);
		}
	}
	if (breakpos == (&curfunc->mem[vaddr - curfunc->start])) {
		fnote ("# 0x%08x # 0x%04x .", vaddr - curfunc->start,
			vaddr - cur->start);
		fnote ("(CC) break\n");
	}

	fnote ("############################################################"
		"######################################\n");
}


void
execute (ia32_function **flist, unsigned int flist_count,
	int argc, char *argv[])
{
	struct sigaction	siga;
	int			argn,
				len;
	char *			targv[16];
	unsigned char *		pg_start;	/* page start */


	/* save current frame markers so we can restore control flow when
	 * emulated program returns. look for "RETURN TO HERE" marker.
	 */
	__asm__ __volatile__ (
		"	movl	%%ebp, %%eax\n"
		"	addl	$4, %%eax\n"
		: "=a" (execute_retloc));

	memset (&siga, 0x00, sizeof (siga));
	siga.sa_handler = NULL;
	siga.sa_sigaction = (void *) exec_sigtrap;
	siga.sa_flags = SA_SIGINFO;
	/* TODO: mask every signal during signal handler execution */
	/* siga.sa_mask = EVERYTHING; */
	siga.sa_restorer = NULL;
	if (sigaction (SIGTRAP, &siga, NULL) == -1) {
		fprintf (stderr, "sigaction failure\n");
		
		exit (EXIT_FAILURE);
	}

	g_flist = flist;
	g_flist_count = flist_count;

	curfunc = ia32_func_list_find_byname (flist, flist_count, startfunc);
	if (curfunc == NULL) {
		fprintf (stderr, "no start function named \"%s\" in object\n",
			startfunc);

		return;
	}

	if (quiet == 0)
		rwait;

	cur = curfunc->br_root;
	bblock_fix ();

	breakpos = ia32_func_v2real (curfunc, cur->end - cur->last_ilen);
	overwritten = breakpos[0];
	fptr = (void *) ia32_func_v2real (curfunc, cur->start);

	bblock_describe (fptr, breakpos);

	if (debug) {
		if (bblock_skip > 0) {
			bblock_skip -= 1;

			if (bblock_skip <= 10 && quiet_limited)
				quiet = 0;
		} else if (quiet == 0)
			rwait;
	}

	breakpos[0] = 0xcc;

	/* get a temporary page on the stack so we can setup the program
	 * arguments. one page should be enough in all cases.
	 */
	__asm__ __volatile__ (
		"	movl	%%esp, %%eax\n"
		"	subl	$4096, %%esp\n"
		: "=a" (pg_start));

	pg_start -= 1;

	/* construct this memory layout:
	 *
	 * esp
	 * |
	 * <argc> <argv[0]> <argv[1]> .. NULL <envp[0]> .. NULL <argv[0] str> ..
	 */
	for (argn = argc - 1 ; argn >= 0 ; --argn) {
		for (len = 0 ; argv[argn][len] != '\0' ; ++len)
			;

		/* copy argument string including trailing NUL byte
		 */
		for ( ; len >= 0 ; --len) {
			pg_start[0] = argv[argn][len];
			pg_start -= 1;
		}
		
		/* FIXME: make this variable, not just 16 elements */
		targv[argn] = pg_start + 1;
	}
	pg_start -= 3;
	*((char **) pg_start) = NULL;
	pg_start -= sizeof (char *);

	/* envp[0] .. would go just here. the NULL we write below is the
	 * terminator for the argv[] pointer array.
	 */
	*((char **) pg_start) = NULL;
	pg_start -= sizeof (char *);

	for (argn = argc - 1 ; argn >= 0 ; --argn) {
		*((char **) pg_start) = targv[argn];
		pg_start -= sizeof (char *);
	}

	*((int *) pg_start) = argc;

	__asm__ __volatile__ (
		"	movl	%%ecx, %%esp\n"
		"	jmpl	*%%eax\n"
		: : "a" (fptr), "c" (pg_start));
/*	fptr (); */
}


static void
exec_stackdump (unsigned int *sptr)
{
	unsigned int	n;


	if (quiet)
		return;

	fnote ("(0x%08x): ", (unsigned int) sptr);

	for (n = 0 ; n < 8 ; ++n) {
		fnote ("0x%08x", sptr[n]);

		if (((n + 1) % 4) == 0 && n != 7)
			fnote ("\n            : ");
		else if (n != 7)
			fnote (" ");
	}
	fnote ("\n");

	return;
}


/* is_systemcall_forbidden
 *
 * we cannot let the emulated program freely set global process conditions we
 * rely on. most important, this includes signal handling, which is what this
 * function accounts for. when a system call is made, it is checked against
 * any possibly hostile calls and only if we return zero here, it is executed.
 * `uctx' is the user context at the time the system call request is made.
 *
 * return 0 if the system call invokes with register context `uctx' is allowed
 * return 1 when the system call may clobber our intentions
 */

static int
is_systemcall_forbidden (ucontext_t *uctx)
{
	unsigned int	sc_no,		/* system call number */
			signal_no;	/* canonical signal number (kill -l) */

	sc_no = uctx->uc_mcontext.gregs[REG_EAX];

	/* TODO: add handling for: sigprocmask, sigpending, sigsuspend,
	 * rt_sigprocmask, rt_sigpending, rt_sigsuspend, rt_sigqueueinfo,
	 * rt_sigtimedwait, maybe for sigaltstack(?, no 186)
	 */
	switch (sc_no) {
	case (__NR_signal):
	case (__NR_sigaction):
	case (__NR_rt_sigaction):
		signal_no = uctx->uc_mcontext.gregs[REG_EBX];
		break;
	default:
		return (0);
	}

	if (signal_no == SIGTRAP)
		return (1);

	return (0);
}


#define	LOADER_STACKSIZE	64

ia32_bblock *	brstack[LOADER_STACKSIZE];
ia32_function *	fcstack[LOADER_STACKSIZE];
int		brstack_ptr = 0;
int		trapcount = 1;

static void
exec_sigtrap (int signum, siginfo_t *si, ucontext_t *uctx)
{
	static int		system_call_magic = 0;
	int			condres;
	unsigned int		n,
				eip,
				sreg;
	ia32_xref *		xref;
	ia32_switchtable *	stab;
	unsigned int *		memabs_data;
	unsigned char *		memreg_data;
	ia32_function *		lookup;	/* temporary function object */
	unsigned int		addr;
	unsigned int *		memsib_data;


	/* account for the int3 instruction
	 */
	eip = uctx->uc_mcontext.gregs[REG_EIP] - 1;

	if (system_call_magic) {
		system_call_magic = 0;

		fnote ("### system call magic, passing on...\n");

		/* 1. restore the first-in-basic-block instruction
		 * 2. cur = cur->endbr[0] (old-cur is the syscall basic block)
		 * 3. process new basic block as usual
		 */
		breakpos[0] = overwritten;
		cur = cur->endbr[0];

		goto schedule_bblock;
	}

	/* TODO: check the signal was send to us by ourselves
	 * XXX: warning, lots of the siginfo stuff is union based, so only
	 *      can use a few at a time, if they are dependant.
	 * if (si->si_pid != getpid ()) { abort (); }
	 */
#if 0
	printf ("code: 0x%08x (%s)\n",
		si->si_code, si->si_code == 0x80 ? "KERNEL" : "-");
#endif
	fnote ("\n§§§ new basic block\n");

	if (debug) {
		if (bblock_skip > 0) {
			bblock_skip -= 1;

			if (bblock_skip <= 10 && quiet_limited)
				quiet = 0;
		} else if (quiet == 0)
			rwait;
	}

	for (n = 0 ; n < brstack_ptr ; ++n)
		fnote ("=(%s)=|", fcstack[n]->name);
	fnote ("### %s ###\n", curfunc->name);

	fnote ("eip: 0x%08x\n", eip);
	fnote ("esp: 0x%08x\n", uctx->uc_mcontext.gregs[REG_ESP]);

	fnote ("### %s:0x%04x (0x%08x) type: %d\n",
		curfunc->name, ia32_func_r2virt (curfunc, eip),
		eip, cur->endtype);

	fnote ("\n");
	exec_stackdump ((unsigned int *) uctx->uc_mcontext.gregs[REG_ESP]);
	fnote ("= %d\n", trapcount++);

	switch (cur->endtype) {
	case (BR_END_CALL_EXTERN):
		fnote ("### WARNING: skipping instruction at 0x%x\n", cur->end);
	case (BR_END_PASS):
	case (BR_END_TRANSFER):
		cur = cur->endbr[0];
		break;

	case (BR_END_CALL):
		xref = ia32_func_xref_findfrom (curfunc,
			ia32_func_r2virt (curfunc, eip));
		assert (xref != NULL && xref->to_type == IA32_XREF_FUNCTION);

		fnote ("xref: to_type = %d, to_data = 0x%08x\n",
			xref->to_type, (unsigned int) xref->to_data);

		/* FIXME: find a better way to simulate call displacement,
		 *        problem is whether we have a four byte red zone or
		 * not directly below the stack pointer. most likely not, as it
		 * will be used by the sigaction handlers. maybe even use the
		 * stack space for something of use (anti-stack-overflow marker
		 * or such :)
		 */
		if (process_call ((ia32_function *) xref->to_data))
			uctx->uc_mcontext.gregs[REG_ESP] -= 4;

		fnote (" ==CALL==> %s\n", curfunc->name);

		break;

	case (BR_END_TRANSFER_INTER):
		xref = ia32_func_xref_findfrom (curfunc,
			ia32_func_r2virt (curfunc, eip));
		assert (xref != NULL && xref->to_type == IA32_XREF_FUNCTION);
		curfunc = (ia32_function *) xref->to_data;
		cur = curfunc->br_root;
		fnote (" ==JUMP:INTERFUNCTION==> %s\n", curfunc->name);
		break;

	case (BR_END_FUNCPTR_JUMP):
		fnote ("jump to register %u, value 0x%08x\n", cur->call_reg,
			uctx->uc_mcontext.gregs[reg_cpu_to_uc[cur->call_reg]]);
		ia32_func_list_dump (g_flist, g_flist_count);

		curfunc = ia32_func_list_find_bymem (g_flist, g_flist_count,
			(unsigned char *) uctx->uc_mcontext.gregs
				[reg_cpu_to_uc[cur->call_reg]]);
		assert (curfunc != NULL);
		fnote (" ==VJUMP==> %s\n", curfunc->name);
		cur = curfunc->br_root;
		break;

	case (BR_END_FUNCPTR_CALL):
		addr = uctx->uc_mcontext.gregs[reg_cpu_to_uc[cur->call_reg]];

		fnote ("call to register %u, value 0x%08x\n",
			cur->call_reg, addr);

		/* get the real function behind the address given.
		 */
		lookup = ia32_func_list_find_bymem (g_flist, g_flist_count,
			(unsigned char *) addr);

		if (process_call (lookup))
			uctx->uc_mcontext.gregs[REG_ESP] -= 4;

		fnote (" ==VCALL==> %s\n", curfunc->name);

		break;

	case (BR_END_CALL_MEM):
		fnote ("call through memory, at [inst + %d]\n",
			cur->memabs_pos);
		assert (cur->endbr_count == 1 && cur->memabs_pos > 0);

		memabs_data = (unsigned int *) ia32_func_v2real (curfunc,
			cur->end - cur->last_ilen + cur->memabs_pos);
		memabs_data = (unsigned int *) (*memabs_data);
		fnote ("  mem-indirection [0x%08x] = 0x%08x\n",
			(unsigned int) memabs_data, *memabs_data);

		lookup = ia32_func_list_find_bymem (g_flist, g_flist_count,
			(unsigned char *) (*memabs_data));

		if (process_call (lookup))
			uctx->uc_mcontext.gregs[REG_ESP] -= 4;

		fnote (" ==MEMCALL==> %s\n", curfunc->name);

		break;

	case (BR_END_CALL_MEMREG):
		fnote ("call through memory, [reg + displ]. reg %d, "
			"displ instr[%d]\n", cur->memreg_callreg,
			cur->memreg_displ);

		assert (cur->endbr_count == 1);

		memreg_data = NULL;

		/* FIXME: remove once ensured it works */
		rwait;

		/* in case there is a displacement, extract it
		 */
		if (cur->memreg_displ > 0) {
			memreg_data = ia32_func_v2real (curfunc,
				cur->end - cur->last_ilen + cur->memreg_displ);
			memreg_data = (unsigned char *)
				(*((unsigned int *) memreg_data));
		}

		memreg_data +=
			uctx->uc_mcontext.gregs[reg_cpu_to_uc[cur->memreg_callreg]];

		memreg_data = (unsigned char *) (*((unsigned int *) memreg_data));
		lookup = ia32_func_list_find_bymem (g_flist, g_flist_count,
			memreg_data);

		if (process_call (lookup))
			uctx->uc_mcontext.gregs[REG_ESP] -= 4;

		fnote (" ==MEMREGCALL==> %s\n", curfunc->name);

		break;

	case (BR_END_CALL_MEMSIB):
		fnote ("indirect volatile call with sib memory addressing\n");

		addr = 0;

		fnote ("  ==> [");
		if (cur->memsib_base) {
			fnote ("reg%d + ", cur->memsib_basereg);
			addr = uctx->uc_mcontext.gregs[reg_cpu_to_uc[cur->memsib_base]];
		}

		if (cur->memsib_index) {
			fnote ("reg%d * %d", cur->memsib_indexreg,
				1 << cur->memsib_scale);

			addr += uctx->uc_mcontext.gregs[reg_cpu_to_uc[cur->memsib_indexreg]]
				<< cur->memsib_scale;
		}

		memsib_data = (unsigned int *) addr;

		if (cur->memsib_displpos > 0) {
			fnote (" + inst[%d]]\n", cur->memsib_displpos);

			memsib_data = (unsigned int *) ia32_func_v2real (curfunc,
				cur->end - cur->last_ilen + cur->memsib_displpos);
			addr += *memsib_data;
			memsib_data = (unsigned int *) addr;
		} else
			fnote ("]\n");

		fnote ("      mem-indirection [0x%08x] = 0x%08x\n",
			(unsigned int) memsib_data, *memsib_data);

		lookup = ia32_func_list_find_bymem (g_flist, g_flist_count,
			(unsigned char *) (*memsib_data));

		if (process_call (lookup))
			uctx->uc_mcontext.gregs[REG_ESP] -= 4;

		fnote (" ==SIBCALL==> %s\n", curfunc->name);

		break;

	case (BR_END_RET):
		if (brstack_ptr == 0) {
			printf ("### RETURN STACK UNDERFLOW ###\n");

			uctx->uc_mcontext.gregs[REG_EIP] = execute_retloc[0];
			uctx->uc_mcontext.gregs[REG_EBP] = execute_retloc[-1];
			uctx->uc_mcontext.gregs[REG_ESP] =
				(unsigned int) &execute_retloc[1];

			return;
		}

		brstack_ptr -= 1;
		assert (brstack_ptr >= 0);

		cur = brstack[brstack_ptr];
		curfunc = fcstack[brstack_ptr];
		uctx->uc_mcontext.gregs[REG_ESP] += 4;

		break;

	case (BR_END_IF_INTER):
		fnote ("inter-if with condition 0x%02x\n", cur->cond);
		condres = ia32_eflags_eval (uctx->uc_mcontext.gregs[REG_EFL],
			cur->cond);

		/* in case the condition is false, just step to the next
		 * instruction
		 */
		if (condres == 0) {
			cur = cur->endbr[0];
			break;
		}

		/* do an inter-function jump, doh! :(
		 */
		xref = ia32_func_xref_findfrom (curfunc,
			ia32_func_r2virt (curfunc, eip));
		assert (xref != NULL && xref->to_type == IA32_XREF_FUNCTION);

		fnote ("xref: to_type = %d, to_data = 0x%08x\n",
			xref->to_type, (unsigned int) xref->to_data);

		curfunc = (ia32_function *) xref->to_data;
		cur = curfunc->br_root;
		fnote (" ==JMP==> %s\n", curfunc->name);
		break;

	case (BR_END_IF):
		fnote ("if with condition 0x%02x\n", cur->cond);
		condres = ia32_eflags_eval (uctx->uc_mcontext.gregs[REG_EFL],
			cur->cond);

		if (condres) {
			fnote ("\ttrue\n");
		} else
			fnote ("\tfalse\n");

		cur = cur->endbr[condres];
		break;

	case (BR_END_SWITCH):
		stab = (ia32_switchtable *) cur->switchtab;
		fnote ("switchtable, index (reg%u << %u), elem 0-%u\n",
			stab->idx_reg, stab->idx_scale, stab->entries - 1);

		regdump (uctx);

		sreg = uctx->uc_mcontext.gregs[reg_cpu_to_uc[stab->idx_reg]];
		fnote ("reg%u = 0x%08x\n", stab->idx_reg, sreg);
		assert (stab->idx_scale == 2);
		cur = cur->endbr[sreg];
		fnote (" to => 0x%08x\n", cur->start);
		break;

	/* system calls are not trivial to deal with. we stick to this method:
	 *
	 *   1. filter whether we allow it to be called
	 *      - no, just skip over system call and make cur = endbr[0], skip
	 *        further step
	 *      - yes, proceed at 2.
	 *   2. execute the system call by scheduling an extra "int3" right
	 *      after it, then returning
	 *   3. use special magic handling at begin of this function to
	 *      restore the additional "int3" instruction, makin cur = endbr[0]
	 */
	case (BR_END_CTRL_SYSCALL):
		if (is_systemcall_forbidden (uctx)) {
			cur = cur->endbr[0];
			break;
		}

		/* system call is allowed, deal with it by restoring the
		 * systemcall instruction and breaking right after it.
		 */
		uctx->uc_mcontext.gregs[REG_EIP] = eip;
		breakpos[0] = overwritten;
		breakpos = ia32_func_v2real (curfunc, cur->endbr[0]->start);
		overwritten = breakpos[0];
		breakpos[0] = 0xcc;

		system_call_magic = 1;

		return;

	default:
		fnote ("unable to decode endtype %d yet.\n", cur->endtype);
		_exit (1);
		break;
	}

schedule_bblock:
	/* restore overwritten byte, then process new bblock
	 */
	breakpos[0] = overwritten;
	bblock_fix ();

	sim_stats.bb_count += 1;
	sim_stats.bb_byte_size += cur->end - cur->start;
	/* TODO: sim_stats.bb_inst_size += ia32_inst_count (cur) */

	fnote ("### :: > cur->last_ilen = %d\n", cur->last_ilen);

	breakpos = ia32_func_v2real (curfunc, cur->end - cur->last_ilen);

	fptr = (void *) ia32_func_v2real (curfunc, cur->start);
	bblock_describe (fptr, breakpos);

	regdump (uctx);

	fnote ("\n");
	exec_stackdump ((unsigned int *) uctx->uc_mcontext.gregs[REG_ESP]);

	overwritten = breakpos[0];
	breakpos[0] = 0xcc;

	uctx->uc_mcontext.gregs[REG_EIP] = (unsigned int) fptr;
}


static int inline
process_call (ia32_function *target)
{
	if (target == NULL) {
		fnote ("FATAL: invalid target function (NULL) reached from "
			"\"%s\":0x%x\n", curfunc->name, cur->end);

		fnote ("FATAL: skipping call, danger ahead\n");
		cur = cur->endbr[0];

		return (0);
		/*_exit (EXIT_FAILURE);*/
	}

	/* skip over position curious functions.
	 */
	if (target->is_pos_curious)  {
		fnote ("WARNING: position curious function \"%s\", "
			"skipping\n", target->name);

		/* the block after the call (i.e. nop the call)
		 */
		cur = cur->endbr[0];
		return (0);
	}

	/* save the current position on the internal stack
	 */
	fcstack[brstack_ptr] = curfunc;
	brstack[brstack_ptr] = cur->endbr[0];
	brstack_ptr += 1;

	/* process the new target
	 */
	curfunc = target;
	cur = curfunc->br_root;

	return (1);
}


static void
regdump (ucontext_t *uctx)
{
	fnote ("eax 0x%08x  ebx 0x%08x  ecx 0x%08x  edx 0x%08x\n",
		uctx->uc_mcontext.gregs[REG_EAX],
		uctx->uc_mcontext.gregs[REG_EBX],
		uctx->uc_mcontext.gregs[REG_ECX],
		uctx->uc_mcontext.gregs[REG_EDX]);
	fnote ("esp 0x%08x  ebp 0x%08x  esi 0x%08x  edi 0x%08x\n",
		uctx->uc_mcontext.gregs[REG_ESP],
		uctx->uc_mcontext.gregs[REG_EBP],
		uctx->uc_mcontext.gregs[REG_ESI],
		uctx->uc_mcontext.gregs[REG_EDI]);
}


static void
test_morph (ia32_function **flist, unsigned int flist_count, char *fname)
{
	morph		mr;
	ia32_bblock **	brl;
	unsigned int	brl_count,
			brl_test;

	ia32_bblock **	bsp;
	unsigned int	bsp_count;
	unsigned int	n;


	mr.flist = flist;
	mr.flist_count = flist_count;
	morph_abstract (&mr);

	mr.func = ia32_func_list_find_byname (flist, flist_count, fname);
	if (mr.func == NULL) {
		fprintf (stderr, "no such function \"%s\".\n", fname);

		return;
	}

	/* get all bblockes for this function and choose a random one
	 */
	brl = ia32_br_get_all (mr.func->br_root, &brl_count);
	morph_br_sort (brl, brl_count);

	brl_test = random () % brl_count;
	mr.bblock = brl[brl_test];

	fprintf (stderr, "testing bblock %u: 0x%08x - 0x%08x\n",
		brl_test, mr.bblock->start, mr.bblock->end);

	morph_br_extend (&mr, 4);

	/* find shortest path between function entry point and return
	 */
	for (brl_test = 0 ; brl_test < brl_count ; ++brl_test)
		if (brl[brl_test]->endtype == BR_END_RET)
			break;
	assert (brl_test < brl_count);

	system ("date");
	bsp = ia32_func_br_sp_list (mr.func, &bsp_count,
		mr.func->br_root, brl[brl_test]);
	system ("date");

	for (n = 0 ; n < bsp_count ; ++n)
		fprintf (stderr, "%2d: 0x%08x\n", n, bsp[n]->start);

	free (bsp);

	bsp = ia32_func_br_mustexec (mr.func, &bsp_count);
	for (n = 0 ; n < bsp_count ; ++n)
		fprintf (stderr, "%2d: 0x%08x\n", n, bsp[n]->start);

	func_output ("output.vcg", flist, flist_count, fname, 0);

	free (bsp);
	free (brl);

	return;
}



