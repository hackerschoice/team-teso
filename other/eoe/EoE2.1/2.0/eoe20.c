/*** Device-driver for the /dev/exec device, used by EoE. 
 *** (C) 1999/2000 by S. Krahmer <krahmer@cs.uni-potsdam.de> under
 *** the GPL. Use it at your own risk!
 ***
 ***/
#define __KERNEL__
#define MODULE
#define EXEC_MAJOR 127
//#define MY_DEBUG
#ifdef MY_DEBUG
#define dprintk(x,y...) printk(x,##y)
#else
#define dprintk(x,y...)
#endif

#define EXEC_SETEUID 0x2600
#define MAXNAME 1000

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <asm/segment.h>
#include <sys/syscall.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/malloc.h>

#ifdef KERNEL_VERSION
#error "Are you dumb? Use the 2.2 version of EoE for 2.2 kernels - not the 2.0 one."
#endif

/* prototypes */
int add_program(struct pt_regs);
int exec_lseek(struct inode*, struct file*, off_t, int);
int exec_read(struct inode*, struct file*, char*, int);
int exec_ioctl(struct inode*, struct file*, unsigned int, unsigned long);
int exec_open(struct inode*, struct file*);
void exec_close(struct inode*, struct file*);

extern void *sys_call_table[];
int (*o_exec)(struct pt_regs regs);

/* globals */
int use_count = 0;
int to_monitor = 0;
int _EXEC_MAJOR = 0;

struct executions {
	char *name;
	struct executions *next;
};

/* globals */
struct executions *act = NULL, *last = NULL;
struct wait_queue *wp = NULL;

struct file_operations exec_ops = {
   	exec_lseek,
        exec_read,
        NULL,
        NULL,
        NULL,
        exec_ioctl,
        NULL,
        exec_open,
        exec_close
};

/* New execve(), hooks old one
 */
int n_exec(struct pt_regs regs)
{
   	char *filename = NULL;
        int error = 0;
        
	/* only have a look at this EUID 
	* (may be set via ioctl() ) 
	*/
	if (current->euid == to_monitor) {
		dprintk("try to add program\n");
	        if ((error = add_program(regs)) != 0)
			return error;
	}

        /* get filename from user-space */ 
        if ((error = getname((char*)regs.ebx, &filename)) != 0)
           	return error;
       	/* execute as normal */
	error = do_execve(filename, (char**)regs.ecx, (char**)regs.edx, &regs);
	putname(filename);
	return error;
}

/* add an entry to our linked list */
int add_program(struct pt_regs regs)
{
	char *filename = NULL, **argv = NULL, *ar = NULL;
	int error = 0, i = 0, j = 0;	
	struct executions *l;
	char c = 0;

	/* get name from userspace */
	if ((error = getname((char*)regs.ebx, &filename)) != 0) 
		return error;

	dprintk("filename = %s\n", filename);

	/* create new object */
	if ((l = (struct executions*)kmalloc(sizeof(struct executions), GFP_KERNEL)) == NULL) 
		return -ENOMEM;
	l->next = NULL;
	
	/* allocate mem for programname */
	if ((l->name = (char*)kmalloc(MAXNAME, GFP_KERNEL)) == NULL)
		return -ENOMEM;
	memset(l->name, 0, MAXNAME);
	
	dprintk("allocated mem for name\n");
	
	/* link to next entry */
	if (last)
		last->next = l;
	last = l;
	
	/* important for sleep() ! */
	if (!act) {
		act = last;
		wake_up_interruptible(&wp);
	}
	memcpy(last->name, filename, MAXNAME-1);
	i = strlen(last->name);
	
	/* get commandline arguments */
	argv = (char**)regs.ecx;
	if ((error = verify_area(VERIFY_READ, argv+1, sizeof(char*))) < 0)
		return error;
	while ((ar = get_user(++argv)) != NULL) {
		last->name[i++] = ' ';
		while (1) {
			if ((error = verify_area(VERIFY_READ, ar + j, sizeof(char))) < 0)
				return error;
			if ((c = get_user(ar + j)) && i < MAXNAME - 1) {
				last->name[i] = (char)c;
				i++;
				j++;
			} else
				break;
		}
		j = 0;
		if ((error = verify_area(VERIFY_READ, argv, sizeof(char*))) < 0)
			return error;
	}
	last->name[i] = '\0';

	dprintk("successful added filename\n");
	putname(filename);	
   	return 0;
}

/* open() method for our driver 
 */
int exec_open(struct inode *inode, struct file *file)
{
   	if (!suser())
           	return -EPERM;

	/* don't open device twice */
        if (use_count)
           	return -EBUSY;
                
        use_count = current->pid;
#ifndef MY_DEBUG
        MOD_INC_USE_COUNT;
#endif
        return 0;
}

/* close()
 */
void exec_close(struct inode *inode, struct file *file)
{
   	if (!suser())
           	return;

#ifndef MY_DEBUG
        MOD_DEC_USE_COUNT;
#endif
	use_count = 0;
        return;
}
                
/* read()             
 */
int exec_read(struct inode *inode, struct file* file, char *buf, int count)
{
	int error = 0;
	struct executions *l = NULL;
	
   	if (!suser()) 
           	return -EPERM;
        
        /* noone else than the open'ed process can read */
        if (use_count != current->pid) 
           	return -EBUSY;

	dprintk("handle pid %d\n", current->pid);	
	
	/* if no more entrys, block */
	if (!act) {
		/* if non-blocking, return */
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		interruptible_sleep_on(&wp);
		if (current->signal & ~current->blocked)
			return -ERESTARTSYS;
	}
	dprintk("I don't sleep\n");
	
	if ((error = verify_area(VERIFY_WRITE, buf, count)) != 0)
		return error;
	
	/* the real read() */
	memcpy_tofs(buf, act->name, count);

	dprintk("after memcpy_tofs\n");

	/* do the list-handling */
	l = act;
	act = act->next;
	dprintk("try to free structs\n");
	if (l) {
		if (l->name)
			kfree(l->name);
/*		kfree(l);*/
	}
	return count;	
}

/* We don't provide a lseek() b/c it is
 * useless
 */
int exec_lseek(struct inode *inode, struct file *file, off_t offset, int how)
{
	return 0;
}

int exec_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{	
	int error = 0;
	
	switch (cmd) {
		/* set EUID wich we will monitor */
		case EXEC_SETEUID:
			if ((error = verify_area(VERIFY_READ, (int*)arg, sizeof(*(int*)arg))) < 0)
				return error;
			to_monitor = get_user((int*)arg);
			break;
		/* POSIX requires ENOTTY ! */
		default:
			return -ENOTTY;
	}
	return 0;
} 


int init_module()
{
   	int r = 0;
	
        register_symtab(NULL);

	r = register_chrdev(EXEC_MAJOR, "exec", &exec_ops);
	if (r < 0) {
		printk(KERN_WARNING "exec [init_module()]: Huh ?\n"
		                    "Can't get major-number (%d)!\n", EXEC_MAJOR);
		return r;
	}
	/* if it was dynamic-register, save major# 
	 * for unregister() later
	 */
	if (!EXEC_MAJOR)
		_EXEC_MAJOR = r;
	else
		_EXEC_MAJOR = EXEC_MAJOR;
   	o_exec = sys_call_table[__NR_execve];
        sys_call_table[__NR_execve] = n_exec;
        return 0;
}

int cleanup_module()
{
   	sys_call_table[__NR_execve] = o_exec;
	unregister_chrdev(_EXEC_MAJOR, "exec");
        return 0;
}

