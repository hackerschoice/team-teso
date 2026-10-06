/*** Device-driver for the /dev/exec device, used by EoE.
 *** (C) 1999/2000 by S. Krahmer <krahmer@cs.uni-potsdam.de> under
 *** the GPL. Use it at your own risk!
 ***
 ***/
#define __KERNEL__
#define MODULE

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
#include <linux/smp_lock.h>
#include <asm/uaccess.h>
#include "eoe.h"

/*#define MY_DEBUG*/
#ifdef MY_DEBUG
#define dprintk(x,y...) printk(x,##y)
#else
#define dprintk(x,y...)
#endif

#ifndef KERNEL_VERSION
#error "What do you do? Use the 2.0 version for 2.0 kernels!"
#endif

extern void *sys_call_table[];
int (*o_exec)(struct pt_regs regs);

/* already opened ? */
int use_count = 0;

/* euid to monitor */
int to_monitor = 0;

struct file_operations exec_ops = {
	NULL,		/* lseek */
        exec_read,      
        NULL,           /* write */
        NULL,           /* readdir */
        NULL,           /* poll  */  
        exec_ioctl,     
        NULL,           /* mmap  */
        exec_open,      
        NULL,           /* flush */
        exec_close,     
};

/* New execve(), hooks old one
 */
int n_exec(struct pt_regs regs)
{
   	char *filename = NULL;
        int error = 0;
        
	lock_kernel();
	filename = getname((char*)regs.ebx);
	error = PTR_ERR(filename);
	if (IS_ERR(error))
		goto out;
	
	/* only have a look at this EUID 
	* (may be set via ioctl() ) 
	*/
	if (current->euid == to_monitor || to_monitor == -1) {
		dprintk("try to add program\n");
	        if ((error = add_program(regs)) != 0)
			return error;
	}

       	/* execute as normal */
	error = do_execve(filename, (char**)regs.ecx, (char**)regs.edx, &regs);
	putname(filename);
out:
	unlock_kernel();
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
	filename = getname((char*)regs.ebx);

	dprintk("filename = %s\n", filename);

	/* create new object */
	if ((l = (struct executions*)kmalloc(sizeof(struct executions), GFP_KERNEL)) == NULL) 
		return -ENOMEM;
	l->next = NULL;
	
	/* allocate mem for programname 
	 */
	if ((l->name = (char*)kmalloc(MAXNAME, GFP_KERNEL)) == NULL)
		return -ENOMEM;
	memset(l->name, 0, MAXNAME);
	
	dprintk("allocated mem for name\n");
	
	/* link to next entry 
	 */
	if (last)
		last->next = l;
	last = l;
	
	/* important for sleep() ! 
	 */
	if (!act) {
		act = last;
		wake_up_interruptible(&wp);
	}
	memcpy(last->name, filename, MAXNAME-1);
	i = strlen(last->name);
	
	/* get commandline arguments 
	 */
	argv = (char**)regs.ecx;

	get_user(ar, ++argv);
	while (ar != NULL) {
		last->name[i++] = ' ';
		while (1) {
			get_user(c, ar + j);
			if (c && i < MAXNAME - 1) {
				last->name[i] = (char)c;
				i++;
				j++;
			} else
				break;
		}
		j = 0;
		get_user(ar, ++argv);
	}
	last->name[i] = '\0';
	
	/* YoHo. Save UID and EUID too. */
	last->uid = current->uid;
	last->euid = current->euid;
	
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
void exec_close(struct inode* inode, struct file *file)
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
int exec_read(struct file* file, char *buf, size_t count, loff_t *p)
{
	int error = 0;
	struct executions *l = NULL;
	char tmp[MAXNAME+10];
	
   	if (!suser()) 
           	return -EPERM;
        
        /* noone else than the open'ed process can read 
	 */
        if (use_count != current->pid) 
           	return -EBUSY;

	dprintk("handle pid %d\n", current->pid);	
	
	/* if no more entrys, block 
	 */
	if (!act) {
		/* if non-blocking, return */
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		interruptible_sleep_on(&wp);
		if (signal_pending(current))
			return -ERESTARTSYS;
	}
	dprintk("I don't sleep\n");
	
	/* the real read() 
	 */
	if ((error = access_ok(VERIFY_WRITE, buf, count)) < 0)
           	return error;
        
	memset(tmp, 0, MAXNAME+10);
	sprintf(tmp, "%d:%d:", act->uid, act->euid);
	strncat(tmp, act->name, MAXNAME);
	copy_to_user(buf, tmp, count);

	dprintk("after memcpy_tofs\n");

	/* do all the list-handling 
	 */
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


int exec_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{	
	int error = 0;

        /* should not really necessary here, because only root
         * is allowed to open device, but who knows ...
         */
        if (!suser())
           	return -EPERM;

        /* if cmd is of wrong type */
        if (_IOC_TYPE(cmd) != EOE_MAGIC)
           	return -EINVAL;
	
	switch (cmd) {
		/* set EUID wich we will monitor 
		 */
		case EOE_SETEUID:
			get_user(to_monitor, (int*)arg);
			break;
			
		/* monitor ALL euids
		 */
		case EOE_SETALL:
			to_monitor = -1;
			break;
		/* POSIX requires ENOTTY ! 
		 */
		default:
			return -ENOTTY;
	}
	return 0;
} 

/* dynamic majornumbers not longer supported by EoE
 */
int init_module()
{
   	int r = 0;
	
	EXPORT_NO_SYMBOLS;

	r = register_chrdev(EOE_MAJOR, "exec", &exec_ops);
	if (r < 0) {
		printk(KERN_WARNING "exec [init_module()]: Huh ?\n"
		                    "Can't get major-number (%d)!\n", EOE_MAJOR);
		return r;
	}
	o_exec = sys_call_table[__NR_execve];
        sys_call_table[__NR_execve] = n_exec;
        return 0;
}

int cleanup_module()
{
   	sys_call_table[__NR_execve] = o_exec;
	unregister_chrdev(EOE_MAJOR, "exec");
        return 0;
}

