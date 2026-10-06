/*** Used to detect stealth modules. ;-)
 ***/
#define __KERNEL__
#define MODULE
#include <linux/module.h>

int init_module()
{
   	int i = 0;
        struct module *m = &__this_module;
        
        while (m) {
           	printk("Found %s\n", m->name);
#ifdef KILL_EOE
		if (strstr(m->name, "eoe")) {
			for (i = 0; i < GET_USE_COUNT(m); i++)	
				__MOD_DEC_USE_COUNT(m);
		}
#endif
		m = m->next;
        }
        return 0;
}

int cleanup_module()
{
   	return 0;
}
