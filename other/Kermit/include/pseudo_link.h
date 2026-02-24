/*
 * pseudo_link.h:
 * file for pseudolinking.
 * put all your pointer to function prototypes here.
 * written by palmers / teso
 */
#include <glob.h>
#include <linux/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <asm/ptrace.h>
#include <addresses.h>

#define	USE_SYS_FORK	\
int (*sys_fork)(struct pt_regs) = \
			(int (*)(struct pt_regs))SYS_FORK_ADD;	/* arch dependant! */

#define	USE_SYS_READ	\
size_t (*sys_read)(unsigned int, char *, size_t) = \
			(size_t (*)(unsigned int, char *, size_t))SYS_READ_ADD;

#define	USE_SYS_WRITE	\
size_t (*sys_write)(unsigned int, char *, size_t) = \
			(size_t (*)(unsigned int, char *, size_t))SYS_WRITE_ADD;

#define	USE_SYS_EXIT	\
int (*sys_exit)(int) = \
			(int (*)(int))SYS_EXIT_ADD;

#define	USE_SYS_SETUID	\
int (*sys_setuid)(uid_t) = \
			(int (*)(uid_t))SYS_SETUID_ADD;

#define	USE_SYS_SETGID	\
int (*sys_setgid)(gid_t) = \
			(int (*)(gid_t))SYS_SETGID_ADD;

#define	USE_SYS_GETUID	\
int (*sys_getuid)(void) = \
			(int (*)(void))SYS_GETUID_ADD;

#define	USE_SYS_GETGID	\
int (*sys_getgid)(void) = \
			(int (*)(void))SYS_GETGID_ADD;

#define USE_SYS_OPEN	\
int (*sys_open)(const char *, int, int) = \
			(int (*)(const char *, int, int))SYS_OPEN_ADD;

#define	USE_SYS_CLOSE	\
int (*sys_close)(int) = \
			(int (*)(int))SYS_CLOSE_ADD;

#define	USE_KMALLOC	\
void *(*kmalloc)(size_t, int) = \
			(void *(*)(size_t, int)) KMALLOC_ADD;


