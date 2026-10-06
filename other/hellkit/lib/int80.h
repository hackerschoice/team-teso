#include "unistd.h"
#ifndef _I386_FCNTL_H
#define O_RDONLY    00
#define O_WRONLY    01
#define O_RDWR      02
#define O_CREAT   0100
#define O_TRUNC  01000
#define O_APPEND 02000
#endif

static inline int read(int fd, void *buf, long count)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_read), "S" ((long)fd),
			      "c" ((long)buf), "d" ((long)count): "bx");
	return ret;
}


static inline int write(int fd, void *buf, long count)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_write), "S" ((int)fd),
			      "c" ((long)buf), "d" ((long)count): "bx");
	return ret;
}


static inline int execve(char *s, char **argv, char **envp)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_execve), "S" ((long)s),
			      "c" ((long)argv), "d" ((long)envp): "bx");
	return ret;
}


static inline int setreuid(int reuid, int euid)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_setreuid), "S" ((long)reuid),
			      "c" ((long)euid): "bx");
	return ret;
}


static inline int chroot(char *path)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_chroot), "S" ((long)path): "bx");
	return ret;
}


static inline int dup(int fd)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_dup), "S" (fd): "bx");
	return ret;
}


static inline int dup2(int ofd, int nfd)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_dup2), "S" (ofd), "c" (nfd): "bx");
	return ret;
}


static inline int open(char *path, int mode, int flags)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_open), "S" ((long)path),
			      "c" ((int)mode), "d" ((int)flags): "bx");
	return ret;
}



static inline int chdir(char *path)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_chdir), "S" ((long)path): "bx");
	return ret;
}

static inline int close(int fd)
{
	long ret;
	
	__asm__ __volatile__ ("pushl %%ebx\n\t"
			      "movl %%esi, %%ebx\n\t"
			      "int $0x80"
			     :"=a" (ret)
			     :"0" (__NR_close), "S" ((int)fd): "bx");
	return ret;
}

