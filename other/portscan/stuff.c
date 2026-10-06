#include "portscan.h"
#include <stdarg.h>

int Sendto(int s,const void *msg,int len,unsigned int flags,const struct
	   sockaddr *to,int tolen)
{
	int resu;

	resu = sendto(s, msg, len, flags, to, tolen);
	if (resu < 0) {
		if (errno == EACCES)  /* indicates broadcast address */
			return(-1);
		perror("sendto");
		exit(-1);
	}
	return(resu);
}

int Socket(int domain, int type, int protocol)
{
	int fd;

	fd = socket(domain,type,protocol);
	if (fd < 0) {
		perror("socket");
		exit(-1);
	}
	return(fd);
}


int Print(char *fmt,...)
{
	va_list va;

	va_start(va,fmt);
	if (logfile) {vfprintf(logfile,fmt,va);fflush(logfile);}
	vfprintf(stdout,fmt,va);
	va_end(va);
	return(1);
}

void *xmalloc(size_t size)
{
	void *ptr = malloc(size);

	if (ptr == NULL) {
		Print("xmalloc: out of memory\n");
		exit(-1);
	}
	return(ptr);
}


int unblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, flags|O_NONBLOCK);
	return flags;
}
