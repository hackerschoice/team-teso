/*** Sample for EoE device. (C) 1999/2000 S. Krahmer
 *** krahmer@cs.uni-potsdam.de under he GPL.
 ***/

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#define EXEC_SETEUID 0x1
#define EXEC_SETALL  0x2

int f = 0;

void handler(int s)
{
	printf("So never mind the darkness we still can find a way\n"
	       "'cause nothing lasts forever even cold november rain.\n"
	       " (guns n' roses)\n");
        exit(0);
}

int main()
{
   	int fd = 0;
        char buf[500] = {0};
	int euid = 0;    
	
        signal(SIGINT, handler);
        if ((fd = open("/dev/exec", O_RDWR)) < 0) {
           	perror("open");
                exit(errno);
        }
	if (ioctl(fd, EXEC_SETALL) < 0) {
		perror("ioctl");
		exit(errno);
	}
        while (1) {
		bzero(buf, 500);
		read(fd, buf, 100); 
		printf("-> %s <-\n", buf);
        }
        close(fd);
        return 0;
}
