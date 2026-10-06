#include "../../lib/int80.h"

int main()
{
   	int fd, nfd;
        char *a[] = {"/bin/sh", 0};
        char *s = "Hello world!";
	char *p = "./x";
	
        fd = open(p, O_RDWR|O_CREAT, 0600);
        nfd = dup(fd);
        write(nfd, s, 12);
        close(nfd);
        close(fd);
        execve(a[0], a, 0);
}

