/*
 * this is nothing. just to get familiar with ptrace stuff
 * and testing...
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

/* lets take this lame shellcode...doing some useless jumps
   nop's setuid(0) and exec /bin/id */
char shellcode[] =  "\x90\x90\x90\x90\x90\x90\x90\x90"
"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
        "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
        "\x80\xe8\xdc\xff\xff\xff/bin/id";


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

void
die(char *s, int code)
{
	fprintf(stderr, "ERROR: %s", s);
	exit(code);
}

void
test_shellcode(char *sc)
{
/* pushl sc; push ip; CALL xxx; pushl %ebp; movl %esp, %ebp */
   __asm__("jmp             *0x8(%ebp)");
}

void
mysignal(int sig)
{
	fprintf(stderr, "signal %d received\n", sig);
}


void
do_child()
{
	int i=1;
	/* no signal should be delivered...anyway. lets check
	   if someone is doing something evil to us...CATCH IT!*/
	signal(SIGTRAP, mysignal);
	signal(SIGALRM, mysignal);
	signal(SIGCHLD, mysignal);
	signal(SIGCONT, mysignal);
	signal(SIGSTOP, mysignal);
	while(i)	/* stay in here...parent, screw me up ! */
	{
		printf("child %d\n", i++);
		sleep(2);
	}

}

int
main(int argc, char *argv[])
{
	int pid, i;
	struct pt_regs regs;
	struct elf_prpsinfo proc;


	if ( (pid = fork()) == 0)
		do_child();
	if (pid < 0)
		die("sucker..fork failed\n", -1);

	stat(pid);
	sleep(1);
	printf("attaching child %d\n", pid);
	if ( (i = ptrace(PTRACE_ATTACH, pid, 0, 0)) != 0)
		die("ptrace_attach\n", -1);
	i = waitpid(pid, 0,0);
	stat(pid);
	if ( (i = ptrace(PTRACE_POKEUSER, pid, 4*EIP, shellcode)) != 0)
		die("ptrace_pokeuser\n", -1);
	
	if( (i = ptrace(PTRACE_DETACH, pid, 0, 0)) != 0)
		die("ptrace_detach failed\n", -1);

	stat(pid);
	printf("done..w8ting 10 seconds\n");
	sleep(10);

	exit(0);
	return(0);
}

