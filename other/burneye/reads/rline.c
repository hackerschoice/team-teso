#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>


#define _NSIG           64
#define _NSIG_BPW       32
#define _NSIG_WORDS     (_NSIG / _NSIG_BPW)


#if 0
struct _fpreg {
        unsigned short significand[4];
        unsigned short exponent;
};
 
struct _fpxreg {
        unsigned short significand[4];
        unsigned short exponent;
        unsigned short padding[3];
};
 
struct _xmmreg {
        unsigned long element[4];
};

struct _fpstate {
        /* Regular FPU environment */
        unsigned long   cw;
        unsigned long   sw;
        unsigned long   tag;
        unsigned long   ipoff;
        unsigned long   cssel;
        unsigned long   dataoff;
        unsigned long   datasel;
        struct _fpreg   _st[8];
        unsigned short  status;
        unsigned short  magic;          /* 0xffff = regular FPU data only */
 
        /* FXSR FPU environment */
        unsigned long   _fxsr_env[6];   /* FXSR FPU env is ignored */
        unsigned long   mxcsr;
        unsigned long   reserved;
        struct _fpxreg  _fxsr_st[8];    /* FXSR FPU reg data is ignored */
        struct _xmmreg  _xmm[8];
        unsigned long   padding[56];
};

struct sigcontext {
        unsigned short gs, __gsh;
        unsigned short fs, __fsh;
        unsigned short es, __esh;
        unsigned short ds, __dsh;
        unsigned long edi;
        unsigned long esi;
        unsigned long ebp;
        unsigned long esp;
        unsigned long ebx;
        unsigned long edx;
        unsigned long ecx;
        unsigned long eax;
        unsigned long trapno;
        unsigned long err;
        unsigned long eip;
        unsigned short cs, __csh;
        unsigned long eflags;
        unsigned long esp_at_signal;
        unsigned short ss, __ssh;
        struct _fpstate * fpstate;
        unsigned long oldmask;
        unsigned long cr2;
};

struct sigframe
{
    char *pretcode;
    int sig;
    struct sigcontext sc;
    struct _fpstate fpstate;
    unsigned long extramask[_NSIG_WORDS-1];
    char retcode[16];
};

struct rt_sigframe
{
    char *pretcode;
    int sig;
    struct siginfo *pinfo;
    void *puc;
    struct siginfo info;
    struct ucontext uc;
    struct _fpstate fpstate;
    char retcode[16];
};
#endif


struct ucontext {
    unsigned long     uc_flags;
    struct ucontext  *uc_link;
    stack_t           uc_stack;
    struct sigcontext uc_mcontext;
    sigset_t          uc_sigmask;   /* mask last for extensibility */
};


void enable_single_stepping()
{
    __asm__ __volatile__
    (
        "pushfl\n"
        "orb $0x01,1(%%esp)\n"
        "popfl\n"
        :
        :
        : "cc"
    );
}


void disable_single_stepping()
{
    __asm__ __volatile__
    (
        "pushfl\n"
        "andb $0xFE,1(%%esp)\n"
        "popfl\n"
        :
        :
        : "cc"
    );
}


void encrypt(unsigned char* ptr, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        ptr[i] ^= 0x5A;
    }
}


void decrypt(unsigned char* ptr, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        ptr[i] ^= 0x5A;
    }
}


void protected()
{
    char msg[] = "you can't debug here ;-)\n";

    __asm__ __volatile__
    (
        "movl %1,%%edx\n"
        "movl %0,%%ecx\n"
        "movl $1,%%ebx\n"
        "movl $4,%%eax\n"
        "int $0x80\n"
        :
        : "g" (msg), "g" (sizeof(msg))
        : "bx", "cx", "dx"
    );
}
void protected_end() {}


unsigned char* begin = (unsigned char*) &protected;
unsigned char* end = (unsigned char*) &protected_end;
unsigned char* ptr;


void rline(int sig, siginfo_t * si, void * _uc)
{
    struct ucontext* uc = (struct ucontext*) _uc;

    printf("eip: %08X\n", uc->uc_mcontext.eip);
    if (ptr == (unsigned char*)uc->uc_mcontext.eip) {
        decrypt(ptr, end-begin);
    }
//    uc->uc_mcontext.eip = uc->uc_mcontext.eip-1;
}

int main(int argc, char* argv[])
{
    struct sigaction sa;
    struct sigaction osa;

    int i;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = NULL;
    sa.sa_sigaction = rline;
    sa.sa_flags = SA_SIGINFO;
    sa.sa_restorer = NULL;

    if (-1 == sigaction(SIGTRAP, &sa, &osa))
    {
        write(2, "oops", 4);
        return -1;
    }

    ptr = mmap(0, end - begin, PROT_EXEC|PROT_WRITE|PROT_READ, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    printf("mmap: %08X, size: %d\n", ptr, end-begin);
    memcpy(ptr, begin, end-begin);
    encrypt(ptr, end-begin);

    enable_single_stepping();

//    malloc(4000);
    ((void(*)())ptr)();

#if 0
    __asm__ __volatile__
    (
        "movl $1000000,%%ecx\n"
        "0:"
        "loop 0b\n"
        :
        :
        : "cx", "cc"
    );
#endif

    disable_single_stepping();

    return 0;
}
