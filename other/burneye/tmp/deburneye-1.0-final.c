/*
 * Burneye Decryptor v0.1.0
 * Copyright 2001 PM <pm@coredump.cx>
 * All rights reserved
 *
 * THIS IS PRIVATE SOURCE CODE. YOU'RE NOT ALLOWED TO
 * DISTRIBUTE IT. I DO NOT WANT TO SEE THIS SHOW UP IN
 * A PUBLIC FORUM SUCH AS HACK.CO.ZA OR BUGTRAQ.
 *
 * v0.1.0 (2002/01/04)
 *   Initial Release
 */
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * Global Variables
 */
pid_t pid;
unsigned debug = 0;
unsigned short killapp = 0, quiet = 0;
struct user regs;

/*
 * Function Declarations
 */
void print_usage(const char *);
void ptrace_until_eip(const unsigned long);
unsigned long ptrace_read_data(const unsigned long);
void ptrace_write_data(const unsigned long, const unsigned long);
void ptrace_read_regs();

/*
 * Main Application
 */
int main(int argc, char *argv[])
{
    unsigned long data;
    unsigned long filesize,i,pos;
    FILE *fp;
    char *outfile = 0, *infile = 0;
    int opt;

    /* Check Arguments */
    while ((opt = getopt(argc, argv, "i:o:d:kq")) > 0) {
        switch (opt) {
        case 'i':
            infile = optarg;
            break;
        case 'o':
            outfile = optarg;
            break;
        case 'd':
            debug = atoi(optarg);
            break;
        case 'k':
            killapp++;
            break;
        case 'q':
            quiet++;
            break;
        }
    }
    if (!quiet) {
        printf( "Burneye Decryptor v0.1.0\n"
                "Copyright 2001 PM <pm@coredump.cx>\n"
                "All rights reserved, do not distribute!\n\n"
              );
    }
    if (!infile) {
        print_usage(argv[0]);
    }
    if (!outfile) {
        outfile = "output";
    }
   
    /* Fork */
    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    /* Setup ptrace on child */
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
            perror("ptrace PTRACE_TRACEME");
            exit(EXIT_FAILURE);
        }
        if (debug) fprintf(stderr, "debug: child is executing: %s\n",
                           infile);
        close(1);
        dup2(2, 1);
        execl(infile,infile,NULL);
        perror("execl");
        exit(EXIT_FAILURE);
    }
    wait(NULL);

    /* Print entry point */
    if (debug) {
        ptrace_read_regs();
        fprintf(stderr,"debug: entrypoint: %.8lX\n", regs.regs.eip);
    }
    
    /* Run until after decryption phase #1 */
    if (!quiet) printf("Decrypting. Be patient\n");
    if (debug) fprintf(stderr,"debug: decryption phase #1\n");
    ptrace_until_eip(0x053710AB);

    /* Remove anti debugging tricks */
    if (debug) fprintf(stderr,"debug: removing anti-debug code\n");
    data = ptrace_read_data(0x053714CC);
    data &= 0xFF00FFFF; data += 0xEB0000;
    ptrace_write_data(0x053714CC,data);

    /* Find startpos */
    if (debug) fprintf(stderr,"debug: find elf header\n");
    ptrace_until_eip(0x05371A07);
    ptrace_read_regs();
    data = ptrace_read_data(regs.regs.ebp-0x2E0);
    
    /* Still not always correct, search for elf header */
    pos = data-1;
    do {
        data = ptrace_read_data(++pos);
    } while (data != 0x464C457F);

    /* Continue until end of burneye stub */
    ptrace_until_eip(0x053710FC);

    /* Get filesize, and calculate output filesize */
    if (debug) fprintf(stderr,"debug: dumping data\n");
    fp = fopen(infile,"r");
    fseek(fp,0,SEEK_END);
    filesize = ftell(fp)-(pos-0x05370000);
    fclose(fp);
    if (debug) fprintf(stderr,"debug: output filesize %ld\n",filesize);

    /* Write output file */
    if (debug) fprintf(stderr,"debug: dumping to file");
    fp = fopen(outfile,"w");
    if (!fp) {
        perror("fopen outputfile");
        exit(EXIT_FAILURE);
    }
    for(i=0; i<filesize; i+=4) {
        data = ptrace_read_data(pos+i);
        fwrite(&data,4,1,fp);
    }
    fseek(fp,0,0);
    ftruncate(fileno(fp),filesize);
    fclose(fp);

    /* Kill process or let go of it */
    if (killapp) {
        if (debug) fprintf(stderr,"debug: killing application\n");
        if (ptrace(PTRACE_KILL, pid, NULL, NULL) < 0) {
            perror("ptrace PTRACE_KILL");
            exit(EXIT_FAILURE);
        }
    } else {
        if (debug) fprintf(stderr,"debug: let application run\n");
        if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
            perror("ptrace PTRACE_DETACH");
            exit(EXIT_FAILURE);
        }
    }

    /* Everything done */
    if (!quiet) printf("Done, decryption completed\n");
    exit(EXIT_SUCCESS);
}

/*
 * Print application usage and quit
 */
void print_usage(const char *argv0)
{
    printf("usage: %s <arguments>\n", argv0);
    printf("-i infile      input file (required)\n"
           "-o outfile     output file (default: output)\n"
           "-k             kill application after decryption\n"
           "-q             quiet mode, display errors only\n"
           "-d debuglevel  debug level (1-debug info, 2-ptrace info)\n"
          );
    exit(EXIT_FAILURE);
}

/*
 * Single step until a given EIP
 */
void ptrace_until_eip(const unsigned long eip)
{
    do {
        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
            perror("ptrace PTRACE_SINGLESTEP");
            exit(EXIT_FAILURE);
        }
        wait(NULL);
        ptrace_read_regs();
    } while (regs.regs.eip != eip);
}

/*
 * Read registers
 */
void ptrace_read_regs()
{
    memset (&regs, 0, sizeof (regs));
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        perror("ptrace PTRACE_GETREGS");
        exit(EXIT_FAILURE);
    }
}

/*
 * Read data from process
 */
unsigned long ptrace_read_data(const unsigned long addr)
{
    unsigned long data;
    errno = 0;
    data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    if (errno) {
        perror("ptrace PTRACE_PEEKDATA");
        exit(EXIT_FAILURE);
    }
    if (debug > 1) {
        fprintf(stderr,"ptrace_read_data: read %.8lX from %.8lX\n",
                data, addr);
    }
    return data;
}

/*
 * Write data to process
 */
void ptrace_write_data(const unsigned long addr, const unsigned long data)
{
    if (ptrace(PTRACE_POKEDATA, pid, addr, data) < 0) {
        perror("ptrace PTRACE_POKEDATA");
        exit(EXIT_FAILURE);
    }
    if (debug > 1) {
        fprintf(stderr,"ptrace_write_data: wrote %.8lX to %.8lX\n",
                data, addr);
    }
}


