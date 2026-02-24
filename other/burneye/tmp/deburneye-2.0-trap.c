/*
 * Burneye Decryptor v0.2.0
 * Copyright 2002 PM <pm@coredump.cx>
 * All rights reserved
 *
 * THIS IS PRIVATE SOURCE CODE. YOU'RE NOT ALLOWED TO
 * DISTRIBUTE IT. I DO NOT WANT TO SEE THIS SHOW UP IN
 * A PUBLIC FORUM SUCH AS HACK.CO.ZA OR BUGTRAQ.
 *
 * v0.2.0 (2002/01/06)
 *   Added decryption trap
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
#include <string.h>

/*
 * Global Variables
 */
pid_t pid;
unsigned debug = 0;
unsigned short killapp = 0, quiet = 0;
struct user regs;

/*
 * Code for use with the trap function
 * Full NASM source is appended at the end
 */
#define TRAPSTARTUP_SIZE 9
unsigned char trapstartup[TRAPSTARTUP_SIZE] = {
    0x67,0xBF,0x00,0x1E,0x37,0x05,0x67,0xFF,0xE7
};
#define TRAPCODE_SIZE 174
unsigned char trapcode[TRAPCODE_SIZE] = {
    0x9C,0x60,0xB8,0x05,0x00,0x00,0x00,0xBB,0x04,0x1F,0x37,0x05,
    0xB9,0x41,0x00,0x00,0x00,0xBA,0x80,0x01,0x00,0x00,0xCD,0x80,
    0x89,0xC7,0xBE,0x0B,0x5A,0x37,0x05,0x46,0x81,0x3E,0x7F,0x45,
    0x4C,0x46,0x75,0xF7,0xB8,0x00,0x1F,0x37,0x05,0x8B,0x10,0xB8,
    0x04,0x00,0x00,0x00,0x89,0xFB,0x89,0xF1,0x29,0xF2,0xCD,0x80,
    0xB8,0x06,0x00,0x00,0x00,0x89,0xFB,0xCD,0x80,0xB8,0x80,0x1F,
    0x37,0x05,0x80,0x38,0x00,0x0F,0x84,0x3E,0x00,0x00,0x00,0xB8,
    0x02,0x00,0x00,0x00,0xCD,0x80,0x09,0xC0,0x0F,0x85,0x2F,0x00,
    0x00,0x00,0xB8,0x80,0x1F,0x37,0x05,0xBF,0xF0,0x1F,0x37,0x05,
    0xAB,0xB8,0x00,0x00,0x00,0x00,0xAB,0xAB,0xB8,0x0B,0x00,0x00,
    0x00,0xBB,0x80,0x1F,0x37,0x05,0xB9,0xF0,0x1F,0x37,0x05,0xBA,
    0xF8,0x1F,0x37,0x05,0xCD,0x80,0xB8,0x01,0x00,0x00,0x00,0xCD,
    0x80,0xBF,0xD8,0x10,0x37,0x05,0xB8,0x50,0x8D,0xBC,0x24,0xAB,
    0xB8,0x00,0xF0,0xFF,0xFF,0xAB,0xC6,0x07,0x60,0x61,0x9D,0xBF,
    0xD8,0x10,0x37,0x05,0xFF,0xE7
};

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
    char *trapfile = 0, *trapapp = 0;
    int opt;

    /* Check Arguments */
    while ((opt = getopt(argc, argv, "i:o:d:kqt:r:")) > 0) {
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
        case 't':
            trapfile = optarg;
            break;
        case 'r':
            trapapp = optarg;
            break;
        }
    }
    if (!quiet) {
        printf("Burneye Decryptor v0.2.0\n"
               "Copyright 2002 PM <pm@coredump.cx>\n"
               "All rights reserved, do not distribute!\n"
              );
    }
    if (!infile) {
        print_usage(argv[0]);
    }
    if (!outfile) {
        outfile = "output";
    }
    if (trapfile && strlen(trapfile) > 64) {
        fprintf(stderr,"Trap output filename may only be 64 "
                "characters long");
        exit(EXIT_FAILURE);
    }
    if (trapapp && strlen(trapapp) > 64) {
        fprintf(stderr,"Trap application name may only be 64 "
                "characters long");
        exit(EXIT_FAILURE);
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

    if (!trapfile) {

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

    } else {

        pos = 0x05370000;
        
    }

    /* Get filesize, and calculate output filesize */
    if (debug) fprintf(stderr,"debug: dumping data\n");
    fp = fopen(infile,"r");
    fseek(fp,0,SEEK_END);
    if (!trapfile) {
        filesize = ftell(fp)-(pos-0x05370000);
    } else {
        filesize = ftell(fp);
    }
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
    fseek(fp,0,SEEK_SET);
    ftruncate(fileno(fp),filesize);
    if (!trapfile) {
        fclose(fp);
    }

    /* Kill process or let go of it */
    if (killapp || trapfile) {
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

    /* Insert Trap Code */
    if (trapfile) {
        if (debug) fprintf(stderr,"debug: installing trap\n");
        fseek(fp,0x107B,SEEK_SET);
        fputc(0x90,fp);
        fseek(fp,0x10D8,SEEK_SET);
        fwrite(trapstartup,TRAPSTARTUP_SIZE,1,fp);
        fseek(fp,0x1E00,SEEK_SET);
        fwrite(trapcode,TRAPCODE_SIZE,1,fp);
        fseek(fp,0x1F00,SEEK_SET);
        filesize += 0x05370000;
        fwrite(&filesize,4,1,fp);
        fseek(fp,0x1F04,SEEK_SET);
        fwrite(trapfile,strlen(trapfile)+1,1,fp);
        fseek(fp,0x1F80,SEEK_SET);
        if (trapapp) {
            fwrite(trapapp,strlen(trapapp)+1,1,fp);
        } else {
            fputc(0,fp);
        }
    }

    /* Everything done */
    if (!quiet && !trapfile) printf("Done, decryption completed\n");
    if (!quiet && trapfile) printf("Done, trapcode planted\n");
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
           "-t outfile     install a decryption trap\n"
           "-r application run an application after decryption trap\n"
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

/*
 * NASM Source code for the trap code
 * compile with:
 *  nasm -f bin trapcode.asm
 */

/*
    BITS 32

    pushf
    pushad
    
    ;
    ; Dump decrypted file to disk
    ;
    
    ; open file for writing
    mov     eax, 5              ; sys_open
    mov     ebx, 05371F04h      ; ptr to filename
    mov     ecx, 65             ; write only / create file 
    mov     edx, 0600q          ; file mode
    int     80h
    mov     edi, eax
    ; find elf header
    mov     esi, 05375A0Ch-1
ElfLoop:
    inc     esi
    cmp     dword [esi], 0464C457Fh
    jnz     short ElfLoop
    ; write to file
    mov     eax, 05371F00h
    mov     edx, dword [eax]
    mov     eax, 4              ; sys_write
    mov     ebx, edi            ; filedesc
    mov     ecx, esi            ; buffer
    sub     edx, esi
    int     80h
    ; close file
    mov     eax, 6              ; sys_close
    mov     ebx, edi            ; filedesc
    int     80h

    ;
    ; Run command
    ;

    ; really run?
    mov     eax, 05371F80h
    cmp     byte [eax], 0
    jz      NoExec
    ; fork
    mov     eax, 2              ; sys_fork
    int     80h
    or      eax, eax            ; parent?
    jnz     NoExec              ; continue
    ; prepare execve
    mov     eax, 05371F80h
    mov     edi, 05371FF0h
    stosd
    mov     eax, 0
    stosd
    stosd
    ; execve
    mov     eax, 11             ; sys_execve
    mov     ebx, 05371F80h      ; ptr to arg0
    mov     ecx, 05371FF0h      ; ptr to args
    mov     edx, 05371FF8h      ; ptr to env
    int     80h
    ; kill child (if execve failed)
    mov     eax, 1
    int     80h
NoExec:

    ;
    ; Cleanup and return
    ;
    
    ; restore original code
    mov     edi, 053710D8h 
    mov     eax, 024BC8D50h
    stosd
    mov     eax, 0FFFFF000h
    stosd
    mov     byte [edi], 060h
    popad
    popf
    ; Return to application
    mov     edi, 053710D8h 
    jmp     edi

*/

