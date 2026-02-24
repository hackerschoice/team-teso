
#DFLAGS=-O2
DFLAGS=-g -ggdb
CC=gcc
CFLAGS=$(DFLAGS) -Wall
OBJS=	shellcode.o \
	hppa.o	hppa_hpux.o \
	mips.o	mips_irix.o \
	sparc.o	sparc_solaris.o \
	x86.o	x86_bsd.o x86_linux.o \

all:	shellkit splocoder

clean:
	rm -f *.o shellkit
	rm -f splocoder

shellkit:	$(OBJS)
	$(CC) $(CFLAGS) -o shellkit shellkit.c $(OBJS)

splocoder:	splocoder.c
	$(CC) $(CFLAGS) -o splocoder splocoder.c


