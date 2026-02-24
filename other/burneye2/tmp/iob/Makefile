
CC=gcc
CFLAGS=-Os -nostdlib

# 1. order of start.o important, -L/-l does not matter
LIBS_DIET=/usr/lib/diet/lib-i386/start.o \
	-L/usr/lib/diet/lib-i386 -lc -L/usr/lib/gcc-lib/i386-linux/2.95.4 -lgcc
INCLUDE_DIET=-I/usr/include/diet

# gcc --help -v 2>&1 |grep crt
LIBS_GLIBC=/usr/lib/crt1.o /usr/lib/crti.o /usr/lib/gcc-lib/i386-linux/2.95.4/crtbegin.o \
	-lc -L/usr/lib/gcc-lib/i386-linux/2.95.4 -lgcc \
	/usr/lib/gcc-lib/i386-linux/2.95.4/crtend.o /usr/lib/crtn.o

all:	iob

clean:
	rm -f *.o iob-glibc iob-dietlibc

iob:	iob-final-dietlibc.o iob-final-glibc.o
	ld -o iob-dietlibc iob-final-dietlibc.o
	ld -o iob-glibc iob-final-glibc.o

iob-final-dietlibc.o:	iob.c
	$(CC) $(INCLUDE_DIET) $(CFLAGS) -c -o iob.o iob.c
	$(CC) $(INCLUDE_DIET) $(CFLAGS) -c -o pty.o pty.c
	ld -r -d -o iob-final-dietlibc.o iob.o pty.o $(LIBS_DIET)

iob-final-glibc.o:	iob.c
	$(CC) $(CFLAGS) -c -o iob.o iob.c
	$(CC) $(CFLAGS) -c -o pty.o pty.c
	ld -r -d -o iob-final-glibc.o iob.o pty.o $(LIBS_GLIBC)
