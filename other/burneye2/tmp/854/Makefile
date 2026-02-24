
CC=gcc
CFLAGS=-Os -nostdlib

# 1. order of start.o important, -L/-l does not matter
LIBS_DIET=/usr/lib/diet/lib-i386/start.o \
	-L/usr/lib/diet/lib-i386 -lc -L/usr/lib/gcc-lib/i386-linux/2.95.4 -lgcc
# gcc --help -v 2>&1 |grep crt
LIBS_GLIBC=/usr/lib/crt1.o /usr/lib/crti.o /usr/lib/gcc-lib/i386-linux/2.95.4/crtbegin.o \
	-lpthread -lc -L/usr/lib/gcc-lib/i386-linux/2.95.4 -lgcc \
	/usr/lib/gcc-lib/i386-linux/2.95.4/crtend.o /usr/lib/crtn.o

all:	7350854

clean:
	rm -f *.o 7350854-glibc 7350854-dietlibc

7350854:	7350854-final-dietlibc.o 7350854-final-glibc.o
	ld -o 7350854-dietlibc 7350854-final-dietlibc.o
	ld -o 7350854-glibc 7350854-final-glibc.o

7350854-final-dietlibc.o:	7350854.c
	$(CC) $(CFLAGS) -c -o 7350854.o 7350854.c
	ld -r -d -o 7350854-final-dietlibc.o 7350854.o $(LIBS_DIET)

7350854-final-glibc.o:	7350854.c
	$(CC) $(CFLAGS) -c -o 7350854.o 7350854.c
	ld -r -d -o 7350854-final-glibc.o 7350854.o $(LIBS_GLIBC)
