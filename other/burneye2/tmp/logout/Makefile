
CC=gcc
CFLAGS=-Os -nostdlib

# 1. order of start.o important, -L/-l does not matter
LIBS_DIET=/usr/lib/diet/lib-i386/start.o \
	-L/usr/lib/diet/lib-i386 -lc -L/usr/lib/gcc-lib/i386-linux/2.95.4 -lgcc
DIET_INCLUDE=-I/usr/include/diet

# gcc --help -v 2>&1 |grep crt
LIBS_GLIBC=/usr/lib/crt1.o /usr/lib/crti.o /usr/lib/gcc-lib/i386-linux/2.95.4/crtbegin.o \
	-lc -L/usr/lib/gcc-lib/i386-linux/2.95.4 -lgcc \
	/usr/lib/gcc-lib/i386-linux/2.95.4/crtend.o /usr/lib/crtn.o

all:	7350logout

clean:
	rm -f *.o 7350logout-glibc 7350logout-dietlibc

7350logout:	7350logout-final-dietlibc.o 7350logout-final-glibc.o
	ld -o 7350logout-dietlibc 7350logout-final-dietlibc.o
	ld -o 7350logout-glibc 7350logout-final-glibc.o

7350logout-final-dietlibc.o:	7350logout.c
	$(CC) $(DIET_INCLUDE) $(CFLAGS) -c -o 7350logout.o 7350logout.c
	ld -r -d -o 7350logout-final-dietlibc.o 7350logout.o $(LIBS_DIET)

7350logout-final-glibc.o:	7350logout.c
	$(CC) $(CFLAGS) -c -o 7350logout.o 7350logout.c
	ld -r -d -o 7350logout-final-glibc.o 7350logout.o $(LIBS_GLIBC)
