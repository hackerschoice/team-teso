
CC=gcc
CFLAGS=-Os -nostdlib


FILES=ldistfp.o common.o network.o

# 1. order of start.o important, -L/-l does not matter
LIBS_DIET=/usr/lib/diet/lib-i386/start.o \
	-L/usr/lib/diet/lib-i386 -lc -L/usr/lib/gcc-lib/i386-linux/2.95.4 -lgcc
DIET_INCLUDE=-I/usr/include/diet

# gcc --help -v 2>&1 |grep crt
LIBS_GLIBC=/usr/lib/crt1.o /usr/lib/crti.o /usr/lib/gcc-lib/i386-linux/2.95.4/crtbegin.o \
	-lc -L/usr/lib/gcc-lib/i386-linux/2.95.4 -lgcc \
	/usr/lib/gcc-lib/i386-linux/2.95.4/crtend.o /usr/lib/crtn.o

all:	ldistfp

clean:
	rm -f *.o ldistfp-glibc ldistfp-dietlibc

ldistfp:	ldistfp-final-dietlibc.o ldistfp-final-glibc.o
	ld -o ldistfp-dietlibc ldistfp-final-dietlibc.o
	ld -o ldistfp-glibc ldistfp-final-glibc.o

ldistfp-final-dietlibc.o:	$(FILES)
	$(CC) $(DIET_INCLUDE) $(CFLAGS) -c -o ldistfp.o ldistfp.c
	$(CC) $(DIET_INCLUDE) $(CFLAGS) -c -o network.o network.c
	$(CC) $(DIET_INCLUDE) $(CFLAGS) -c -o common.o common.c
	ld -r -d -o ldistfp-final-dietlibc.o $(FILES) $(LIBS_DIET)

ldistfp-final-glibc.o:	ldistfp.c
	$(CC) $(CFLAGS) -c -o ldistfp.o ldistfp.c
	$(CC) $(CFLAGS) -c -o network.o network.c
	$(CC) $(CFLAGS) -c -o common.o common.c
	ld -r -d -o ldistfp-final-glibc.o $(FILES) $(LIBS_GLIBC)
