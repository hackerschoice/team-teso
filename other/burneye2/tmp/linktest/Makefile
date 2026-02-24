
CC=gcc
CFLAGS=-Os -nostdlib

# 1. order of start.o important, -L/-l does not matter
LIBS=obj-dietstart/start.o -L/usr/lib/diet/lib-i386 -lc -L/usr/lib/gcc-lib/i386-linux/2.95.4 -lgcc

all:	hello

clean:
	rm -f hello *.o

hello:	hello-final.o
	ld -o hello hello-final.o

# hello-final.o is what we need as burneye input
hello-final.o:	hello.o
	ld -r -o hello-final.o hello.o $(LIBS)

hello.o:	hello.c
	$(CC) $(CFLAGS) -c -o hello.o hello.c
