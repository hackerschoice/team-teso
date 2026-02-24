CFLAGS=-m486 -c -O2 -Wall -DMODULE -D__KERNEL__ -I/usr/src/linux/include
CC=cc
LD=ld

.SUFFIXES: .o .c

.c.o:
	$(CC) $(CFLAGS) $<

OBJ = balloc.o bitmap.o dir.o file.o fsync.o ialloc.o inode.o \
		ioctl.o namei.o super.o symlink.o rc4.o

all: ecfs.o

ecfs.o: ${OBJ}
	$(LD) -r ${OBJ} -o $@

clean:
	rm -rf *.o
    



