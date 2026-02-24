
#DFLAGS=-O2
DFLAGS=-g -ggdb
CC=gcc
CFLAGS=$(DFLAGS) -Wall -DIRIX

all:
	$(CC) $(CFLAGS) -o chmod ../codedump.c chmod.s
	$(CC) $(CFLAGS) -o chroot ../codedump.c chroot.s
	$(CC) $(CFLAGS) -o connectsh ../codedump.c connectsh.s
	$(CC) $(CFLAGS) -o execvesh ../codedump.c execvesh.s
	$(CC) $(CFLAGS) -o exit ../codedump.c exit.s
	$(CC) $(CFLAGS) -o portshellsh ../codedump.c portshellsh.s
	$(CC) $(CFLAGS) -o read ../codedump.c read.s
	$(CC) $(CFLAGS) -o setgid ../codedump.c setgid.s
	$(CC) $(CFLAGS) -o setreuid ../codedump.c setreuid.s

clean:
	rm -f code.h codetest \
		chmod chroot connectsh execvesh exit portshellsh read \
		setgid setreuid

