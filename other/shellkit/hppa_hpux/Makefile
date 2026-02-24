
#DFLAGS=-O2
DFLAGS=-g -ggdb
CC=gcc
CFLAGS=$(DFLAGS) -Wall

all:
	$(CC) $(CFLAGS) -o execvesh execvesh.s

clean:
	rm -f *.o
	rm -f chmod chroot connectsh execvesh exit portshellsh read \
		setgid setreuid

