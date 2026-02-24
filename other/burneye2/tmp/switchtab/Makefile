
DFLAGS=
CC=gcc-3.2
LD=ld
CFLAGS=$(DFLAGS) -Wall -O
LIBS=-Lelf -lxelf -Lia32 -lia32

all:	switch

clean:
	rm -f switch.o

switch:	switch.c
	$(CC) $(CFLAGS) -c -o switch.o switch.c
#	$(LD) -r -o switch-final.o switch.o \
#		/usr/lib/diet/lib-i386/libc.a \
#		/usr/lib/diet/lib-i386/start.o


