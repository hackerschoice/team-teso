
# zylyx - makefile
# by scut of teso

DFLAGS=-Wall
LIBS=-lpthread -lslang
CC=gcc
CFLAGS=$(DFLAGS)
PREFIX=/usr/local

all:	zylyx

clean:
	rm -f *.o

zylyx:	common.o network.o proxy.o screen.o zylyx.c
	$(CC) $(CFLAGS) -o zylyx zylyx.c common.o network.o proxy.o screen.o $(LIBS)
	strip zylyx
	mv zylyx ../

common.o:	common.c
		$(CC) $(CFLAGS) -c common.c

network.o:	network.c
		$(CC) $(CFLAGS) -c network.c

proxy.o:	proxy.c
		$(CC) $(CFLAGS) -c proxy.c

screen.o:	screen.c
		$(CC) $(CFLAGS) -c screen.c

